"""POST /otp/verify: success, expiry, reuse, wrong codes, lockout, parallel calls."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.conftest import MSISDN, OTHER_IP, wrong


def test_o01_send_and_verify(api):
    """O01."""
    api.send()
    r = api.verify(api.code())
    assert r.status_code == 200
    assert "detail" in r.json()


def test_zero_code_is_valid(api, codes):
    codes(0)
    api.send()
    assert api.code() == "000000"
    assert api.verify("000000").status_code == 200


def test_valid_just_before_expiry(api, clock):
    api.send()
    clock.advance(119.999)
    assert api.verify(api.code()).status_code == 200


def test_o03_expired_at_exactly_120s(api, clock):
    """O03: elapsed >= 120 s -> 410, and it stays 410."""
    api.send()
    clock.advance(120)
    assert api.verify(api.code()).status_code == 410
    assert api.verify(api.code()).status_code == 410


def test_code_is_single_use(api):
    api.send()
    c1 = api.code()
    assert api.verify(c1).status_code == 200
    assert api.verify(c1).status_code == 401


def test_no_active_code_is_401(api):
    assert api.verify("123456").status_code == 401


@pytest.mark.parametrize("code", ["12345", "1234567", "12345a", "", None, 123456, " 12345"])
def test_bad_code_is_400(api, code):
    api.send()
    assert api.verify(code).status_code == 400


@pytest.mark.parametrize("body", [b"not json", b"[]", b"{}", b""])
def test_bad_body_is_400(api, body):
    r = api.client().post("/otp/verify", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_o12_lock_on_fifth_wrong_code(api):
    """O12: 4 x 401, the 5th wrong -> 423, then 423 even for the right code and for send."""
    api.send()
    c1 = api.code()
    for _ in range(4):
        assert api.verify(wrong(c1)).status_code == 401
    assert api.verify(wrong(c1)).status_code == 423
    assert api.verify(c1).status_code == 423
    r = api.send()
    assert r.status_code == 423
    assert r.headers["Retry-After"] == "900"


def _lock(api) -> None:
    api.send()
    for _ in range(5):
        api.verify(wrong(api.code()))


def test_lock_lasts_900s(api, clock):
    _lock(api)
    clock.advance(899.999)
    assert api.send().status_code == 423
    assert api.verify("123456").status_code == 423
    clock.advance(0.001)
    assert api.send().status_code == 200
    assert api.verify(api.code()).status_code == 200


def test_lock_cancels_active_code(api, clock):
    api.send()
    c1 = api.code()
    for _ in range(5):
        api.verify(wrong(c1))
    clock.advance(900)
    assert api.verify(c1).status_code == 401


def test_counter_resets_after_lock(api, clock):
    _lock(api)
    clock.advance(900)
    api.send()
    for _ in range(4):
        assert api.verify(wrong(api.code())).status_code == 401
    assert api.verify(wrong(api.code())).status_code == 423


def test_counter_is_per_number_not_per_otp(api, clock):
    """A new send between attempts must not reset the brute-force counter."""
    api.send()
    for _ in range(4):
        assert api.verify(wrong(api.code())).status_code == 401
    clock.advance(30)
    api.send()
    assert api.verify(wrong(api.code())).status_code == 423


def test_success_resets_counter(api, clock):
    api.send()
    for _ in range(4):
        api.verify(wrong(api.code()))
    assert api.verify(api.code()).status_code == 200
    clock.advance(30)
    api.send()
    for _ in range(4):
        assert api.verify(wrong(api.code())).status_code == 401


def test_counter_ignores_missing_expired_and_bad_format(api, clock):
    for _ in range(5):
        assert api.verify("123456").status_code == 401  # no code yet
        assert api.verify("12345").status_code == 400  # bad format
    clock.advance(60)  # fresh IP window
    api.send()
    clock.advance(120)
    for _ in range(5):
        assert api.verify(wrong(api.code())).status_code == 410  # expired
    clock.advance(60)
    api.send()
    for _ in range(4):
        assert api.verify(wrong(api.code())).status_code == 401
    assert api.verify(wrong(api.code())).status_code == 423


def test_lock_is_per_number(api):
    _lock(api)
    api.send("996770730001")
    assert api.verify(api.code("996770730001"), "996770730001").status_code == 200


def test_o16_parallel_verify_one_wins(api):
    """O16: 20 parallel verify with the right code -> exactly one 200, the rest 401."""
    api.send()
    c1 = api.code()
    with ThreadPoolExecutor(20) as pool:
        statuses = list(pool.map(lambda _: api.verify(c1).status_code, range(20)))
    assert sorted(statuses) == [200] + [401] * 19


def test_parallel_from_different_ips(api):
    api.send()
    c1 = api.code()
    ips = [f"10.0.0.{i}" for i in range(10)] + [OTHER_IP] * 10
    with ThreadPoolExecutor(20) as pool:
        statuses = list(pool.map(lambda ip: api.verify(c1, MSISDN, ip).status_code, ips))
    assert statuses.count(200) == 1
