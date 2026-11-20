"""IP limit on verify: 20 requests in (t-60, t] per IP over all numbers, the 21st -> 429."""

from tests.conftest import IP, OTHER_IP, wrong


def _numbers(n: int) -> list[str]:
    return [f"9967707{i:05d}" for i in range(n)]


def test_20_pass_21st_is_429(api):
    for msisdn in _numbers(20):
        assert api.verify("123456", msisdn).status_code == 401
    r = api.verify("123456", "996770799999")
    assert r.status_code == 429
    assert "detail" in r.json()


def test_bad_format_counts_too(api):
    for _ in range(20):
        assert api.verify("bad").status_code == 400
    assert api.verify("bad").status_code == 429


def test_ip_limit_checked_before_format_and_lock(api):
    api.send()
    for _ in range(5):
        api.verify(wrong(api.code()))  # number locked, 5 hits used
    for _ in range(15):
        assert api.verify("bad").status_code == 400
    assert api.verify("bad").status_code == 429
    assert api.verify(api.code()).status_code == 429  # not 423


def test_other_ip_is_not_limited(api):
    for _ in range(20):
        api.verify("123456")
    assert api.verify("123456", ip=IP).status_code == 429
    assert api.verify("123456", ip=OTHER_IP).status_code == 401


def test_window_is_sliding_60s(api, clock):
    for _ in range(10):
        api.verify("123456")
    clock.advance(30)
    for _ in range(10):
        api.verify("123456")
    clock.advance(29.999)
    assert api.verify("123456").status_code == 429
    clock.advance(0.001)  # t=60: the first 10 hits left (t-60, t]
    for _ in range(10):
        assert api.verify("123456").status_code == 401
    assert api.verify("123456").status_code == 429


def test_rejected_requests_do_not_extend_the_window(api, clock):
    for _ in range(20):
        api.verify("123456")
    for _ in range(59):
        clock.advance(1)
        assert api.verify("123456").status_code == 429
    clock.advance(1)
    assert api.verify("123456").status_code == 401


def test_x_forwarded_for_is_ignored(api):
    for _ in range(20):
        api.verify("123456")
    r = api.client().post(
        "/otp/verify",
        json={"msisdn": "996770730000", "code": "123456"},
        headers={"X-Forwarded-For": OTHER_IP},
    )
    assert r.status_code == 429
