"""Build the OTP Shield bot avatar and logos (Catppuccin) as SVG + PNG next to this file.

Run: python assets/gen.py  (needs Google Chrome for PNG rendering; Windows path below).
"""

import subprocess
import tempfile
from pathlib import Path

OUT = Path(__file__).parent
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SHIELD = "M256 48 L432 112 V240 C432 352 360 424 256 464 C152 424 80 352 80 240 V112 Z"
DOT_XS, DOT_YS, DOT_R = (176, 256, 336), (224, 312), 32  # six code digits, 3x2

MOCHA = {"base": "#1e1e2e", "text": "#cdd6f4", "accent": "#cba6f7"}  # accent = mauve
LATTE = {"text": "#4c4f69", "accent": "#8839ef"}


def dots(fill: str) -> str:
    return "".join(f'<circle cx="{x}" cy="{y}" r="{DOT_R}" fill="{fill}"/>' for x in DOT_XS for y in DOT_YS)


def avatar() -> str:
    # Shield scaled to 80% so Telegram's circular crop does not cut it.
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">'
        f'<rect width="512" height="512" fill="{MOCHA["base"]}"/>'
        '<g transform="translate(256 256) scale(0.8) translate(-256 -256)">'
        f'<path d="{SHIELD}" fill="{MOCHA["accent"]}"/>{dots(MOCHA["base"])}</g></svg>'
    )


def logo(pal: dict) -> str:
    # Dots are cut out of the shield, so the logo has no tile and works on any background.
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" width="760" height="200" viewBox="0 0 760 200">'
        f'<defs><mask id="m"><rect width="512" height="512" fill="#fff"/>{dots("#000")}</mask></defs>'
        f'<g transform="translate(20 8) scale(0.36)"><path d="{SHIELD}" fill="{pal["accent"]}" mask="url(#m)"/></g>'
        '<text x="220" y="128" font-family="Segoe UI, Inter, Helvetica, Arial, sans-serif" font-size="84" '
        f'font-weight="700" fill="{pal["text"]}">OTP <tspan fill="{pal["accent"]}">Shield</tspan></text></svg>'
    )


def render(svg: Path, size: str, profile: str) -> None:
    subprocess.run(
        [CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--user-data-dir={profile}",
         "--default-background-color=00000000", f"--screenshot={svg.with_suffix('.png')}",
         f"--window-size={size}", svg.as_uri()],
        capture_output=True, check=True,
    )


def main() -> None:
    files = {
        "avatar": (avatar(), "512,512"),
        "logo-mocha": (logo(MOCHA), "760,200"),  # for dark backgrounds
        "logo-latte": (logo(LATTE), "760,200"),  # for light backgrounds
    }
    with tempfile.TemporaryDirectory() as profile:
        for stem, (svg, size) in files.items():
            path = OUT / f"{stem}.svg"
            path.write_text(svg, encoding="utf-8")
            render(path, size, profile)


if __name__ == "__main__":
    main()
