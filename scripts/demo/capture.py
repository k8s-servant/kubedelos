"""Take the README pictures from a running ``kubedelos ui``: screenshots of the dashboard, its fix-first list with the
top fix opened and the findings sorted by risk, in the light and dark themes, and a recording of a scan from the Scans
page to the risk-sorted findings.

Run it against the demo cluster only (scripts/demo/cluster.sh), with an empty data directory, so the pictures hold
nothing from a real cluster; scripts/demo/README.md has the steps. It needs Playwright (``pip install playwright`` in a
scratch virtualenv) and drives the installed Google Chrome, so no browser is downloaded:

    python scripts/demo/capture.py URL OUT_DIR [--scan]

URL is the token URL ``kubedelos ui`` printed. With ``--scan`` it first records a scan as numbered frames in
``OUT_DIR/frames``, which scripts/demo/gif.sh turns into a GIF; the scan itself plays as a time lapse.
"""

import argparse
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Page, sync_playwright

VIEWPORT = {"width": 1280, "height": 800}
SCAN_TIMEOUT_S = 20 * 60
FPS = 4  # the playback rate scripts/demo/gif.sh uses


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _sign_in(page: Page, url: str) -> None:
    page.goto(url)  # the token is swapped for a session cookie, then the dashboard loads
    page.wait_for_load_state("networkidle")


class _Frames:
    """Numbered screenshots of ``page``, played back at FPS by scripts/demo/gif.sh. ``hold`` shows the page for that
    long; ``lapse`` keeps one frame every ``every`` seconds while ``busy()`` holds, so a long wait plays fast."""

    def __init__(self, page: Page, out: Path) -> None:
        self.page, self.out, self.count = page, out, 0
        out.mkdir(parents=True, exist_ok=True)

    def shot(self) -> None:
        self.page.screenshot(path=self.out / f"{self.count:04d}.png")
        self.count += 1

    def hold(self, seconds: float) -> None:
        for _ in range(max(1, round(seconds * FPS))):
            self.shot()
            time.sleep(1 / FPS)

    def lapse(self, busy, every: float, limit_s: float) -> None:
        deadline = time.monotonic() + limit_s
        while busy():
            if time.monotonic() > deadline:
                raise TimeoutError("the scan did not finish in time")
            self.shot()
            time.sleep(every)


def _record_scan(browser, url: str, out: Path) -> None:
    context = browser.new_context(viewport=VIEWPORT)
    page = context.new_page()
    frames = _Frames(page, out / "frames")
    _sign_in(page, url)
    origin = _origin(url)
    page.goto(f"{origin}/scans")
    page.get_by_label("Rescan every image").check()  # scan for real rather than from the 24-hour result cache
    frames.hold(1.5)
    page.get_by_role("button", name="Scan ").first.click()
    # The progress readout polls itself (hx-get) while the scan runs and loses the attribute once it has ended.
    polling = "() => document.querySelector('#scan-progress')?.hasAttribute('hx-get') ?? false"
    page.wait_for_function(polling, timeout=30_000)
    frames.lapse(lambda: page.evaluate(polling), every=2.0, limit_s=SCAN_TIMEOUT_S)
    page.wait_for_load_state("networkidle")
    frames.hold(1.5)
    page.goto(f"{origin}/")
    page.wait_for_load_state("networkidle")
    frames.hold(3)
    _open_top_fix(page)
    frames.hold(4)
    page.goto(f"{origin}/findings?sort=risk")
    page.wait_for_load_state("networkidle")
    frames.hold(3)
    context.close()


def _open_top_fix(page: Page) -> None:
    """Scroll to the fix-first list and open its top row, which shows the factors behind the score."""
    row = page.locator("details.fix-row").first
    page.evaluate("y => window.scrollBy(0, y)", row.bounding_box()["y"] - 140)
    row.locator("summary").click()
    page.wait_for_timeout(300)


def _shoot(browser, url: str, out: Path, scheme: str) -> None:
    context = browser.new_context(viewport=VIEWPORT, color_scheme=scheme, device_scale_factor=2)
    page = context.new_page()
    _sign_in(page, url)
    origin = _origin(url)
    page.goto(f"{origin}/")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=out / f"dashboard-{scheme}.png")
    _open_top_fix(page)
    page.screenshot(path=out / f"fix-first-{scheme}.png")
    page.goto(f"{origin}/findings?sort=risk")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=out / f"findings-risk-{scheme}.png")
    context.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("url")
    parser.add_argument("out", type=Path)
    parser.add_argument("--scan", action="store_true", help="record a scan first")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        if args.scan:
            _record_scan(browser, args.url, args.out)
        for scheme in ("light", "dark"):
            _shoot(browser, args.url, args.out, scheme)
        browser.close()


if __name__ == "__main__":
    main()
