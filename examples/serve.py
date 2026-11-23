"""Serve the synthetic fixture shop and its "third-party" CDN on two local ports.

    python examples/serve.py                      # shop on :8000, CDN on :8001
    python examples/serve.py --port 9000 --cdn-port 9001

The shop (``fixture-site/``) and the CDN (``fixture-cdn/``) are different origins, the way a
real shop and a vendor's CDN are. ``{{CDN}}`` in the shop's HTML is replaced with the CDN's
origin, and HTML responses carry a few security headers so that scans have some to record.
Files are read on every request, so editing a CDN file simulates a vendor shipping a new
version.

Standard library only; tests import :func:`start` to run both servers on free ports.
"""

from __future__ import annotations

import argparse
import functools
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
SITE_DIR = HERE / "fixture-site"
CDN_DIR = HERE / "fixture-cdn"

# Every HTML page gets these; the checkout page also gets a report-only CSP.
PAGE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def guess_type(self, path: str | os.PathLike[str]) -> str:
        if str(path).endswith((".js", ".mjs")):
            return "text/javascript"
        return super().guess_type(path)


class _CdnHandler(_QuietHandler):
    pass


class _SiteHandler(_QuietHandler):
    cdn_origin = ""

    def do_GET(self) -> None:
        path = self.translate_path(self.path)
        if Path(path).is_dir() and self.path.split("?", 1)[0].endswith("/"):
            path = str(Path(path) / "index.html")
        if not path.endswith(".html"):
            super().do_GET()
            return
        try:
            html = Path(path).read_text(encoding="utf-8")
        except OSError:
            self.send_error(404)
            return
        body = html.replace("{{CDN}}", self.cdn_origin).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in PAGE_HEADERS.items():
            self.send_header(name, value)
        if path.endswith("checkout.html"):
            self.send_header(
                "Content-Security-Policy-Report-Only",
                f"script-src 'self' {self.cdn_origin} 'nonce-demo-nonce'; report-uri /csp-reports",
            )
        self.end_headers()
        self.wfile.write(body)


@dataclass(frozen=True)
class Demo:
    site_origin: str
    cdn_origin: str


def _serve(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    return thread


@contextmanager
def start(host: str = "127.0.0.1", port: int = 0, cdn_port: int = 0) -> Iterator[Demo]:
    """Run the CDN and the shop in background threads (port 0 picks a free port)."""
    cdn = ThreadingHTTPServer((host, cdn_port), functools.partial(_CdnHandler, directory=CDN_DIR))
    cdn.daemon_threads = True
    cdn_origin = f"http://{host}:{cdn.server_address[1]}"
    handler = type("Handler", (_SiteHandler,), {"cdn_origin": cdn_origin})
    site = ThreadingHTTPServer((host, port), functools.partial(handler, directory=SITE_DIR))
    site.daemon_threads = True
    _serve(cdn)
    _serve(site)
    try:
        yield Demo(site_origin=f"http://{host}:{site.server_address[1]}", cdn_origin=cdn_origin)
    finally:
        for server in (site, cdn):
            server.shutdown()
            server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--cdn-port", type=int, default=8001)
    args = parser.parse_args()
    with start(args.host, args.port, args.cdn_port) as demo:
        print(f"shop on {demo.site_origin}, CDN on {demo.cdn_origin} (Ctrl-C to stop)")
        with suppress(KeyboardInterrupt):
            threading.Event().wait()


if __name__ == "__main__":
    main()
