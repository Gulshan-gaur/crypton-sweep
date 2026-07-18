#!/usr/bin/env python3
"""Serve a generated Crypton Sweep HTML report on localhost."""

from __future__ import annotations

import argparse
import os
import threading
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve a Crypton Sweep report in a browser")
    parser.add_argument("--report", default="scan.html", help="HTML filename inside --directory")
    parser.add_argument("--directory", default="reports", help="Directory containing reports")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address; localhost by default")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    directory = Path(args.directory).resolve()
    report = Path(args.report)
    if report.is_absolute() or ".." in report.parts:
        raise SystemExit("--report must be a filename relative to --directory")
    report_path = directory / report
    if not report_path.is_file():
        raise SystemExit(f"report not found: {report_path}")

    directory.mkdir(parents=True, exist_ok=True)
    handler = lambda *handler_args, **handler_kwargs: SimpleHTTPRequestHandler(
        *handler_args, directory=os.fspath(directory), **handler_kwargs
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    url = f"http://{args.host}:{args.port}/{quote(report.as_posix())}"
    print(f"[crypton-sweep] serving {report_path}")
    print(f"[crypton-sweep] dashboard: {url}")
    print("[crypton-sweep] press Ctrl+C to stop")
    if not args.no_browser:
        threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[crypton-sweep] server stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
