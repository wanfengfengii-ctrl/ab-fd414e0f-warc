"""HTTP front end for the WARC auditor.

Endpoints
---------
POST /api/warc/audit   raw body of Content-Type application/warc, <= 16 MiB
GET  /healthz          liveness/readiness probe
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .warc import ALLOWED_TYPES, AuditError, MAX_BYTES, audit

CONTENT_TYPE = "application/warc"

# Stable error codes. Anything else is an unexpected server fault (500).
HTTP_STATUS = {
    "EMPTY_ARCHIVE": 400,
    "FILE_TOO_LARGE": 413,
    "MALFORMED_BOUNDARY": 400,
    "MALFORMED_HEADER": 400,
    "MALFORMED_HTTP": 400,
    "LENGTH_MISMATCH": 400,
    "DIGEST_MISMATCH": 422,
    "REFERENCE_INVALID": 422,
    "RECORD_LIMIT": 400,
}


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "WarcAudit/1.0"
    protocol_version = "HTTP/1.1"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        if self.path.split("?", 1)[0] == "/healthz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "unknown route"}})

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook
        if self.path.split("?", 1)[0] != "/api/warc/audit":
            self._send_json(
                404, {"error": {"code": "NOT_FOUND", "message": "unknown route"}}
            )
            return

        try:
            declared_len = int(self.headers.get("Content-Length", ""))
        except ValueError:
            # Without a length frame the request cannot be consumed safely.
            self.close_connection = True
            self._reject(411, "LENGTH_REQUIRED", "Content-Length header is required")
            return

        if declared_len <= 0:
            self._reject(400, "EMPTY_ARCHIVE", "request body is empty")
            return

        if declared_len > MAX_BYTES:
            # Drain what the client already sends so it can receive the 413
            # instead of a TCP reset; give up draining pathologically large
            # claims and close the connection instead.
            if not self._drain(declared_len, hard_cap=64 * 1024 * 1024):
                self.close_connection = True
            self._reject(
                413,
                "FILE_TOO_LARGE",
                f"archive exceeds the {MAX_BYTES} byte limit",
            )
            return

        # Consume the whole framed body first so that rejection responses stay
        # compatible with HTTP/1.1 keep-alive.
        data = self._read_exactly(declared_len)
        if data is None:
            return  # response already sent

        ctype = self.headers.get("Content-Type", "")
        main_type = ctype.split(";", 1)[0].strip().lower()
        if main_type != CONTENT_TYPE:
            self._reject(
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                f"Content-Type must be {CONTENT_TYPE}",
            )
            return

        try:
            records = audit(data)
        except AuditError as exc:
            self._send_json(
                HTTP_STATUS.get(exc.code, 400),
                {
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "record": exc.index,
                    }
                },
            )
            return

        self._send_json(
            200,
            {
                "status": "accepted",
                "record_count": len(records),
                "record_types": ALLOWED_TYPES,
                "records": [r.to_dict() for r in records],
            },
        )

    # ------------------------------------------------------------------
    def _drain(self, length: int, hard_cap: int) -> bool:
        """Consume and discard up to ``length`` body bytes.

        Returns True when the whole declared body was consumed (the keep-alive
        connection stays usable), False when ``hard_cap`` was hit and the
        connection must be closed.
        """
        budget = min(length, hard_cap)
        remaining = budget
        try:
            while remaining:
                chunk = self.rfile.read(min(remaining, 1024 * 1024))
                if not chunk:
                    return False
                remaining -= len(chunk)
        except (ConnectionError, OSError):
            return False
        return budget == length

    def _read_exactly(self, length: int) -> bytes | None:
        chunks: list[bytes] = []
        remaining = length
        try:
            while remaining:
                chunk = self.rfile.read(min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except (ConnectionError, OSError):
            self.close_connection = True
            self._reject(400, "TRUNCATED_REQUEST", "client closed the request early")
            return None
        if remaining:
            self.close_connection = True
            self._reject(400, "TRUNCATED_REQUEST", "request body shorter than declared")
            return None
        return b"".join(chunks)

    def _reject(self, status: int, code: str, message: str, record: int | None = None):
        self._send_json(
            status,
            {"error": {"code": code, "message": message, "record": record}},
        )

    def log_message(self, fmt: str, *args) -> None:  # quieter, structured log
        import sys

        sys.stderr.write(
            '{"event":"http", "client":%s, "message":%s}\n'
            % (json.dumps(self.address_string()), json.dumps(fmt % args))
        )


def build_server(host: str = "0.0.0.0", port: int | None = None) -> ThreadingHTTPServer:
    port = port if port is not None else int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), AuditHandler)
    httpd.daemon_threads = True
    return httpd


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    httpd = build_server(host)
    print(f"WARC audit service listening on {host}:{httpd.server_address[1]}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
