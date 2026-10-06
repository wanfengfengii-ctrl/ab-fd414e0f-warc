"""End-to-end smoke tests against the real HTTP server.

The server is started on an ephemeral port inside this process, so the same
checks run locally and inside the one-shot ``verify`` Compose service.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.server import build_server  # noqa: E402

from tests.warcfactory import (  # noqa: E402
    make_record,
    request_record,
    response_pair,
    revisit_record,
    sha256,
    warcinfo,
)


class ServerSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = build_server("127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _post(self, body: bytes, content_type: str = "application/warc"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/api/warc/audit",
            body=body,
            headers={"Content-Type": content_type, "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        payload = resp.read()
        conn.close()
        return resp.status, json.loads(payload)

    def _get(self, path: str):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    # ------------------------------------------------------------------
    def test_health(self):
        status, body = self._get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")

    def test_valid_package_accepted_in_order(self):
        info = warcinfo("aaaa")
        req = request_record("bbbb")
        resp, block, payload = response_pair("cccc")
        rev = revisit_record("dddd", "cccc", sha256(payload))
        status, doc = self._post(info + req + resp + rev)
        self.assertEqual(status, 200, doc)
        self.assertEqual(doc["status"], "accepted")
        self.assertEqual(doc["record_count"], 4)
        self.assertEqual(
            [(r["index"], r["type"]) for r in doc["records"]],
            [(1, "warcinfo"), (2, "request"), (3, "response"), (4, "revisit")],
        )
        self.assertEqual(doc["records"][2]["block_length"], len(block))
        self.assertEqual(doc["records"][2]["block_digest"], sha256(block))
        self.assertEqual(doc["records"][2]["payload_digest"], sha256(payload))

    def test_bad_digest_rejects_whole_package(self):
        good = warcinfo("aaaa")
        resp, block, payload = response_pair("cccc")
        tampered = block.replace(b"200 OK", b"200 ok", 1)
        bad = make_record(
            "cccc", "response", tampered,
            target_uri="https://example.org/",
            payload_digest=sha256(payload),
            block_digest_override=sha256(block),
        )
        status, doc = self._post(good + bad)
        self.assertEqual(status, 422, doc)
        self.assertEqual(doc["error"]["code"], "DIGEST_MISMATCH")
        self.assertEqual(doc["error"]["record"], 2)

    def test_bad_payload_digest(self):
        resp, block, _ = response_pair("cccc")
        bad = make_record(
            "cccc", "response", block,
            target_uri="https://example.org/",
            payload_digest=sha256(b"other"),
        )
        status, doc = self._post(bad)
        self.assertEqual(status, 422, doc)
        self.assertEqual(doc["error"]["code"], "DIGEST_MISMATCH")
        self.assertEqual(doc["error"]["record"], 1)

    def test_forward_reference_rejected(self):
        resp, _, payload = response_pair("later")
        rev = revisit_record("early", "later", sha256(payload))
        status, doc = self._post(rev + resp)
        self.assertEqual(status, 422, doc)
        self.assertEqual(doc["error"]["code"], "REFERENCE_INVALID")
        self.assertEqual(doc["error"]["record"], 1)

    def test_dangling_reference_rejected(self):
        rev = revisit_record("lonely", "ghost", "sha256:" + "a" * 64)
        status, doc = self._post(rev)
        self.assertEqual(status, 422, doc)
        self.assertEqual(doc["error"]["code"], "REFERENCE_INVALID")
        self.assertEqual(doc["error"]["record"], 1)

    def test_boundary_error_reports_first_bad_record(self):
        bad = warcinfo() + b"not a warc record"
        status, doc = self._post(bad)
        self.assertEqual(status, 400, doc)
        self.assertEqual(doc["error"]["code"], "MALFORMED_BOUNDARY")
        self.assertEqual(doc["error"]["record"], 2)

    def test_wrong_content_type(self):
        status, doc = self._post(warcinfo(), content_type="application/octet-stream")
        self.assertEqual(status, 415, doc)
        self.assertEqual(doc["error"]["code"], "UNSUPPORTED_MEDIA_TYPE")

    def test_too_large(self):
        block = b"x" * (16 * 1024 * 1024 + 1)
        rec = make_record("big", "warcinfo", block, content_type="application/warc-fields")
        status, doc = self._post(rec)
        self.assertEqual(status, 413, doc)
        self.assertEqual(doc["error"]["code"], "FILE_TOO_LARGE")

    def test_empty_body(self):
        status, doc = self._post(b"")
        self.assertEqual(status, 400, doc)
        self.assertEqual(doc["error"]["code"], "EMPTY_ARCHIVE")

    def test_keep_alive_reuses_connection_after_rejection(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            # First request is rejected for the wrong media type...
            conn.request(
                "POST",
                "/api/warc/audit",
                body=warcinfo(),
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(warcinfo())),
                },
            )
            first = conn.getresponse()
            self.assertEqual(first.status, 415)
            first.read()
            # ...and the same connection still serves a valid request.
            info = warcinfo("aaaa")
            resp, _, payload = response_pair("cccc")
            package = info + resp
            conn.request(
                "POST",
                "/api/warc/audit",
                body=package,
                headers={"Content-Type": "application/warc",
                         "Content-Length": str(len(package))},
            )
            second = conn.getresponse()
            doc = json.loads(second.read())
            self.assertEqual(second.status, 200, doc)
            self.assertEqual(doc["record_count"], 2)
            self.assertEqual(doc["records"][1]["payload_digest"], sha256(payload))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
