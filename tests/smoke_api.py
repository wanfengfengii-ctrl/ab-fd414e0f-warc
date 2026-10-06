"""Black-box API smoke used by the one-shot ``verify`` service.

Posts three packages to a running instance:
  1. a fully valid WARC                 -> must be 200
  2. a WARC with a corrupted block      -> must be DIGEST_MISMATCH
  3. a WARC with a dangling revisit     -> must be REFERENCE_INVALID

Exits 0 only when all three behave exactly as specified.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.warcfactory import (  # noqa: E402
    make_record,
    request_record,
    response_pair,
    revisit_record,
    sha256,
    warcinfo,
)


def post(base_url: str, body: bytes):
    url = urlparse(base_url)
    conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=15)
    conn.request(
        "POST",
        "/api/warc/audit",
        body=body,
        headers={"Content-Type": "application/warc", "Content-Length": str(len(body))},
    )
    resp = conn.getresponse()
    doc = json.loads(resp.read())
    conn.close()
    return resp.status, doc


def check(name: str, condition: bool, detail: str) -> bool:
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}: {detail}")
    return condition


def main() -> int:
    base_url = os.environ.get("AUDIT_URL", "http://127.0.0.1:8080").rstrip("/")

    # 1) Valid package: warcinfo + request + response + matching revisit.
    info = warcinfo("aaaa")
    req = request_record("bbbb")
    resp, block, payload = response_pair("cccc")
    good_revisit = revisit_record("dddd", "cccc", sha256(payload))
    valid = info + req + resp + good_revisit

    # 2) Bad digest: response block tampered, declared digest kept.
    tampered = block.replace(b"200 OK", b"200 ok", 1)
    bad_digest_rec = make_record(
        "cccc", "response", tampered,
        target_uri="https://example.org/",
        payload_digest=sha256(payload),
        block_digest_override=sha256(block),
    )
    bad_digest = info + bad_digest_rec

    # 3) Bad reference: revisit points at a record that never appears.
    bad_reference = revisit_record("eeee", "missing", "sha256:" + "a" * 64)

    failures = 0

    status, doc = post(base_url, valid)
    ok = (
        status == 200
        and doc.get("status") == "accepted"
        and doc.get("record_count") == 4
        and [r["type"] for r in doc.get("records", [])]
        == ["warcinfo", "request", "response", "revisit"]
        and doc["records"][2]["block_digest"] == sha256(block)
    )
    failures += not check("valid package", ok, f"HTTP {status}, {doc}")

    status, doc = post(base_url, bad_digest)
    ok = (
        status == 422
        and doc.get("error", {}).get("code") == "DIGEST_MISMATCH"
        and doc["error"].get("record") == 2
    )
    failures += not check("bad digest rejected", ok, f"HTTP {status}, {doc}")

    status, doc = post(base_url, bad_reference)
    ok = (
        status == 422
        and doc.get("error", {}).get("code") == "REFERENCE_INVALID"
        and doc["error"].get("record") == 1
    )
    failures += not check("bad reference rejected", ok, f"HTTP {status}, {doc}")

    if failures:
        print(f"SMOKE FAILED: {failures} check(s) failed")
        return 1
    print("SMOKE OK: all API checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
