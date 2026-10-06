"""Unit tests for the strict WARC auditor. Run: python -m unittest discover -s tests"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.warc import MAX_RECORDS, AuditError, audit  # noqa: E402

from tests.warcfactory import (  # noqa: E402
    http_response,
    make_record,
    request_record,
    response_pair,
    revisit_record,
    sha256,
    warcinfo,
)


class AuditSuccessTests(unittest.TestCase):
    def test_warcinfo_only(self):
        reports = audit(warcinfo())
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].warc_type, "warcinfo")
        self.assertIsNone(reports[0].payload_digest)
        self.assertTrue(reports[0].block_digest.startswith("sha256:"))

    def test_full_capture_chain_in_order(self):
        rec1 = warcinfo("aaaa")
        req = request_record("bbbb")
        resp, _, payload = response_pair("cccc")
        rev = revisit_record("dddd", "cccc", sha256(payload))
        reports = audit(rec1 + req + resp + rev)
        self.assertEqual([r.warc_type for r in reports],
                         ["warcinfo", "request", "response", "revisit"])
        self.assertEqual([r.index for r in reports], [1, 2, 3, 4])
        self.assertEqual(reports[3].payload_digest, sha256(payload))
        self.assertEqual(reports[2].block_length, len(http_response()))

    def test_chunked_http_response(self):
        entity = b"abc" * 10
        resp, block, payload = response_pair("cccc", chunked=True, entity=entity)
        # The payload digest covers the de-chunked entity body, while the
        # block digest (checked by audit) covers the whole chunk-framed block.
        self.assertEqual(payload, entity)
        self.assertIn(b"Transfer-Encoding: chunked", block)
        reports = audit(resp)
        self.assertEqual(reports[0].payload_digest, sha256(payload))
        self.assertEqual(reports[0].block_length, len(block))

    def test_reports_preserve_original_order(self):
        recs = b"".join(
            response_pair(f"{i:04d}", entity=bytes([65 + (i % 2)]) * 3)[0]
            for i in range(1, 6)
        )
        reports = audit(recs)
        self.assertEqual([r.index for r in reports], [1, 2, 3, 4, 5])
        self.assertEqual(len({r.block_digest for r in reports}), 2)

    def test_500_records_accepted(self):
        recs = b"".join(
            response_pair(f"{i:010d}", entity=b"x")[0] for i in range(MAX_RECORDS)
        )
        self.assertEqual(len(audit(recs)), MAX_RECORDS)


class BoundaryTests(unittest.TestCase):
    def _expect(self, data, code, index=None):
        with self.assertRaises(AuditError) as ctx:
            audit(data)
        self.assertEqual(ctx.exception.code, code)
        if index is not None:
            self.assertEqual(ctx.exception.index, index)

    def test_empty(self):
        self._expect(b"", "EMPTY_ARCHIVE")

    def test_bad_version_line(self):
        bad = warcinfo().replace(b"WARC/1.1", b"WARC/1.0", 1)
        self._expect(bad, "MALFORMED_BOUNDARY", 1)

    def test_bare_lf_rejected(self):
        bad = warcinfo().replace(b"WARC/1.1\r\n", b"WARC/1.1\n", 1)
        self._expect(bad, "MALFORMED_BOUNDARY", 1)

    def test_missing_record_terminator(self):
        rec = warcinfo()
        self._expect(rec[:-4], "MALFORMED_BOUNDARY", 1)

    def test_wrong_record_terminator_lf_only(self):
        rec = warcinfo()[:-4] + b"\n\n\n\n"
        self._expect(rec, "MALFORMED_BOUNDARY", 1)

    def test_length_too_long(self):
        block = b"software: x\r\n"
        rec = make_record("1", "warcinfo", block)
        # Claim two extra bytes in Content-Length without providing them.
        rec_bad = rec.replace(
            b"Content-Length: " + str(len(block)).encode(),
            b"Content-Length: " + str(len(block) + 5).encode(),
            1,
        )
        self._expect(rec_bad, "LENGTH_MISMATCH", 1)

    def test_length_too_short_eats_terminator(self):
        block = b"software: x\r\n"
        rec = make_record("1", "warcinfo", block)
        rec_bad = rec.replace(
            b"Content-Length: " + str(len(block)).encode(),
            b"Content-Length: " + str(len(block) - 2).encode(),
            1,
        )
        self._expect(rec_bad, "DIGEST_MISMATCH", 1)

    def test_trailing_garbage_after_archive(self):
        rec = warcinfo() + b"junk"
        self._expect(rec, "MALFORMED_BOUNDARY", 2)

    def test_record_limit(self):
        recs = b"".join(
            response_pair(f"{i:010d}", entity=b"x")[0]
            for i in range(MAX_RECORDS + 1)
        )
        self._expect(recs, "RECORD_LIMIT", MAX_RECORDS + 1)


class HeaderTests(unittest.TestCase):
    def _expect(self, data, code, index=1):
        with self.assertRaises(AuditError) as ctx:
            audit(data)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(ctx.exception.index, index)

    def test_duplicate_required_header(self):
        rec = make_record("1", "warcinfo", b"x", extra_headers=(
            ("WARC-Type", "warcinfo"),
        ))
        self._expect(rec, "MALFORMED_HEADER")

    def test_missing_required_header(self):
        rec = make_record("1", "warcinfo", b"x")
        rec_bad = rec.replace(b"WARC-Date: 2026-10-06T00:00:00Z\r\n", b"", 1)
        self._expect(rec_bad, "MALFORMED_HEADER")

    def test_header_appearing_twice_with_crlf(self):
        rec = make_record("1", "warcinfo", b"x")
        rec_bad = rec.replace(
            b"Content-Type: application/warc-fields\r\n",
            b"Content-Type: application/warc-fields\r\n"
            b"Content-Type: application/warc-fields\r\n",
            1,
        )
        self._expect(rec_bad, "MALFORMED_HEADER")

    def test_obs_folding_rejected(self):
        rec = warcinfo()
        rec_bad = rec.replace(
            b"Content-Type: application/warc-fields\r\n",
            b"Content-Type: application/warc-fields\r\n continuation\r\n",
            1,
        )
        self._expect(rec_bad, "MALFORMED_HEADER")

    def test_unknown_type(self):
        rec = make_record("1", "metadata", b"x", content_type="application/octet-stream")
        self._expect(rec, "MALFORMED_HEADER")

    def test_missing_block_digest(self):
        rec = make_record("1", "warcinfo", b"x", omit_block_digest=True)
        self._expect(rec, "MALFORMED_HEADER")

    def test_bad_digest_shape_uppercase(self):
        rec = make_record(
            "1", "warcinfo", b"x",
            block_digest_override="sha256:" + "AB" * 32,
        )
        self._expect(rec, "MALFORMED_HEADER")

    def test_bad_digest_algorithm(self):
        rec = make_record(
            "1", "warcinfo", b"x",
            block_digest_override="sha1:" + "a" * 40,
        )
        self._expect(rec, "MALFORMED_HEADER")

    def test_response_without_payload_digest(self):
        block = http_response(b"hi")
        rec = make_record(
            "3", "response", block, target_uri="https://example.org/",
            payload_digest_override=None,
        )
        self._expect(rec, "MALFORMED_HEADER")

    def test_warcinfo_with_payload_digest_rejected(self):
        rec = make_record(
            "1", "warcinfo", b"x",
            payload_digest_override="sha256:" + "a" * 64,
        )
        self._expect(rec, "MALFORMED_HEADER")

    def test_bad_calendar_date(self):
        rec = make_record("1", "warcinfo", b"x", date="2026-02-30T12:00:00Z")
        self._expect(rec, "MALFORMED_HEADER")

    def test_duplicate_record_id(self):
        a, _, _ = response_pair("same-id")
        b, _, _ = response_pair("same-id", entity=b"yy")
        with self.assertRaises(AuditError) as ctx:
            audit(a + b)
        self.assertEqual(ctx.exception.code, "MALFORMED_HEADER")
        self.assertEqual(ctx.exception.index, 2)


class DigestTests(unittest.TestCase):
    def test_corrupted_block_detected_at_first_record(self):
        rec_bad = warcinfo().replace(b"software:", b"SoftWare:", 1)
        with self.assertRaises(AuditError) as ctx:
            audit(rec_bad)
        self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")
        self.assertEqual(ctx.exception.index, 1)

    def test_tampered_second_record_block(self):
        good = warcinfo("a")
        resp, block, payload = response_pair("b")
        tampered_block = block.replace(b"200 OK", b"200 ok", 1)
        resp_bad = make_record(
            "b", "response", tampered_block,
            target_uri="https://example.org/",
            payload_digest=sha256(payload),
            block_digest_override=sha256(block),  # digest kept from intact block
        )
        with self.assertRaises(AuditError) as ctx:
            audit(good + resp_bad)
        self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")
        self.assertEqual(ctx.exception.index, 2)

    def test_payload_digest_mismatch(self):
        resp, _, payload = response_pair("b")
        resp_bad = make_record(
            "b", "response", http_response(b"different body"),
            target_uri="https://example.org/",
            payload_digest=sha256(payload),  # digest of the old body
        )
        with self.assertRaises(AuditError) as ctx:
            audit(resp_bad)
        self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")
        self.assertEqual(ctx.exception.index, 1)

    def test_block_digest_covers_exact_declared_bytes(self):
        # Declared digest over the block plus one hidden byte: framing must
        # reject before the digest even matters (length/boundary check), or
        # digest mismatch if both lengths agree.
        block = b"abc"
        rec = make_record(
            "1", "warcinfo", block,
            block_digest_override=sha256(block + b"d"),
        )
        with self.assertRaises(AuditError) as ctx:
            audit(rec)
        self.assertEqual(ctx.exception.code, "DIGEST_MISMATCH")


class HttpEntityTests(unittest.TestCase):
    def _expect(self, block, code="MALFORMED_HTTP"):
        rec = make_record(
            "1", "response", block, target_uri="https://example.org/",
            payload_digest=sha256(b"ignored"),
        )
        with self.assertRaises(AuditError) as ctx:
            audit(rec)
        self.assertEqual(ctx.exception.code, code)

    def test_not_http(self):
        self._expect(b"this is not http at all")

    def test_bad_status_line(self):
        self._expect(b"HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")

    def test_content_length_mismatch(self):
        block = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"
        self._expect(block, "LENGTH_MISMATCH")

    def test_duplicate_http_content_length(self):
        block = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"
        )
        self._expect(block)

    def test_cl_and_te_together(self):
        block = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
        )
        self._expect(block)

    def test_truncated_chunk(self):
        block = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc"
        )
        self._expect(block)

    def test_no_framing_headers(self):
        self._expect(b"HTTP/1.1 200 OK\r\nX-Test: 1\r\n\r\nbody")

    def test_bare_lf_in_http_headers(self):
        self._expect(b"HTTP/1.1 200 OK\r\nContent-Length: 0\nX-Evil: 1\r\n\r\n")

    def test_content_length_leading_zero(self):
        self._expect(b"HTTP/1.1 200 OK\r\nContent-Length: 003\r\n\r\nabc")

    def test_invalid_chunk_trailer(self):
        block = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n0\r\nbad-trailer\r\n\r\n"
        )
        self._expect(block)


class ReferenceTests(unittest.TestCase):
    def _expect(self, data, code, index=None):
        with self.assertRaises(AuditError) as ctx:
            audit(data)
        self.assertEqual(ctx.exception.code, code)
        if index is not None:
            self.assertEqual(ctx.exception.index, index)

    def test_forward_reference_rejected(self):
        resp, _, payload = response_pair("later")
        rev = revisit_record("early", "later", sha256(payload))
        self._expect(rev + resp, "REFERENCE_INVALID", 1)

    def test_dangling_reference_rejected(self):
        rev = revisit_record("r1", "ghost", "sha256:" + "a" * 64)
        self._expect(rev, "REFERENCE_INVALID", 1)

    def test_reference_to_non_response_rejected(self):
        req = request_record("req")
        rev = revisit_record("r1", "req", "sha256:" + "a" * 64)
        self._expect(req + rev, "REFERENCE_INVALID", 2)

    def test_payload_digest_must_match_target(self):
        resp, _, payload = response_pair("resp")
        wrong = sha256(b"not the payload")
        self.assertNotEqual(wrong, sha256(payload))
        rev = revisit_record("r1", "resp", wrong)
        self._expect(resp + rev, "REFERENCE_INVALID", 2)

    def test_self_reference_rejected(self):
        # A revisit cannot point at itself; it is not in the known set yet.
        rev = revisit_record("self", "self", "sha256:" + "a" * 64)
        self._expect(rev, "REFERENCE_INVALID", 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
