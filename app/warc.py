"""Strict byte-level WARC 1.1 auditor.

The parser is intentionally unforgiving: records must be framed exactly as
WARC 1.1 specifies (CRLF line endings, single required headers, a Content-Length
that accounts for every block byte). Block and payload digests are recomputed
from the declared raw bytes, so tolerant re-parsing can never launder a
corrupted record into the archive.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 500

CRLF = b"\r\n"
RECORD_TERMINATOR = b"\r\n\r\n"
VERSION_LINE = b"WARC/1.1\r\n"

ALLOWED_TYPES = ("warcinfo", "request", "response", "revisit")

# RFC 7230 token characters, used for both WARC and HTTP header field names.
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$")
_ANGLE_URI_RE = re.compile(r"^<[^<>\s]+>$")
_DIGEST_ALGO = "sha256"


class AuditError(Exception):
    """A rejection. ``index`` is the 1-based record number, when attributable."""

    def __init__(self, code: str, message: str, index: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.index = index


@dataclass
class RecordReport:
    index: int
    warc_type: str
    block_length: int
    block_digest: str
    payload_digest: str | None

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "type": self.warc_type,
            "block_length": self.block_length,
            "block_digest": self.block_digest,
            "payload_digest": self.payload_digest,
        }


# ---------------------------------------------------------------------------
# Low level helpers
# ---------------------------------------------------------------------------


def _read_line(data: bytes, pos: int, index: int) -> tuple[bytes, int]:
    """Read one CRLF-terminated line, rejecting bare LF."""
    crlf = data.find(CRLF, pos)
    if crlf == -1:
        raise AuditError(
            "MALFORMED_BOUNDARY",
            "unterminated line; every line must end with CRLF",
            index,
        )
    line = data[pos:crlf]
    if b"\n" in line:
        raise AuditError(
            "MALFORMED_HEADER", "bare LF line ending is not permitted", index
        )
    return line, crlf + 2


def _parse_headers(data: bytes, pos: int, index: int) -> tuple[dict[str, str], int]:
    """Parse a CRLF-framed header section ending in an empty line."""
    headers: dict[str, str] = {}
    while True:
        line, pos = _read_line(data, pos, index)
        if not line:
            break
        if line[:1] in (b" ", b"\t"):
            raise AuditError(
                "MALFORMED_HEADER", "obs-fold header continuation is not permitted", index
            )
        colon = line.find(b":")
        if colon <= 0:
            raise AuditError("MALFORMED_HEADER", "header field missing ':'", index)
        name_b = line[:colon]
        value_b = line[colon + 1 :]
        try:
            name = name_b.decode("ascii")
        except UnicodeDecodeError:
            raise AuditError(
                "MALFORMED_HEADER", "header field name is not ASCII", index
            ) from None
        if not _TOKEN_RE.match(name):
            raise AuditError(
                "MALFORMED_HEADER", f"invalid header field name: {name!r}", index
            )
        if value_b[:1] in (b" ", b"\t"):
            value_b = value_b[1:]
            while value_b[:1] in (b" ", b"\t"):
                value_b = value_b[1:]
        try:
            value = value_b.decode("utf-8")
        except UnicodeDecodeError:
            raise AuditError(
                "MALFORMED_HEADER", "header value is not valid UTF-8", index
            ) from None
        key = name.lower()
        if key in headers:
            raise AuditError(
                "MALFORMED_HEADER", f"duplicate header field: {name}", index
            )
        headers[key] = value
    return headers, pos


def _digest_value(headers: dict[str, str], name: str, index: int) -> str | None:
    raw = headers.get(name)
    if raw is None:
        return None
    if not _DIGEST_RE.match(raw):
        raise AuditError(
            "MALFORMED_HEADER",
            f"{name} must be 'sha256:' followed by 64 lowercase hex digits",
            index,
        )
    return raw


def _sha256_hex(block: bytes) -> str:
    return _DIGEST_ALGO + ":" + hashlib.sha256(block).hexdigest()


# ---------------------------------------------------------------------------
# HTTP/1.x entity body extraction (for response records)
# ---------------------------------------------------------------------------

_STATUS_RE = re.compile(rb"^HTTP/1\.[01] [1-5][0-9]{2}(?: [\t\x21-\x7e]*)?$")
_CHUNK_SIZE_RE = re.compile(rb"^[0-9A-Fa-f]+(?:;.*)?$")


def _http_entity_body(block: bytes, index: int) -> bytes:
    sep = block.find(RECORD_TERMINATOR)
    if sep == -1:
        raise AuditError(
            "MALFORMED_HTTP", "response block is not a framed HTTP message", index
        )
    head = block[:sep]
    if any(head[i] == 0x0A and (i == 0 or head[i - 1] != 0x0D) for i in range(len(head))):
        raise AuditError(
            "MALFORMED_HTTP", "bare LF in HTTP header section is not permitted", index
        )
    lines = head.split(CRLF)
    status = lines[0]
    if not _STATUS_RE.match(status):
        raise AuditError(
            "MALFORMED_HTTP", "invalid HTTP status line in response block", index
        )
    http_headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            raise AuditError(
                "MALFORMED_HTTP", "premature blank line in HTTP headers", index
            )
        if line[:1] in (b" ", b"\t"):
            raise AuditError(
                "MALFORMED_HTTP", "obs-fold HTTP header is not permitted", index
            )
        colon = line.find(b":")
        if colon <= 0:
            raise AuditError("MALFORMED_HTTP", "HTTP header missing ':'", index)
        try:
            name = line[:colon].decode("ascii", "strict").lower()
        except UnicodeDecodeError:
            raise AuditError(
                "MALFORMED_HTTP", "HTTP header name is not ASCII", index
            ) from None
        if not _TOKEN_RE.match(name):
            raise AuditError("MALFORMED_HTTP", "invalid HTTP header name", index)
        value = line[colon + 1 :]
        while value[:1] in (b" ", b"\t"):
            value = value[1:]
        while value[-1:] in (b" ", b"\t"):
            value = value[:-1]
        if name in ("content-length", "transfer-encoding") and name in http_headers:
            raise AuditError(
                "MALFORMED_HTTP", f"duplicate HTTP {name} header", index
            )
        http_headers[name] = value.decode("iso-8859-1")

    body_start = sep + len(RECORD_TERMINATOR)
    body = block[body_start:]

    te = http_headers.get("transfer-encoding")
    clen = http_headers.get("content-length")
    if te is not None and clen is not None:
        raise AuditError(
            "MALFORMED_HTTP",
            "HTTP message must not use both Transfer-Encoding and Content-Length",
            index,
        )

    if te is not None:
        if te.strip().lower() != "chunked":
            raise AuditError(
                "MALFORMED_HTTP",
                "only 'Transfer-Encoding: chunked' is supported",
                index,
            )
        return _decode_chunked(body, index)

    if clen is None:
        raise AuditError(
            "MALFORMED_HTTP",
            "HTTP response must declare Content-Length or chunked encoding",
            index,
        )
    if not re.fullmatch(rb"(?:0|[1-9][0-9]*)", clen.encode("ascii")):
        raise AuditError(
            "MALFORMED_HTTP",
            "invalid HTTP Content-Length (digits only, no leading zeros)",
            index,
        )
    length = int(clen)
    if length != len(body):
        raise AuditError(
            "LENGTH_MISMATCH",
            f"HTTP entity body is {len(body)} bytes, Content-Length declares {length}",
            index,
        )
    return body


def _decode_chunked(body: bytes, index: int) -> bytes:
    out = bytearray()
    pos = 0
    while True:
        crlf = body.find(CRLF, pos)
        if crlf == -1:
            raise AuditError("MALFORMED_HTTP", "truncated chunked body", index)
        size_line = body[pos:crlf]
        if not _CHUNK_SIZE_RE.match(size_line):
            raise AuditError("MALFORMED_HTTP", "invalid chunk size line", index)
        size_hex = size_line.split(b";", 1)[0]
        try:
            size = int(size_hex, 16)
        except ValueError:
            raise AuditError("MALFORMED_HTTP", "invalid chunk size", index) from None
        pos = crlf + 2
        if size == 0:
            # Zero or more trailer entity-headers, then a terminating empty line.
            while pos < len(body):
                line_end = body.find(CRLF, pos)
                if line_end == -1:
                    raise AuditError(
                        "MALFORMED_HTTP", "truncated chunk trailers", index
                    )
                if line_end == pos:
                    pos = line_end + 2
                    break
                trailer = body[pos:line_end]
                tcolon = trailer.find(b":")
                try:
                    tname = trailer[:tcolon].decode("ascii") if tcolon > 0 else ""
                except UnicodeDecodeError:
                    tname = ""
                if tcolon <= 0 or not _TOKEN_RE.match(tname):
                    raise AuditError(
                        "MALFORMED_HTTP", "invalid chunk trailer field", index
                    )
                pos = line_end + 2
            if pos != len(body):
                raise AuditError(
                    "MALFORMED_HTTP", "trailing bytes after last chunk", index
                )
            return bytes(out)
        if pos + size + 2 > len(body):
            raise AuditError("MALFORMED_HTTP", "truncated chunk data", index)
        if body[pos + size : pos + size + 2] != CRLF:
            raise AuditError(
                "MALFORMED_HTTP", "chunk data not terminated by CRLF", index
            )
        out.extend(body[pos : pos + size])
        pos += size + 2


# ---------------------------------------------------------------------------
# WARC record validation
# ---------------------------------------------------------------------------

_REQUIRED_COMMON = ("warc-type", "warc-record-id", "warc-date", "content-length")


def _validate_warc_headers(headers: dict[str, str], index: int) -> str:
    for name in _REQUIRED_COMMON:
        if name not in headers:
            raise AuditError(
                "MALFORMED_HEADER", f"required header missing: {name}", index
            )

    warc_type = headers["warc-type"]
    if warc_type not in ALLOWED_TYPES:
        raise AuditError(
            "MALFORMED_HEADER",
            f"unsupported WARC-Type: {warc_type!r}",
            index,
        )

    if not _ANGLE_URI_RE.match(headers["warc-record-id"]):
        raise AuditError(
            "MALFORMED_HEADER",
            "WARC-Record-ID must be an angle-bracket enclosed URI",
            index,
        )

    date = headers["warc-date"]
    m = _DATE_RE.match(date)
    if not m:
        raise AuditError(
            "MALFORMED_HEADER",
            "WARC-Date must be RFC 3339 UTC, e.g. 2026-01-01T00:00:00Z",
            index,
        )
    year, month, day = int(m[1]), int(m[2]), int(m[3])
    hour, minute, second = int(m[4]), int(m[5]), int(m[6])
    try:
        datetime(year, month, day, hour, minute, second)
    except ValueError:
        raise AuditError(
            "MALFORMED_HEADER", "WARC-Date is not a valid calendar date", index
        ) from None

    raw_len = headers["content-length"]
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", raw_len):
        raise AuditError(
            "MALFORMED_HEADER",
            "Content-Length must be digits without leading zeros",
            index,
        )

    content_type = headers.get("content-type", "").strip()
    if warc_type == "warcinfo" and content_type != "application/warc-fields":
        raise AuditError(
            "MALFORMED_HEADER",
            "warcinfo records require 'Content-Type: application/warc-fields'",
            index,
        )
    if warc_type == "request" and content_type != "application/http;msgtype=request":
        raise AuditError(
            "MALFORMED_HEADER",
            "request records require 'Content-Type: application/http;msgtype=request'",
            index,
        )
    if warc_type == "response" and content_type != "application/http;msgtype=response":
        raise AuditError(
            "MALFORMED_HEADER",
            "response records require 'Content-Type: application/http;msgtype=response'",
            index,
        )
    if warc_type == "revisit" and content_type != "application/http;msgtype=response":
        raise AuditError(
            "MALFORMED_HEADER",
            "revisit records require 'Content-Type: application/http;msgtype=response'",
            index,
        )

    if warc_type in ("request", "response", "revisit"):
        target = headers.get("warc-target-uri")
        if target is None or not target.strip() or " " in target:
            raise AuditError(
                "MALFORMED_HEADER",
                f"{warc_type} records require a valid WARC-Target-URI",
                index,
            )
    if warc_type == "revisit" and not headers.get("warc-profile", "").strip():
        raise AuditError(
            "MALFORMED_HEADER", "revisit records require WARC-Profile", index
        )

    return warc_type


def audit(data: bytes) -> list[RecordReport]:
    """Audit a complete WARC 1.1 byte string. Raises AuditError on any fault."""
    if not data:
        raise AuditError("EMPTY_ARCHIVE", "no WARC records found", None)
    if len(data) > MAX_BYTES:
        raise AuditError("FILE_TOO_LARGE", f"archive exceeds {MAX_BYTES} bytes", None)
    if not data.startswith(VERSION_LINE):
        raise AuditError(
            "MALFORMED_BOUNDARY",
            "archive must begin with 'WARC/1.1' followed by CRLF",
            1,
        )

    pos = 0
    records: list[RecordReport] = []
    # record id -> (type, computed payload digest for responses)
    known: dict[str, tuple[str, str | None]] = {}

    while pos < len(data):
        index = len(records) + 1
        if index > MAX_RECORDS:
            raise AuditError(
                "RECORD_LIMIT", f"archive holds more than {MAX_RECORDS} records", index
            )
        if not data.startswith(VERSION_LINE, pos):
            raise AuditError(
                "MALFORMED_BOUNDARY",
                "expected a new 'WARC/1.1' version line",
                index,
            )
        pos += len(VERSION_LINE)

        headers, pos = _parse_headers(data, pos, index)
        warc_type = _validate_warc_headers(headers, index)
        length = int(headers["content-length"])

        declared_block_digest = _digest_value(
            headers, "warc-block-digest", index
        )
        if declared_block_digest is None:
            raise AuditError(
                "MALFORMED_HEADER", "WARC-Block-Digest is required", index
            )
        declared_payload_digest = _digest_value(
            headers, "warc-payload-digest", index
        )
        if warc_type in ("response", "revisit") and declared_payload_digest is None:
            raise AuditError(
                "MALFORMED_HEADER",
                f"{warc_type} records require WARC-Payload-Digest",
                index,
            )
        if warc_type in ("warcinfo", "request") and declared_payload_digest is not None:
            raise AuditError(
                "MALFORMED_HEADER",
                f"{warc_type} records must not carry WARC-Payload-Digest",
                index,
            )

        block_end = pos + length
        if block_end > len(data):
            raise AuditError(
                "LENGTH_MISMATCH",
                f"Content-Length declares {length} bytes but only "
                f"{len(data) - pos} remain",
                index,
            )
        block = data[pos:block_end]
        if not data.startswith(RECORD_TERMINATOR, block_end):
            raise AuditError(
                "MALFORMED_BOUNDARY",
                "record block must be followed by CRLF CRLF",
                index,
            )
        pos = block_end + len(RECORD_TERMINATOR)

        actual_block_digest = _sha256_hex(block)
        if actual_block_digest != declared_block_digest:
            raise AuditError(
                "DIGEST_MISMATCH",
                "WARC-Block-Digest does not match the declared block bytes",
                index,
            )

        computed_payload: str | None = None
        if warc_type == "response":
            entity = _http_entity_body(block, index)
            computed_payload = _sha256_hex(entity)
            if computed_payload != declared_payload_digest:
                raise AuditError(
                    "DIGEST_MISMATCH",
                    "WARC-Payload-Digest does not match the HTTP entity body",
                    index,
                )

        if warc_type == "revisit":
            refers = headers.get("warc-refers-to")
            if not refers:
                raise AuditError(
                    "MALFORMED_HEADER",
                    "revisit records require WARC-Refers-To",
                    index,
                )
            if not _ANGLE_URI_RE.match(refers):
                raise AuditError(
                    "MALFORMED_HEADER",
                    "WARC-Refers-To must be an angle-bracket enclosed URI",
                    index,
                )
            target = known.get(refers)
            if target is None:
                raise AuditError(
                    "REFERENCE_INVALID",
                    "WARC-Refers-To does not resolve to an earlier record",
                    index,
                )
            target_type, target_payload = target
            if target_type != "response":
                raise AuditError(
                    "REFERENCE_INVALID",
                    "WARC-Refers-To must point to a response record",
                    index,
                )
            if target_payload != declared_payload_digest:
                raise AuditError(
                    "REFERENCE_INVALID",
                    "revisit payload digest differs from the referenced response",
                    index,
                )

        rec_id = headers["warc-record-id"]
        if rec_id in known:
            raise AuditError(
                "MALFORMED_HEADER", "duplicate WARC-Record-ID in archive", index
            )
        known[rec_id] = (warc_type, computed_payload)
        records.append(
            RecordReport(
                index=index,
                warc_type=warc_type,
                block_length=length,
                block_digest=declared_block_digest,
                payload_digest=declared_payload_digest,
            )
        )

    if not records:
        raise AuditError("EMPTY_ARCHIVE", "no WARC records found", None)
    return records
