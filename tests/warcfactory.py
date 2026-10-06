"""Helpers for assembling well-formed (and deliberately broken) WARC files."""

from __future__ import annotations

import hashlib

CRLF = b"\r\n"


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def http_response(entity: bytes = b"hello world", *, chunked: bool = False) -> bytes:
    if chunked:
        head = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
        )
        chunk = b"%x\r\n%s\r\n" % (len(entity), entity)
        return head + chunk + b"0\r\n\r\n"
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        + b"Content-Length: %d\r\n\r\n" % len(entity)
        + entity
    )


def http_entity(response_block: bytes) -> bytes:
    """Mirror the entity body that the auditor hashes."""
    head_end = response_block.find(b"\r\n\r\n")
    body = response_block[head_end + 4 :]
    if b"Transfer-Encoding: chunked" in response_block.split(b"\r\n\r\n", 1)[0]:
        out = bytearray()
        pos = 0
        while True:
            eol = body.find(b"\r\n", pos)
            size = int(body[pos:eol].split(b";", 1)[0], 16)
            pos = eol + 2
            if size == 0:
                return bytes(out)
            out.extend(body[pos : pos + size])
            pos += size + 2
    return body


def make_record(
    rec_id: str,
    warc_type: str,
    block: bytes,
    *,
    target_uri: str | None = None,
    payload_digest: str | None = None,
    refers_to: str | None = None,
    profile: str | None = None,
    date: str = "2026-10-06T00:00:00Z",
    content_type: str | None = None,
    block_digest_override: str | None = None,
    payload_digest_override: str | None = None,
    extra_headers: tuple[tuple[str, str], ...] = (),
    omit_block_digest: bool = False,
    raw_block: bytes | None = None,
) -> bytes:
    if content_type is None:
        content_type = {
            "warcinfo": "application/warc-fields",
            "request": "application/http;msgtype=request",
            "response": "application/http;msgtype=response",
            "revisit": "application/http;msgtype=response",
        }[warc_type]

    lines = [
        ("WARC-Type", warc_type),
        ("WARC-Record-ID", f"<urn:uuid:{rec_id}>"),
        ("WARC-Date", date),
    ]
    if target_uri is not None:
        lines.append(("WARC-Target-URI", target_uri))
    if profile is not None or warc_type == "revisit":
        lines.append(
            (
                "WARC-Profile",
                profile
                or "http://netpreserve.org/warc/1.1/revisit/server-not-modified",
            )
        )
    if refers_to is not None:
        lines.append(("WARC-Refers-To", f"<urn:uuid:{refers_to}>"))
    lines.append(("Content-Type", content_type))
    lines.append(("Content-Length", str(len(block))))
    if not omit_block_digest:
        lines.append(
            ("WARC-Block-Digest", block_digest_override or sha256(block))
        )
    if payload_digest_override is not None:
        lines.append(("WARC-Payload-Digest", payload_digest_override))
    elif payload_digest is not None:
        lines.append(("WARC-Payload-Digest", payload_digest))
    lines.extend(extra_headers)

    head = b"WARC/1.1\r\n"
    for name, value in lines:
        head += f"{name}: {value}\r\n".encode("utf-8")
    head += b"\r\n"
    return head + (raw_block if raw_block is not None else block) + b"\r\n\r\n"


def warcinfo(rec_id: str = "0001", block: bytes | None = None) -> bytes:
    if block is None:
        block = b"software: warc-audit-test\r\nformat: WARC File Format 1.1\r\n"
    return make_record(rec_id, "warcinfo", block)


def request_record(rec_id: str = "0002", uri: str = "https://example.org/") -> bytes:
    block = (
        b"GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: audit-test\r\n\r\n"
    )
    return make_record(rec_id, "request", block, target_uri=uri)


def response_pair(
    rec_id: str = "0003",
    uri: str = "https://example.org/",
    *,
    entity: bytes = b"hello world",
    chunked: bool = False,
) -> tuple[bytes, bytes, bytes]:
    block = http_response(entity, chunked=chunked)
    payload = http_entity(block)
    rec = make_record(
        rec_id,
        "response",
        block,
        target_uri=uri,
        payload_digest=sha256(payload),
    )
    return rec, block, payload


def revisit_record(
    rec_id: str,
    refers_to: str,
    payload_digest: str,
    *,
    uri: str = "https://example.org/",
    payload_digest_override: str | None = None,
) -> bytes:
    block = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    return make_record(
        rec_id,
        "revisit",
        block,
        target_uri=uri,
        refers_to=refers_to,
        payload_digest=payload_digest,
        payload_digest_override=payload_digest_override,
    )
