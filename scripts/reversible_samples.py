"""Bounded, reversible *measurement draft*, with no I/O or qualification claims.

The caller retains every original file and supplies trusted original hashes. A
successful proposal is only a byte-equivalence recipe; it says nothing about
recall correctness, coverage, source qualification, or measurement validity.
Unsupported inputs retain the original by identity. Malformed or oversized
inputs refuse derivation and likewise retain the original. No API deletes data.
"""
from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import math
import re
import struct
import sys
import zlib

MAX_COMPRESSED_BYTES = 1 << 20
MAX_DECODED_BYTES = 8 << 20
MAX_RECIPE_BYTES = 1 << 20
MAX_HEADER_BYTES = 1 << 16
MAX_LINES = 65536
MAX_JSON_DEPTH = 32
MAX_JSON_STRUCTURAL_TOKENS = 32768
VERSION = 1
SEMANTICS = "benchmark.measurement:utf8-replace:str.splitlines:json-compact:v1"
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(ValueError):
    """Malformed/untrusted/bounded input: retain all originals; do not derive."""


class _Unsupported(ValueError):
    """Valid but not handled/equivalent: retain the canonical original."""


@dataclass(frozen=True)
class Proposal:
    mode: str
    reason: str
    original_samples_gzip: bytes
    recipe: bytes | None = None


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash(value, label):
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise Refusal(label + ": invalid SHA-256")
    return value


def _integer(value, maximum, label):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Refusal(label + ": invalid bounded integer")
    return value


def _bytes(value, maximum, label):
    if type(value) is not bytes or len(value) > maximum:
        raise Refusal(label + ": bytes required within bound")
    return value


def _keys(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise Refusal(label + ": unknown/missing fields")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _no_constant(value):
    raise ValueError("nonfinite JSON constant")


def _loads(raw, *, strict=False):
    # The benchmark uses normal json.loads, including last-key-wins ordering.
    # Strict duplicate rejection applies only to the recipe, never stdout.
    try:
        if type(raw) is bytes:
            raw = raw.decode("utf-8")
        if type(raw) is not str or len(raw) > MAX_DECODED_BYTES:
            raise Refusal("JSON byte/type bound")
        depth, tokens, quoted, escaped = 0, 0, False, False
        for character in raw:
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
                tokens += 1
            elif character in "[{":
                depth += 1
                tokens += 1
            elif character in "]}":
                depth -= 1
                tokens += 1
            elif character in ",:":
                tokens += 1
            if depth > MAX_JSON_DEPTH or tokens > MAX_JSON_STRUCTURAL_TOKENS:
                raise Refusal("JSON structural bound exceeded")
        return json.loads(raw, parse_constant=_no_constant,
                          **({"object_pairs_hook": _no_duplicates} if strict else {}))
    except Refusal:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise Refusal("invalid bounded JSON") from error


def _dumps(value):
    try:
        return json.dumps(value, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise Refusal("unserializable bounded JSON") from error


def _inflate(compressed):
    _bytes(compressed, MAX_COMPRESSED_BYTES, "gzip input")
    try:
        decoder = zlib.decompressobj(31)
        decoded = decoder.decompress(compressed, MAX_DECODED_BYTES + 1)
    except zlib.error as error:
        raise Refusal("malformed gzip") from error
    if len(decoded) > MAX_DECODED_BYTES or decoder.unconsumed_tail:
        raise Refusal("gzip decoded-size bound exceeded")
    if not decoder.eof:
        raise Refusal("truncated gzip")
    if decoder.unused_data:
        # Concatenation, padding, and trailing bytes are never silently omitted.
        raise _Unsupported("multiple gzip members or trailing bytes")
    return decoded


def _header(compressed):
    if len(compressed) < 18 or compressed[:3] != b"\x1f\x8b\x08":
        raise Refusal("invalid gzip header")
    flags = compressed[3]
    if flags & ~8:
        raise _Unsupported("gzip flags outside supported zero/FNAME subset")
    end, name = 10, b""
    if flags & 8:
        terminator = compressed.find(b"\x00", end, min(len(compressed) - 8, MAX_HEADER_BYTES))
        if terminator < 0:
            raise _Unsupported("gzip FNAME absent or beyond header bound")
        name, end = compressed[end:terminator], terminator + 1
    if end > MAX_HEADER_BYTES or end > len(compressed) - 8:
        raise Refusal("invalid bounded gzip header")
    return {"header_hex": compressed[:end].hex(), "trailer_hex": compressed[-8:].hex(),
            "mtime": struct.unpack_from("<I", compressed, 4)[0], "fname_hex": name.hex()}


def _stdout_rows(raw):
    # This is exactly the decoding/split behavior in benchmark_support and
    # benchmark.measurement. It deliberately does not validate truth or recall.
    lines = raw.decode("utf-8", errors="replace").splitlines()
    if len(lines) > MAX_LINES:
        raise _Unsupported("stdout line-count subset exceeded")
    rows, summary_count = [], 0
    for position, line in enumerate(lines):
        try:
            item = _loads(line)
        except Refusal as error:
            raise _Unsupported("malformed stdout line; retain original") from error
        if type(item) is not dict:
            raise _Unsupported("non-object stdout line")
        if item.get("summary") is True:
            summary_count += 1
        else:
            rows.append((position, item))
    if summary_count != 1:
        raise _Unsupported("exactly one native summary required by this subset")
    return rows


def _overlay(literal):
    if not isinstance(literal, str) or len(literal) > 64:
        raise Refusal("invalid recall literal")
    value = _loads(literal)
    if value is not None and (type(value) is not float or not math.isfinite(value) or not 0 <= value <= 1):
        raise _Unsupported("recall overlay outside null/finite-float subset")
    if _dumps(value) != literal:
        raise _Unsupported("recall literal is not canonical benchmark serialization")
    return value


def _canonical_rows(decoded):
    try:
        text = decoded.decode("utf-8")
    except UnicodeError as error:
        raise Refusal("canonical samples are not UTF-8") from error
    # TextIOWrapper writes LF on POSIX and CRLF on Windows; preserve one style.
    newline = "\r\n" if "\r\n" in text else "\n"
    if not text:
        return [], newline
    lines = text.splitlines(keepends=True)
    if len(lines) > MAX_LINES:
        raise _Unsupported("canonical line-count subset exceeded")
    rows = []
    for line in lines:
        if not line.endswith(newline):
            raise _Unsupported("noncanonical sample newline")
        body = line[:-len(newline)]
        try:
            item = _loads(body)
        except Refusal as error:
            # These authenticated original bytes remain opaque identity data.
            # They are never accepted as valid scientific samples or recipes.
            raise _Unsupported("canonical JSON outside derivable subset; retain original") from error
        if type(item) is not dict or "recall_at_k" not in item or item.get("summary") is True:
            raise _Unsupported("canonical sample lacks supported overlay")
        if _dumps(item) != body:
            raise _Unsupported("noncanonical JSON sample serialization")
        literal = _dumps(item["recall_at_k"])
        _overlay(literal)
        rows.append((body, literal))
    return rows, newline


def _render(rows, stdout_rows, newline):
    if type(rows) is not list or len(rows) > MAX_LINES or len(rows) != len(stdout_rows):
        raise Refusal("recipe row coverage differs from retained stdout")
    output = bytearray()
    for entry, (actual_position, item) in zip(rows, stdout_rows):
        if type(entry) is not list or len(entry) != 2 or type(entry[0]) is not int or entry[0] != actual_position:
            raise Refusal("recipe offsets must cover native samples once in original order")
        updated = dict(item)
        updated["recall_at_k"] = _overlay(entry[1])
        serialized = (_dumps(updated) + newline).encode("utf-8")
        if len(output) + len(serialized) > MAX_DECODED_BYTES:
            raise Refusal("reconstructed sample decoded-size bound exceeded")
        output.extend(serialized)
    return bytes(output)


def _codec(level, flush, segmentation="fixed64k"):
    return {"name": "stdlib-zlib-raw-deflate", "level": level, "mem_level": zlib.DEF_MEM_LEVEL,
            "strategy": zlib.Z_DEFAULT_STRATEGY, "flush": flush,
            "segmentation": segmentation,
            "zlib_compile": zlib.ZLIB_VERSION, "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION,
            "python": list(sys.version_info[:3])}


def _compress(raw, header, trailer, codec):
    _keys(codec, _codec(9, "finish"), "codec")
    level = _integer(codec["level"], 9, "compression level")
    flush = codec["flush"]
    segmentation = codec["segmentation"]
    if ((segmentation == "fixed64k" and flush not in {"finish", "sync-then-finish"})
            or (segmentation == "benchmark-text" and flush != "text-wrapper-close")
            or segmentation not in {"fixed64k", "benchmark-text"}):
        raise Refusal("unsupported codec segmentation/flush")
    expected = _codec(level, flush, segmentation)
    if (any(type(codec[key]) is not type(value) or codec[key] != value for key, value in expected.items())
            or any(type(value) is not int for value in codec["python"])):
        raise Refusal("unsupported codec/version/environment")
    if segmentation == "benchmark-text":
        class BoundedBuffer(io.BytesIO):
            def write(self, value):
                if self.tell() + len(value) > MAX_COMPRESSED_BYTES:
                    raise _Unsupported("text reconstruction compressed-size bound exceeded")
                return super().write(value)
        buffer = BoundedBuffer()
        newline = "\r\n" if b"\r\n" in raw else "\n"
        # Reproduce the actual gzip.open(...,'wt') write and close behavior.
        # Stored-deflate block boundaries can depend on TextIOWrapper writes.
        with gzip.GzipFile(fileobj=buffer, filename="", mode="wb", mtime=0, compresslevel=level) as binary:
            with io.TextIOWrapper(binary, encoding="utf-8", newline=newline) as text:
                for line in raw.decode("utf-8").splitlines():
                    text.write(line + "\n")
        packed = buffer.getvalue()
        if packed[:4] != b"\x1f\x8b\x08\x00" or packed[-8:] != trailer:
            raise Refusal("text reconstruction gzip envelope mismatch")
        if len(header) + len(packed) - 18 + len(trailer) > MAX_COMPRESSED_BYTES:
            raise _Unsupported("text reconstruction original-size bound exceeded")
        return header + packed[10:-8] + trailer
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15, zlib.DEF_MEM_LEVEL, zlib.Z_DEFAULT_STRATEGY)
    parts, size = [header], len(header) + len(trailer)
    for start in range(0, len(raw), 65536):
        part = compressor.compress(raw[start:start + 65536])
        size += len(part)
        if size > MAX_COMPRESSED_BYTES:
            raise _Unsupported("reconstruction compressed-size bound exceeded")
        parts.append(part)
    if flush == "sync-then-finish":
        part = compressor.flush(zlib.Z_SYNC_FLUSH)
        size += len(part); parts.append(part)
    part = compressor.flush(zlib.Z_FINISH)
    size += len(part); parts.extend((part, trailer))
    if size > MAX_COMPRESSED_BYTES:
        raise _Unsupported("reconstruction compressed-size bound exceeded")
    return b"".join(parts)


def _checked_stdout(stdout_gzip, compressed_hash, raw_hash, raw_size):
    _bytes(stdout_gzip, MAX_COMPRESSED_BYTES, "stdout gzip")
    _hash(compressed_hash, "stdout gzip hash"); _hash(raw_hash, "stdout raw hash")
    _integer(raw_size, MAX_DECODED_BYTES, "stdout raw size")
    if _digest(stdout_gzip) != compressed_hash:
        raise Refusal("stdout gzip hash mismatch")
    raw = _inflate(stdout_gzip)
    if len(raw) != raw_size or _digest(raw) != raw_hash:
        raise Refusal("stdout original raw hash/size mismatch")
    return raw


def propose(*, original_samples_gzip, stdout_gzip, expected_samples_sha256,
            expected_stdout_gzip_sha256, expected_stdout_raw_sha256,
            expected_stdout_raw_bytes, source_id, attempt_status):
    """Return a reviewed-in-isolation proposal; originals always remain retained.

    Trusted hashes must originate in the original summary/attempt metadata, not
    from a recipe or from a newly recomputed replacement record. Only PASS
    attempts enter this deliberately conservative reversible subset.
    """
    try:
        _bytes(original_samples_gzip, MAX_COMPRESSED_BYTES, "canonical gzip")
        _hash(expected_samples_sha256, "canonical original hash"); _hash(source_id, "source")
        if _digest(original_samples_gzip) != expected_samples_sha256:
            raise Refusal("canonical original hash mismatch")
        decoded = _inflate(original_samples_gzip)
        raw = _checked_stdout(stdout_gzip, expected_stdout_gzip_sha256,
                              expected_stdout_raw_sha256, expected_stdout_raw_bytes)
        if attempt_status not in {"PASS", "FAIL"}:
            raise Refusal("invalid original attempt status")
        if attempt_status != "PASS":
            raise _Unsupported("failed attempt: retain canonical original and every raw stream")
        metadata = _header(original_samples_gzip)
        canonical_rows, newline = _canonical_rows(decoded)
        native_rows = _stdout_rows(raw)
        if len(canonical_rows) != len(native_rows):
            raise _Unsupported("canonical/native sample coverage differs")
        rows = [[position, literal] for (_, literal), (position, _) in zip(canonical_rows, native_rows)]
        if _render(rows, native_rows, newline) != decoded:
            raise _Unsupported("native samples plus literal overlays are not byte-equivalent")
        header = bytes.fromhex(metadata["header_hex"])
        trailer = bytes.fromhex(metadata["trailer_hex"])
        for level in (9, 6, 1, 0, 2, 3, 4, 5, 7, 8):
            for codec in (_codec(level, "sync-then-finish"), _codec(level, "finish"),
                          _codec(level, "text-wrapper-close", "benchmark-text")):
                try:
                    candidate = _compress(decoded, header, trailer, codec)
                except _Unsupported:
                    continue
                if candidate != original_samples_gzip:
                    continue
                recipe = _dumps({"version": VERSION, "semantics": SEMANTICS, "source_id": source_id,
                                 "original_sha256": expected_samples_sha256, "original_bytes": len(original_samples_gzip),
                                 "stdout_gzip_sha256": expected_stdout_gzip_sha256,
                                 "stdout_raw_sha256": expected_stdout_raw_sha256, "stdout_raw_bytes": expected_stdout_raw_bytes,
                                 "decoded_sha256": _digest(decoded), "decoded_bytes": len(decoded),
                                 "newline": newline, "rows": rows, "gzip": metadata, "codec": codec}).encode()
                if len(recipe) > MAX_RECIPE_BYTES:
                    raise _Unsupported("recipe-size subset exceeded")
                restored = reconstruct(recipe=recipe, stdout_gzip=stdout_gzip,
                                       expected_samples_sha256=expected_samples_sha256, expected_samples_bytes=len(original_samples_gzip),
                                       expected_stdout_gzip_sha256=expected_stdout_gzip_sha256,
                                       expected_stdout_raw_sha256=expected_stdout_raw_sha256,
                                       expected_stdout_raw_bytes=expected_stdout_raw_bytes, expected_source_id=source_id)
                if restored != original_samples_gzip:
                    raise Refusal("byte-exact reconstruction self-check failed")
                return Proposal("derived", "byte-exact reconstruction verified; originals retained", original_samples_gzip, recipe)
        raise _Unsupported("original deflate stream not reproducible by supported codecs")
    except _Unsupported as error:
        return Proposal("identity", str(error), original_samples_gzip)
    except (Refusal, ValueError, TypeError, OverflowError, RecursionError) as error:
        return Proposal("refused", str(error), original_samples_gzip)


def reconstruct(*, recipe, stdout_gzip, expected_samples_sha256, expected_samples_bytes,
                expected_stdout_gzip_sha256, expected_stdout_raw_sha256,
                expected_stdout_raw_bytes, expected_source_id):
    """Reconstruct only against independently supplied original hash/size bindings.

    Recipes contain data, never paths/commands/code. A changed recipe, stdout,
    source binding or codec environment must still reproduce the trusted
    original compressed hash and size; otherwise no reconstructed data returns.
    """
    try:
        _bytes(recipe, MAX_RECIPE_BYTES, "recipe")
        _hash(expected_samples_sha256, "canonical original hash"); _hash(expected_source_id, "source")
        _integer(expected_samples_bytes, MAX_COMPRESSED_BYTES, "canonical original size")
        data = _loads(recipe, strict=True)
        _keys(data, ("version", "semantics", "source_id", "original_sha256", "original_bytes",
                     "stdout_gzip_sha256", "stdout_raw_sha256", "stdout_raw_bytes", "decoded_sha256",
                     "decoded_bytes", "newline", "rows", "gzip", "codec"), "recipe")
        bindings = {"version": VERSION, "semantics": SEMANTICS, "source_id": expected_source_id,
                    "original_sha256": expected_samples_sha256, "original_bytes": expected_samples_bytes,
                    "stdout_gzip_sha256": expected_stdout_gzip_sha256,
                    "stdout_raw_sha256": expected_stdout_raw_sha256, "stdout_raw_bytes": expected_stdout_raw_bytes}
        if any(type(data[key]) is not type(value) or data[key] != value for key, value in bindings.items()):
            raise Refusal("recipe differs from trusted original bindings")
        _hash(data["decoded_sha256"], "decoded hash")
        _integer(data["decoded_bytes"], MAX_DECODED_BYTES, "decoded size")
        if data["newline"] not in {"\n", "\r\n"}:
            raise Refusal("unsupported canonical newline")
        raw = _checked_stdout(stdout_gzip, expected_stdout_gzip_sha256,
                              expected_stdout_raw_sha256, expected_stdout_raw_bytes)
        decoded = _render(data["rows"], _stdout_rows(raw), data["newline"])
        if len(decoded) != data["decoded_bytes"] or _digest(decoded) != data["decoded_sha256"]:
            raise Refusal("reconstructed decoded hash/size mismatch")
        metadata = data["gzip"]
        _keys(metadata, ("header_hex", "trailer_hex", "mtime", "fname_hex"), "gzip metadata")
        if any(type(metadata[key]) is not str for key in ("header_hex", "trailer_hex", "fname_hex")):
            raise Refusal("invalid gzip metadata types")
        if len(metadata["header_hex"]) > 2 * MAX_HEADER_BYTES or len(metadata["trailer_hex"]) != 16:
            raise Refusal("gzip metadata size bound exceeded")
        header, trailer = bytes.fromhex(metadata["header_hex"]), bytes.fromhex(metadata["trailer_hex"])
        if metadata != _header(header + b"\x03\x00" + trailer) or type(metadata["mtime"]) is not int:
            raise Refusal("gzip metadata inconsistent with exact header")
        if trailer != struct.pack("<II", zlib.crc32(decoded), len(decoded)):
            raise Refusal("original gzip trailer differs from reconstructed samples")
        candidate = _compress(decoded, header, trailer, data["codec"])
        if len(candidate) != expected_samples_bytes or _digest(candidate) != expected_samples_sha256:
            raise Refusal("reconstructed original compressed hash/size mismatch")
        if _inflate(candidate) != decoded:
            raise Refusal("reconstructed gzip validation mismatch")
        return candidate
    except Refusal:
        raise
    except (_Unsupported, ValueError, TypeError, OverflowError, RecursionError, zlib.error) as error:
        raise Refusal("recipe reconstruction refused: " + str(error)) from error
