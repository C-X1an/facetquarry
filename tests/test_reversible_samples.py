"""Small, adversarial draft controls; execution requires the root evidence lease."""
import copy
import hashlib
import json
import struct
import unittest
import zlib

import reversible_samples as subject


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def gzip_fixture(raw, *, name=b"cell.samples.jsonl", mtime=123456789, sync=True):
    header = b"\x1f\x8b\x08\x08" + struct.pack("<I", mtime) + b"\x02\xff" + name + b"\x00"
    codec = zlib.compressobj(9, zlib.DEFLATED, -15)
    payload = codec.compress(raw)
    if sync:
        payload += codec.flush(zlib.Z_SYNC_FLUSH)
    payload += codec.flush(zlib.Z_FINISH)
    return header + payload + struct.pack("<II", zlib.crc32(raw), len(raw))


class ReversibleSamplesTests(unittest.TestCase):
    def setUp(self):
        self.source = "a" * 64
        self.rows = [
            {"query": 0, "repetition": 0, "nanoseconds": 4, "response": None},
            {"query": 1, "repetition": 0, "nanoseconds": 7, "response": {"hits": [], "distance_evaluations": 0}},
        ]
        self.raw = (json.dumps(self.rows[0]) + "\r\n" + json.dumps({"summary": True}) + "\n" + json.dumps(self.rows[1]) + "\n").encode()
        overlays = [None, 0.625]
        self.canonical = b"".join((json.dumps({**row, "recall_at_k": recall}, separators=(",", ":")) + "\n").encode() for row, recall in zip(self.rows, overlays))
        self.original = gzip_fixture(self.canonical)
        self.stdout = gzip_fixture(self.raw, name=b"stdout.txt")

    def propose(self, **changes):
        args = dict(original_samples_gzip=self.original, stdout_gzip=self.stdout,
                    expected_samples_sha256=digest(self.original),
                    expected_stdout_gzip_sha256=digest(self.stdout),
                    expected_stdout_raw_sha256=digest(self.raw), expected_stdout_raw_bytes=len(self.raw),
                    source_id=self.source, attempt_status="PASS")
        args.update(changes)
        return subject.propose(**args)

    def reconstruct(self, recipe, **changes):
        args = dict(recipe=recipe, stdout_gzip=self.stdout,
                    expected_samples_sha256=digest(self.original), expected_samples_bytes=len(self.original),
                    expected_stdout_gzip_sha256=digest(self.stdout),
                    expected_stdout_raw_sha256=digest(self.raw), expected_stdout_raw_bytes=len(self.raw),
                    expected_source_id=self.source)
        args.update(changes)
        return subject.reconstruct(**args)

    def test_round_trip_keeps_literal_overlays_header_and_summary_omission(self):
        proposal = self.propose()
        self.assertEqual(proposal.mode, "derived")
        self.assertIs(proposal.original_samples_gzip, self.original)
        recipe = json.loads(proposal.recipe)
        self.assertEqual(recipe["rows"], [[0, "null"], [2, "0.625"]])
        self.assertEqual(recipe["gzip"]["mtime"], 123456789)
        self.assertEqual(bytes.fromhex(recipe["gzip"]["fname_hex"]), b"cell.samples.jsonl")
        self.assertEqual(self.reconstruct(proposal.recipe), self.original)

    def test_plain_finish_and_crlf_canonical(self):
        raw = self.canonical.replace(b"\n", b"\r\n")
        original = gzip_fixture(raw, sync=False)
        proposal = self.propose(original_samples_gzip=original, expected_samples_sha256=digest(original))
        self.assertEqual(proposal.mode, "derived")
        self.assertEqual(self.reconstruct(proposal.recipe, expected_samples_sha256=digest(original), expected_samples_bytes=len(original)), original)

    def test_failed_partial_stdout_is_identity(self):
        proposal = self.propose(attempt_status="FAIL")
        self.assertEqual(proposal.mode, "identity")
        self.assertIs(proposal.original_samples_gzip, self.original)
        self.assertIsNone(proposal.recipe)

    def test_wrong_non_equivalent_or_malformed_line_is_identity(self):
        for raw in [self.raw.replace(b'"nanoseconds": 4', b'"nanoseconds": 5'), self.raw + b"not-json\n", self.raw + b"[]\n", self.raw + b"\n"]:
            with self.subTest(raw=raw):
                stdout = gzip_fixture(raw)
                proposal = self.propose(stdout_gzip=stdout, expected_stdout_gzip_sha256=digest(stdout), expected_stdout_raw_sha256=digest(raw), expected_stdout_raw_bytes=len(raw))
                self.assertEqual(proposal.mode, "identity")
                self.assertIs(proposal.original_samples_gzip, self.original)

    def test_invalid_utf8_replacement_and_unicode_splitlines(self):
        row = {**self.rows[0], "error": "\ufffd"}
        raw = json.dumps(row, ensure_ascii=False).encode().replace(b"\xef\xbf\xbd", b"\xff") + b"\xe2\x80\xa8" + b'{"summary":true}\n'
        canonical = (json.dumps({**row, "recall_at_k": None}, separators=(",", ":")) + "\n").encode()
        original, stdout = gzip_fixture(canonical), gzip_fixture(raw)
        proposal = self.propose(original_samples_gzip=original, expected_samples_sha256=digest(original), stdout_gzip=stdout, expected_stdout_gzip_sha256=digest(stdout), expected_stdout_raw_sha256=digest(raw), expected_stdout_raw_bytes=len(raw))
        self.assertEqual(proposal.mode, "derived")
        self.assertEqual(self.reconstruct(proposal.recipe, stdout_gzip=stdout, expected_samples_sha256=digest(original), expected_samples_bytes=len(original), expected_stdout_gzip_sha256=digest(stdout), expected_stdout_raw_sha256=digest(raw), expected_stdout_raw_bytes=len(raw)), original)

    def test_corruption_truncation_and_hash_size_mismatch_refuse(self):
        corrupt = self.stdout[:-1] + bytes([self.stdout[-1] ^ 1])
        for changes in [dict(stdout_gzip=corrupt, expected_stdout_gzip_sha256=digest(corrupt)), dict(stdout_gzip=self.stdout[:-4], expected_stdout_gzip_sha256=digest(self.stdout[:-4])), dict(expected_samples_sha256="b" * 64), dict(expected_stdout_raw_sha256="b" * 64), dict(expected_stdout_raw_bytes=len(self.raw) + 1), dict(source_id="bad")]:
            with self.subTest(changes=changes):
                proposal = self.propose(**changes)
                self.assertEqual(proposal.mode, "refused")
                self.assertIs(proposal.original_samples_gzip, self.original)

    def test_concatenated_members_are_identity(self):
        stdout = self.stdout + gzip_fixture(b"")
        proposal = self.propose(stdout_gzip=stdout, expected_stdout_gzip_sha256=digest(stdout))
        self.assertEqual(proposal.mode, "identity")

    def test_literal_overlay_refusal(self):
        for literal in [b"NaN", b"1", b'"null"', b"[]", b"true"]:
            original = gzip_fixture(self.canonical.replace(b'"recall_at_k":null', b'"recall_at_k":' + literal))
            proposal = self.propose(original_samples_gzip=original, expected_samples_sha256=digest(original))
            self.assertEqual(proposal.mode, "identity")

    def test_recipe_tampering_order_duplicates_paths_and_environment_refuse(self):
        proposal = self.propose()
        self.assertEqual(proposal.mode, "derived")
        base = json.loads(proposal.recipe)
        mutations = []
        for rows in [[[2, "0.625"], [0, "null"]], [[0, "null"], [0, "null"]], [[0, "null"], [100, "0.625"]], [[True, "null"], [2, "0.625"]], [[0, "0.5"], [2, "0.625"]]]:
            changed = copy.deepcopy(base); changed["rows"] = rows; mutations.append(changed)
        for key, value in [("source_id", "b" * 64), ("original_sha256", "b" * 64), ("version", 999), ("command", "anything")]:
            changed = copy.deepcopy(base); changed[key] = value; mutations.append(changed)
        changed = copy.deepcopy(base); changed["codec"]["zlib_runtime"] = "unknown"; mutations.append(changed)
        changed = copy.deepcopy(base); changed["gzip"]["mtime"] = 0; mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed):
                with self.assertRaises(subject.Refusal):
                    self.reconstruct(json.dumps(changed).encode())

    def test_caps_and_exact_decoded_edge(self):
        for raw in [b"x" * subject.MAX_DECODED_BYTES, b"x" * (subject.MAX_DECODED_BYTES + 1)]:
            stdout = gzip_fixture(raw)
            proposal = self.propose(stdout_gzip=stdout, expected_stdout_gzip_sha256=digest(stdout), expected_stdout_raw_sha256=digest(raw), expected_stdout_raw_bytes=len(raw))
            self.assertEqual(proposal.mode, "identity" if len(raw) == subject.MAX_DECODED_BYTES else "refused")
        proposal = self.propose(stdout_gzip=b"x" * (subject.MAX_COMPRESSED_BYTES + 1))
        self.assertEqual(proposal.mode, "refused")
        with self.assertRaises(subject.Refusal):
            self.reconstruct(b"x" * (subject.MAX_RECIPE_BYTES + 1))


if __name__ == "__main__":
    unittest.main()
