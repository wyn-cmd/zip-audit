# Tests for zip_audit.core and the command line wrapper.
# Every archive used here is built inside the test, so nothing external is needed.

import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zip_audit.cli import main
from zip_audit.core import ArchiveError, Limits, audit


class ArchiveCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="zip-audit-test-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def path_for(self, name):
        return os.path.join(self.dir, name)

    def codes(self, report):
        return sorted(set(f.code for f in report.findings))

    # OR extra bits into the general purpose flag field of the local header and
    # the central directory record, which is where zipfile reports them from.
    def set_flag_bits(self, path, bits):
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        local = data.find(b"PK\x03\x04")
        if local >= 0:
            current = struct.unpack_from("<H", data, local + 6)[0]
            struct.pack_into("<H", data, local + 6, current | bits)
        central = data.find(b"PK\x01\x02")
        if central >= 0:
            current = struct.unpack_from("<H", data, central + 8)[0]
            struct.pack_into("<H", data, central + 8, current | bits)
        with open(path, "wb") as handle:
            handle.write(bytes(data))

    # Build an archive from a list of (name, payload) pairs.
    def make_zip(self, filename, items, compression=zipfile.ZIP_DEFLATED):
        target = self.path_for(filename)
        with zipfile.ZipFile(target, "w", compression) as handle:
            for name, payload in items:
                handle.writestr(name, payload)
        return target


class NameChecks(ArchiveCase):
    def test_plain_archive_is_clean(self):
        target = self.make_zip("plain.zip", [("notes.txt", "hello"), ("src/app.py", "print(1)")])
        report = audit(target)
        self.assertTrue(report.clean)
        self.assertEqual(report.entries, 2)
        self.assertIsNone(report.worst)

    def test_parent_directory_entry_is_high(self):
        target = self.make_zip("trav.zip", [("../evil.txt", "x")])
        report = audit(target)
        self.assertIn("path-traversal", self.codes(report))
        self.assertEqual(report.worst, "high")

    def test_nested_traversal_is_caught(self):
        target = self.make_zip("trav2.zip", [("a/b/../../../evil.txt", "x")])
        self.assertIn("path-traversal", self.codes(audit(target)))

    def test_absolute_path_is_high(self):
        target = self.make_zip("abs.zip", [("/etc/cron.d/job", "x")])
        report = audit(target)
        self.assertIn("absolute-path", self.codes(report))
        self.assertEqual(report.worst, "high")

    def test_windows_drive_letter_and_backslash(self):
        target = self.make_zip("win.zip", [("C:\\Windows\\Temp\\x.txt", "x")])
        codes = self.codes(audit(target))
        self.assertIn("absolute-path", codes)
        self.assertIn("backslash-separator", codes)

    def test_duplicate_name_is_medium(self):
        target = self.path_for("dup.zip")
        with zipfile.ZipFile(target, "w") as handle:
            # zipfile warns about the duplicate we are deliberately creating.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                handle.writestr("same.txt", "first")
                handle.writestr("same.txt", "second")
        report = audit(target)
        self.assertIn("duplicate-entry", self.codes(report))
        self.assertEqual(report.counts["medium"], 1)

    def test_case_collision_is_medium(self):
        target = self.make_zip("case.zip", [("Readme.md", "a"), ("README.md", "b")])
        self.assertIn("case-collision", self.codes(audit(target)))

    def test_same_name_different_case_only_collides_once(self):
        target = self.make_zip("case2.zip", [("A.txt", "a"), ("a.txt", "b"), ("B.txt", "c")])
        report = audit(target)
        collisions = [f for f in report.findings if f.code == "case-collision"]
        self.assertEqual(len(collisions), 1)


class MetadataChecks(ArchiveCase):
    def test_symlink_entry_is_high(self):
        target = self.path_for("link.zip")
        with zipfile.ZipFile(target, "w") as handle:
            info = zipfile.ZipInfo("passwd")
            # 0o120777 is a symbolic link with full permissions, stored in the
            # high half of external_attr exactly as Info-ZIP writes it.
            info.external_attr = (0o120777 << 16)
            handle.writestr(info, "/etc/passwd")
        report = audit(target)
        self.assertIn("symlink-entry", self.codes(report))
        self.assertEqual(report.worst, "high")

    def test_regular_file_with_mode_is_not_a_symlink(self):
        target = self.path_for("mode.zip")
        with zipfile.ZipFile(target, "w") as handle:
            info = zipfile.ZipInfo("script.sh")
            info.external_attr = (0o100755 << 16)
            handle.writestr(info, "#!/bin/sh\n")
        self.assertNotIn("symlink-entry", self.codes(audit(target)))

    def test_encrypted_flag_is_low(self):
        target = self.path_for("enc.zip")
        with zipfile.ZipFile(target, "w") as handle:
            handle.writestr("secret.txt", "hidden")
        # zipfile zeroes the general purpose flags when it writes an entry, so the
        # encryption bit has to be set afterwards to produce a realistic sample.
        self.set_flag_bits(target, 0x1)
        report = audit(target)
        self.assertIn("encrypted-entry", self.codes(report))
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.worst, "low")


class BombChecks(ArchiveCase):
    def test_high_expansion_ratio_is_high(self):
        payload = b"\0" * (4 * 1024 * 1024)
        target = self.make_zip("bomb.zip", [("zeros.bin", payload)])
        report = audit(target)
        self.assertIn("compression-ratio", self.codes(report))
        self.assertEqual(report.counts["high"], 1)

    def test_ratio_limit_is_respected(self):
        payload = b"\0" * (4 * 1024 * 1024)
        target = self.make_zip("bomb2.zip", [("zeros.bin", payload)])
        report = audit(target, Limits(max_ratio=100000.0))
        self.assertNotIn("compression-ratio", self.codes(report))
        report = audit(target, Limits(max_ratio=10.0))
        self.assertIn("compression-ratio", self.codes(report))

    def test_stored_entries_are_not_ratio_flagged(self):
        payload = b"\0" * (2 * 1024 * 1024)
        target = self.make_zip("stored.zip", [("zeros.bin", payload)], compression=zipfile.ZIP_STORED)
        self.assertNotIn("compression-ratio", self.codes(audit(target)))

    def test_total_expanded_size_limit(self):
        target = self.make_zip("total.zip", [("a.bin", b"x" * 5000)], compression=zipfile.ZIP_STORED)
        report = audit(target, Limits(max_uncompressed_bytes=1000))
        self.assertIn("total-size", self.codes(report))

    def test_entry_count_limit(self):
        items = [("f" + str(i) + ".txt", "x") for i in range(4)]
        target = self.make_zip("many.zip", items)
        report = audit(target, Limits(max_entries=2))
        self.assertIn("entry-count", self.codes(report))
        self.assertNotIn("entry-count", self.codes(audit(target)))


class ErrorHandling(ArchiveCase):
    def test_non_zip_input_raises_archive_error(self):
        broken = self.path_for("broken.zip")
        with open(broken, "wb") as handle:
            handle.write(b"this is plain text, not an archive")
        with self.assertRaises(ArchiveError):
            audit(broken)

    def test_missing_file_raises_archive_error(self):
        with self.assertRaises(ArchiveError):
            audit(self.path_for("does-not-exist.zip"))


class CommandLine(ArchiveCase):
    def test_clean_archive_exits_zero(self):
        target = self.make_zip("ok.zip", [("a.txt", "a")])
        self.assertEqual(main([target]), 0)

    def test_findings_exit_one(self):
        target = self.make_zip("bad.zip", [("../x.txt", "a")])
        self.assertEqual(main([target]), 1)

    def test_unreadable_file_exits_two(self):
        broken = self.path_for("nope.zip")
        with open(broken, "wb") as handle:
            handle.write(b"nope")
        self.assertEqual(main([broken]), 2)

    def test_json_output_is_parseable(self):
        target = self.make_zip("j.zip", [("../x.txt", "a"), ("ok.txt", "b")])
        buffer = io.StringIO()
        saved = sys.stdout
        sys.stdout = buffer
        try:
            status = main([target, "--json"])
        finally:
            sys.stdout = saved
        self.assertEqual(status, 1)
        data = json.loads(buffer.getvalue())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["worst"], "high")
        self.assertIn("path-traversal", [f["code"] for f in data[0]["findings"]])

    def test_quiet_hides_clean_archives(self):
        good = self.make_zip("good.zip", [("a.txt", "a")])
        bad = self.make_zip("evil.zip", [("../x.txt", "a")])
        buffer = io.StringIO()
        saved = sys.stdout
        sys.stdout = buffer
        try:
            status = main([good, bad, "--quiet"])
        finally:
            sys.stdout = saved
        text = buffer.getvalue()
        self.assertEqual(status, 1)
        self.assertIn("evil.zip", text)
        self.assertNotIn("good.zip", text)


if __name__ == "__main__":
    unittest.main()
