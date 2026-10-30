"""Alpine version ordering examples from the apk-tools version contract."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from alpine_version import AlpineVersion


class AlpineVersionTests(unittest.TestCase):
    def test_native_ordering(self):
        for before, after in (
            ("1.09", "1.1"),
            ("1.0a", "1.0b"),
            ("1.0_alpha", "1.0_beta"),
            ("1.0_beta", "1.0_pre"),
            ("1.0_pre", "1.0_rc"),
            ("1.0_rc", "1.0"),
            ("1.0", "1.0_cvs"),
            ("1.0_cvs", "1.0_svn"),
            ("1.0_svn", "1.0_git"),
            ("1.0_git", "1.0_hg"),
            ("1.0_hg", "1.0_p"),
            ("1.0_alpha", "1.0_alpha0"),
            ("1.0~abc", "1.0~abd"),
            ("1.0-r1", "1.0-r2"),
        ):
            with self.subTest(before=before, after=after):
                self.assertLess(AlpineVersion(before), AlpineVersion(after))
        self.assertEqual(AlpineVersion("01"), AlpineVersion("1"))

    def test_invalid_versions_are_rejected(self):
        for version in ("1.0_unknown", "1.0bb", "1~ABC", "1.0-r1junk", "1.0-r"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                AlpineVersion(version)
