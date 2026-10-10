"""Armed current PR refresh uses trusted-main validation and an exact head lease."""

import copy
import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
refresh = importlib.import_module("refresh_current_provenance")


class CurrentRefreshTests(unittest.TestCase):
    def setUp(self):
        self.main = self.remote_main = "1" * 40
        self.head = "2" * 40
        self.owned: dict = {"number": 55, "auto_merge": {}, "user": {"login": "bocklabs-release[bot]"},
            "base": {"ref": "main"}, "head": {"ref": "provenance/current/postgres-exporter",
            "sha": self.head, "repo": {"full_name": "bocklabs/trusted-images"}}}
        self.healthy = copy.deepcopy(self.owned)
        self.healthy["number"] = 56
        self.healthy["head"].update(ref="provenance/current/nginx-qualification", sha="4" * 40)
        self.pulls = [self.owned]
        self.latest = {55: copy.deepcopy(self.owned), 56: copy.deepcopy(self.healthy)}
        self.apps = {self.head: "postgres-exporter", "4" * 40: "nginx-qualification"}
        self.records = {app: json.loads((ROOT / f"provenance/{app}/current.json").read_bytes()) for app in self.apps.values()}
        self.candidates = copy.deepcopy(self.records)
        self.candidates["postgres-exporter"]["internal"]["tag"] = "v0.20.1-bocklabs.8"
        self.candidates["nginx-qualification"]["internal"]["tag"] = "1.31.6-bocklabs.2"
        for record in self.candidates.values():
            record["promoted_at"] = "2099-01-01T00:00:00Z"
        self.calls: list[tuple] = []
        self.enterContext(patch.object(refresh, "git", side_effect=self.git))
        self.enterContext(patch.object(refresh, "gh", side_effect=self.gh))
        self.commit = self.enterContext(patch.object(refresh, "merged_commit", return_value=self.main))
        self.enterContext(patch.object(refresh, "load_current", side_effect=lambda app, commit: self.records[app]))

    def git(self, *args):
        self.calls.append(("git", *args))
        if args[0] == "rev-parse":
            return self.main.encode()
        if args[0] == "ls-remote":
            self.assertEqual(args, ("ls-remote", "origin", "refs/heads/main"))
            return f"{self.remote_main}\trefs/heads/main\n".encode()
        if args[0] == "merge-base":
            return b"0" * 40
        if args[0] == "diff":
            app = self.apps[args[-1].split("...")[-1]]
            return f"provenance/{app}/current.json\n".encode()
        if args[0] == "log":
            return b"302587774+bocklabs-release[bot]@users.noreply.github.com\n"
        if args[0] == "show":
            app = args[1].split("/", 2)[1]
            return json.dumps(self.candidates[app]).encode()
        self.assertEqual(args[0], "fetch")
        return b""

    def gh(self, *args):
        self.calls.append(("gh", *args))
        if "--slurp" in args:
            return json.dumps([self.pulls])
        if "PUT" in args:
            return json.dumps({"message": "update requested"})
        number = int(args[-1].rsplit("/", 1)[1])
        return json.dumps(self.latest[number])

    def test_owned_armed_current_only_with_exact_head_lease(self):
        legacy = copy.deepcopy(self.owned)
        legacy["head"]["ref"] = "provenance/postgres-exporter/v0.20.1-bocklabs.8"
        unarmed = copy.deepcopy(self.healthy)
        unarmed["auto_merge"] = None
        foreign = copy.deepcopy(self.healthy)
        foreign["user"]["login"] = "other-user"
        self.pulls = [legacy, unarmed, foreign, self.owned]
        refresh.refresh("bocklabs/trusted-images")
        self.assertEqual([c for c in self.calls if "PUT" in c], [("gh", "api", "--method", "PUT",
            "repos/bocklabs/trusted-images/pulls/55/update-branch", "-f", "expected_head_sha=" + self.head)])
        self.assertEqual([c for c in self.calls if c[:2] == ("git", "fetch")], [("git", "fetch", "origin", self.head)])

    def test_raced_pr_is_reported_while_independent_healthy_pr_progresses(self):
        self.pulls = [self.owned, self.healthy]
        self.latest[55]["head"]["sha"] = "3" * 40
        with self.assertRaisesRegex(ValueError, "PR 55.*changed before refresh"):
            refresh.refresh("bocklabs/trusted-images")
        self.assertEqual([c for c in self.calls if "PUT" in c], [("gh", "api", "--method", "PUT",
            "repos/bocklabs/trusted-images/pulls/56/update-branch", "-f", "expected_head_sha=" + "4" * 40)])
        self.assertEqual([c for c in self.calls if c[:2] == ("git", "fetch")],
            [("git", "fetch", "origin", self.head), ("git", "fetch", "origin", "4" * 40)])

    def test_changed_validated_snapshot_stops_remaining_prs(self):
        self.pulls = [self.owned, self.healthy]
        self.latest[55]["head"]["sha"] = "3" * 40
        self.commit.side_effect = [self.main, self.main, "9" * 40]
        with self.assertRaisesRegex(ValueError, "validated main changed; remaining refreshes stopped"):
            refresh.refresh("bocklabs/trusted-images")
        self.assertFalse([c for c in self.calls if "PUT" in c])
        self.assertFalse([c for c in self.calls if c[:2] == ("git", "fetch") and c[-1] == "4" * 40])

    def test_live_main_advancement_halts_even_with_unchanged_cached_ref(self):
        self.remote_main = "9" * 40
        with self.assertRaisesRegex(ValueError, "validated main changed or unavailable"):
            refresh.refresh("bocklabs/trusted-images")
        self.assertFalse([c for c in self.calls if "PUT" in c])
        self.assertFalse([c for c in self.calls if c[:2] == ("git", "fetch")])


if __name__ == "__main__":
    unittest.main()
