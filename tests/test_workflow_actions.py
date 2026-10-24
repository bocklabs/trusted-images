"""Workflow and local composite-action contract tests."""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"


class WorkflowActionTests(unittest.TestCase):
    def test_workflows_delegate_custom_code_to_actions(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yaml")):
            workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
            for job_name, job in workflow.get("jobs", {}).items():
                for step in job.get("steps", []):
                    with self.subTest(workflow=path.name, job=job_name, step=step.get("name")):
                        self.assertNotIn("run", step)

    def test_local_actions_are_documented_composites(self) -> None:
        for path in sorted(ACTIONS.rglob("action.yaml")):
            action = yaml.safe_load(path.read_text(encoding="utf-8"))
            with self.subTest(action=str(path.relative_to(ROOT))):
                self.assertTrue(action["name"])
                self.assertTrue(action["description"])
                self.assertEqual(action["runs"]["using"], "composite")
                self.assertTrue(any("run" in step for step in action["runs"]["steps"]))
                for name, value in (action.get("inputs") or {}).items():
                    self.assertTrue(value.get("description"), name)
                for name, value in (action.get("outputs") or {}).items():
                    self.assertTrue(value.get("description"), name)
                    self.assertTrue(value.get("value"), name)

    def test_local_action_contracts_match_callers(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            workflow = yaml.safe_load(text)
            for job in workflow.get("jobs", {}).values():
                for step in job.get("steps", []):
                    uses = step.get("uses", "")
                    if not uses.startswith("./.github/actions/"):
                        continue
                    action = yaml.safe_load(
                        (ROOT / uses.removeprefix("./") / "action.yaml").read_text(encoding="utf-8")
                    )
                    given = set(step.get("with", {}))
                    declared_inputs = set((action.get("inputs") or {}).keys())
                    with self.subTest(action=uses):
                        self.assertLessEqual(given, declared_inputs)
                    step_id = step.get("id")
                    if not step_id:
                        continue
                    used = set(
                        re.findall(
                            rf"steps\.{re.escape(step_id)}\.outputs\.([A-Za-z0-9_-]+)",
                            text,
                        )
                    )
                    declared_outputs = set((action.get("outputs") or {}).keys())
                    with self.subTest(action=uses, step=step_id):
                        self.assertLessEqual(used, declared_outputs)

    def test_shared_ci_logic_lives_in_repository_helpers(self) -> None:
        action_files = sorted(ACTIONS.rglob("action.yaml"))
        for path in action_files:
            text = path.read_text(encoding="utf-8")
            with self.subTest(action=str(path.relative_to(ROOT))):
                self.assertNotIn("ghcr.io/token", text)
                self.assertNotIn('docker run --rm --user "$(id -u):$(id -g)"', text)
                self.assertNotIn("cp candidate-artifact/candidate-decision.json candidate-decision.json", text)
                self.assertNotIn("python3 scripts/promote_summary.py", text)

        for helper in ("ghcr", "registry", "oci", "decision", "inventory", "provenance", "summary", "validate"):
            path = ROOT / "scripts/lib" / f"{helper}.sh"
            with self.subTest(helper=helper):
                self.assertTrue(path.is_file())
                self.assertTrue(
                    any(f"scripts/lib/{helper}.sh" in item.read_text(encoding="utf-8") for item in action_files)
                )


if __name__ == "__main__":
    unittest.main()
