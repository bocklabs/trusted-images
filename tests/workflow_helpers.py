"""Load workflow steps through their local composite actions."""

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
INPUT = re.compile(r"^\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}$")


def load_workflow(path: Path) -> Any:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    for job in workflow.get("jobs", {}).values():
        if "steps" in job:
            job["steps"] = expand_steps(job["steps"])
    return workflow


def expand_steps(steps: list[dict]) -> list[dict]:
    expanded = []
    for step in steps:
        uses = step.get("uses", "")
        expanded.append(resolve_local_action(step) if uses.startswith("./.github/actions/") else step)
    return expanded


def resolve_action_env(step: dict, inner: dict) -> dict:
    env = {}
    for key, value in (inner.get("env", {}) or {}).items():
        match = INPUT.fullmatch(str(value))
        env[key] = step.get("with", {}).get(match.group(1), "") if match else value
    env.update(step.get("env", {}) or {})
    return env


def resolve_local_action(step: dict) -> dict:
    uses = step["uses"]
    action = yaml.safe_load((ROOT / uses.removeprefix("./") / "action.yaml").read_text())
    run_steps = [item for item in action["runs"]["steps"] if "run" in item]
    if len(run_steps) != 1:
        raise AssertionError(f"expected one run step in {uses}")
    inner = run_steps[0]
    resolved = {key: value for key, value in step.items() if key != "uses"}
    resolved["run"] = inner["run"]
    env = resolve_action_env(step, inner)
    if env:
        resolved["env"] = env
    if "working-directory" in inner:
        resolved["working-directory"] = inner["working-directory"]
    return resolved


def action_text(step: dict) -> str:
    uses = step.get("uses", "")
    action = yaml.safe_load((ROOT / uses.removeprefix("./") / "action.yaml").read_text())
    return "\n".join(item["run"] for item in action["runs"]["steps"] if "run" in item)


def workflow_action_text(path: Path) -> str:
    workflow = path.read_text(encoding="utf-8")
    uses = set(re.findall(r"uses:\s+(\./\.github/actions/[^\s]+)", workflow))
    return "\n".join(
        (ROOT / action.removeprefix("./") / "action.yaml").read_text(encoding="utf-8")
        for action in sorted(uses)
    )
