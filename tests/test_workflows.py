"""The workflow guards that keep publishing on main and write access away from new packages."""

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())


def runs(job):
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_only_main_publishes_and_the_publish_commit_carries_exclusions():
    publish = workflow("Update.yml")["jobs"]["publish"]
    assert "github.ref == 'refs/heads/main'" in publish["if"]
    assert re.search(r"git add -- [^\n]*\bexclusions\.json", runs(publish))


def test_new_packages_never_run_with_write_access():
    jobs = workflow("dependency-canary.yml")["jobs"]
    writers = {name for name, job in jobs.items()
               if any(access == "write" for access in job.get("permissions", {}).values())}
    assert writers == {"report", "upgrade-pr"}
    assert jobs["report"]["permissions"] == {"issues": "write"}
    assert jobs["canary"]["permissions"] == {"contents": "read"}
    script = runs(jobs["upgrade-pr"])
    assert not re.search(r"\bpdm\s+(run|sync|install|lock|update|add)\b", script)
    assert re.findall(r"\S+\.py", script) == ["dependency_upgrade.py"]
    assert "python3 -I dependency_upgrade.py" in script
    assert "refs/heads/main" in jobs["upgrade-pr"]["if"]


def test_every_pdm_shortcut_runs_a_file_that_exists():
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["pdm"]["scripts"]
    for name, script in scripts.items():
        if "composite" in script:
            assert set(script["composite"]) <= scripts.keys(), name
            continue
        files = re.findall(r"\S+\.py", script["cmd"])
        assert all((ROOT / path).exists() for path in files), name
