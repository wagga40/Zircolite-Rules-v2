import json
import sys

import dependency_canary
from dependency_canary import assess, conflicts, render_markdown

PINNED = {"pysigma": ("2.0.0", []),
          "pysigma-backend-sqlite": ("2.1.0", ["pysigma (>=2.0.0,<3.0)"]),
          "pysigma-pipeline-windows": ("2.0.0", ["pysigma (>=1.0,<2.0)", 'pytest; extra == "test"'])}
RELEASED = dict(PINNED, **{"pysigma-pipeline-windows": ("2.1.0", ["pysigma (>=2.0,<3.0)"])})


def test_conflicts_name_the_requirement_an_installed_version_violates():
    assert conflicts(PINNED) == [
        "pysigma-pipeline-windows 2.0.0 requires `pysigma (>=1.0,<2.0)`; pysigma 2.0.0 is installed"]
    assert conflicts(RELEASED) == []
    assert conflicts({"pySigma": ("1.5.1", []), "backend": ("1", ["PySigma>=2"])})


def test_override_is_removable_only_without_conflicts():
    published = {name: version for name, (version, _) in PINNED.items()}
    overrides = {"pysigma": ">=2.0.0,<3"}
    pinned = assess(published, PINNED, {}, overrides)
    assert not pinned["override_removable"] and not pinned["upgraded"]
    assert "still required" in render_markdown(pinned, overrides)
    released = assess(published, RELEASED, {"pysigma": "2.0.1"}, overrides)
    assert released["override_removable"] and released["upgraded"]
    markdown = render_markdown(released, overrides)
    assert "no longer needed" in markdown
    assert "| pysigma-pipeline-windows | 2.0.0 | 2.1.0 | — |" in markdown
    assert not assess(published, RELEASED, {}, {})["override_removable"]


def test_cli_signals_upgrades_against_the_published_tools(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dependency_canary, "latest_release", lambda name: "9.9.9")
    stack = dependency_canary.installed_stack()
    manifest = tmp_path / "release-manifest.json"
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'test'\n")
    argv = ["dependency_canary.py", "--manifest", str(manifest), "--pyproject", str(pyproject), "--exit-code"]
    monkeypatch.setattr(sys, "argv", argv)
    manifest.write_text(json.dumps({"sources": {"sigmahq": {"tools": {n: v for n, (v, _) in stack.items()}}}}))
    assert dependency_canary.main() == 0
    manifest.write_text(json.dumps({"sources": {"sigmahq": {"tools": {"pysigma": "0.1"}}}}))
    assert dependency_canary.main() == 1
    assert "| 9.9.9 |" in capsys.readouterr().out
