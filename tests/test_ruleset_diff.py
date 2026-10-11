import json
import sys

import pytest
from test_generation import SPEC, detection, source

import gen_ruleset
import ruleset_diff
from ruleset_diff import diff_releases, render_markdown

IDS = ["6b575854-347f-44cc-a48b-1e4e1e62f569", "0f06a3a5-6a09-413f-8743-e6cf35561297",
       "5ad5b4f5-5d4c-4ef1-8a4d-cf6b65f0dfab", "e6c2a7b4-9b6e-4d2f-a0f7-1c8b1d2f3e4a"]


def release(tmp_path, name, documents, spec=SPEC):
    root = source(tmp_path / f"{name}-source", documents)
    output = tmp_path / name
    assert not gen_ruleset.generate({"test": spec}, ["test"], output, tmp_path / "cache", [], {"test": root})
    return output


def test_identical_releases_have_no_changes(tmp_path):
    documents = [detection()]
    diff = diff_releases(release(tmp_path, "old", documents), release(tmp_path, "new", documents))
    assert not ruleset_diff.changed(diff)
    assert {item["status"] for item in diff["artifacts"].values()} == {"unchanged"}
    assert "No source or rule changes." in render_markdown(diff)


def test_each_change_category_is_reported(tmp_path):
    old = release(tmp_path, "old", [detection(id=IDS[0]), detection(id=IDS[1]), detection(id=IDS[2])])
    new = release(tmp_path, "new", [
        detection(id=IDS[0], title="Renamed"),
        detection(id=IDS[1], detection={"selection": {"Image|endswith": "\\other.exe"}, "condition": "selection"}),
        detection(id=IDS[3])])
    diff = diff_releases(old, new)
    item = diff["artifacts"]["rules_test_windows_sysmon.json"]
    assert item["status"] == "changed" and item["entries"] == [3, 3]
    assert [rule["id"] for rule in item["added"]] == [IDS[3]]
    assert [rule["id"] for rule in item["removed"]] == [IDS[2]]
    assert [(rule["id"], rule["added"], rule["removed"]) for rule in item["sql_changed"]] == [(IDS[1], 1, 1)]
    assert [(rule["id"], rule["fields"]) for rule in item["metadata_changed"]] == [(IDS[0], ["title"])]
    assert diff["sources"]["test"]["changed"]
    markdown = render_markdown(diff)
    assert "| rules_test_windows_sysmon.json | changed | 3 → 3 | 1 | 1 | 1 | 1 |" in markdown
    assert "`title` (1)" in markdown


def test_artifacts_on_one_side_are_added_or_removed(tmp_path):
    old = release(tmp_path, "old", [detection()], dict(SPEC, profiles=["sysmon"]))
    new = release(tmp_path, "new", [detection()])
    artifacts = diff_releases(old, new)["artifacts"]
    assert artifacts["rules_test_windows_generic.json"]["status"] == "added"
    assert artifacts["rules_test_windows_sysmon.json"]["status"] == "unchanged"
    assert diff_releases(new, old)["artifacts"]["rules_test_windows_generic.json"]["status"] == "removed"


def test_tampered_release_is_rejected(tmp_path):
    old = release(tmp_path, "old", [detection()])
    new = release(tmp_path, "new", [detection()])
    (new / "rules_test_windows_sysmon.json").write_text("[]")
    with pytest.raises(ValueError, match="hash mismatch"):
        diff_releases(old, new)


def test_markdown_lists_are_limited(tmp_path):
    old = release(tmp_path, "old", [detection()])
    new = release(tmp_path, "new", [detection(id=rule_id) for rule_id in IDS])
    markdown = render_markdown(diff_releases(old, new), limit=1)
    assert "- … and 2 more" in markdown


def test_cli_writes_json_and_signals_changes(tmp_path, monkeypatch, capsys):
    old = release(tmp_path, "old", [detection()])
    new = release(tmp_path, "new", [detection(title="Renamed")])
    output = tmp_path / "diff.json"
    monkeypatch.setattr(sys, "argv", ["ruleset_diff.py", str(old), str(new), "--json", str(output), "--exit-code"])
    assert ruleset_diff.main() == 1
    assert json.loads(output.read_text())["totals"]["metadata_changed"] > 0
    assert "## Ruleset changes" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["ruleset_diff.py", str(old), str(old), "--exit-code"])
    assert ruleset_diff.main() == 0
