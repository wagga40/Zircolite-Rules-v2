import json
import sys

from test_generation import SPEC, detection, source

import exclusion_baseline
from exclusion_baseline import apply, rebaseline
from rule_conversion import compile_source


def broken_source(tmp_path):
    root = source(tmp_path)
    (root / "rules" / "broken.yml").write_text("title: Broken\ndetection: [\n")
    return root


def reviewed(report, **changes):
    return [{**failure, "source": "test", "reason": "Reviewed invalid YAML", **changes}
            for failure in report["failures"]]


def test_reworded_error_is_proposed_and_validates_after_apply(tmp_path):
    root = broken_source(tmp_path)
    _, report = compile_source("test", SPEC, root, [])
    exclusions = reviewed(report, error="Old wording")
    _, report = compile_source("test", SPEC, root, exclusions)
    assert report["status"] == "failed"
    result = rebaseline(exclusions, [report])
    proposal, = result["proposals"]
    assert (proposal["index"], proposal["old"]) == (0, "Old wording")
    assert proposal["new"] == report["failures"][0]["error"]
    assert result["new_failures"] == result["stale"] == []
    updated = apply(exclusions, result)
    assert updated[0]["reason"] == "Reviewed invalid YAML"
    _, report = compile_source("test", SPEC, root, updated)
    assert report["status"] == "validated"
    assert rebaseline(updated, [report]) == {"proposals": [], "new_failures": [], "stale": [], "skipped": []}


def test_new_failures_are_never_approved(tmp_path):
    _, report = compile_source("test", SPEC, broken_source(tmp_path), [])
    result = rebaseline([], [report])
    assert result["proposals"] == []
    assert [failure["path"] for failure in result["new_failures"]] == ["rules/broken.yml"]
    assert apply([], result) == []


def test_changed_file_hash_is_stale_not_proposed(tmp_path):
    _, report = compile_source("test", SPEC, broken_source(tmp_path), [])
    exclusions = reviewed(report, sha256="0" * 64, error="Old wording")
    result = rebaseline(exclusions, [report])
    assert result["proposals"] == []
    assert len(result["new_failures"]) == 1
    assert [item["index"] for item in result["stale"]] == [0]
    assert apply(exclusions, result) == exclusions
    assert apply(exclusions, result, prune=True) == []


def test_ambiguous_location_is_not_proposed(tmp_path):
    _, report = compile_source("test", SPEC, broken_source(tmp_path), [])
    exclusions = reviewed(report, error="First") + reviewed(report, error="Second")
    result = rebaseline(exclusions, [report])
    assert result["proposals"] == []
    assert len(result["new_failures"]) == 1
    assert len(result["stale"]) == 2


def test_fetch_failures_and_other_sources_are_left_alone(tmp_path):
    _, report = compile_source("test", SPEC, source(tmp_path), [])
    other = {"source": "other", "path": "a.yml", "sha256": "1" * 64, "document": "0", "stage": "parse",
             "profile": "*", "error": "Old", "reason": "Reviewed"}
    result = rebaseline([other], [report, {"source": "unreachable", "status": "failed", "error": "Timeout"}])
    assert result == {"proposals": [], "new_failures": [], "stale": [], "skipped": ["unreachable"]}


def test_cli_is_a_dry_run_unless_applied(tmp_path, monkeypatch, capsys):
    _, report = compile_source("test", SPEC, broken_source(tmp_path / "source"), [])
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "test.json").write_text(json.dumps(report))
    path = tmp_path / "exclusions.json"
    path.write_text(json.dumps(reviewed(report, error="Old wording")))
    before = path.read_bytes()
    argv = ["exclusion_baseline.py", str(reports), "--exclusions", str(path), "--exit-code"]
    monkeypatch.setattr(sys, "argv", argv)
    assert exclusion_baseline.main() == 1
    assert path.read_bytes() == before
    assert "- Old wording" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", [*argv, "--apply"])
    exclusion_baseline.main()
    assert json.loads(path.read_text())[0]["error"] == report["failures"][0]["error"]
    monkeypatch.setattr(sys, "argv", argv)
    # The report still shows the failure; the updated record now approves it.
    assert exclusion_baseline.main() == 0


def test_an_edited_rule_failing_as_reviewed_publishes_and_is_proposed_for_re_pinning(tmp_path):
    root = broken_source(tmp_path)
    _, report = compile_source("test", SPEC, root, [])
    exclusions = reviewed(report, sha256="0" * 64)
    _, report = compile_source("test", SPEC, root, exclusions)
    failure, = report["failures"]
    assert report["status"] == "validated" and failure["approved"] and failure["drifted"]
    result = rebaseline(exclusions, [report])
    proposal, = result["proposals"]
    assert (proposal["field"], proposal["old"], proposal["new"]) == ("sha256", "0" * 64, failure["sha256"])
    assert result["new_failures"] == result["stale"] == []
    markdown = exclusion_baseline.render_markdown(result)
    assert "re-pinned" in markdown and failure["error"].splitlines()[0] in markdown
    updated = apply(exclusions, result)
    _, report = compile_source("test", SPEC, root, updated)
    assert not report["failures"][0].get("drifted")
    assert rebaseline(updated, [report])["proposals"] == []


def test_an_edited_rule_failing_differently_still_blocks(tmp_path):
    root = broken_source(tmp_path)
    _, report = compile_source("test", SPEC, root, [])
    _, report = compile_source("test", SPEC, root, reviewed(report, sha256="0" * 64, error="Other"))
    assert report["status"] == "failed" and not report["failures"][0]["approved"]


def test_control_removes_what_is_not_caused_by_the_candidate(tmp_path):
    _, report = compile_source("test", SPEC, broken_source(tmp_path), [])
    stale = {"source": "test", "path": "gone.yml", "sha256": "1" * 64, "document": "0", "stage": "parse",
             "profile": "*", "error": "Old", "reason": "Reviewed"}
    control = rebaseline([stale], [report])
    assert control["new_failures"] and control["stale"]
    assert exclusion_baseline.subtract(control, control) == {
        "proposals": [], "new_failures": [], "stale": [], "skipped": []}
    extra = {**report["failures"][0], "path": "rules/other.yml"}
    candidate = rebaseline([stale], [{**report, "failures": report["failures"] + [extra]}])
    difference = exclusion_baseline.subtract(candidate, control)
    assert [item["path"] for item in difference["new_failures"]] == ["rules/other.yml"]
    assert difference["stale"] == []


def outside_fences(markdown):
    """Text CommonMark renders outside fenced code blocks."""
    outside, fence = [], None
    for line in markdown.splitlines():
        run = line[:len(line) - len(line.lstrip(line[:1]))] if line[:1] in "~`" else ""
        if fence is None and len(run) >= 3:
            fence = run
        elif fence is not None and run and run[0] == fence[0] and len(run) >= len(fence) and not line[len(run):].strip():
            fence = None
        elif fence is None:
            outside.append(line)
    return "\n".join(outside)


def test_upstream_text_is_fenced_in_the_markdown():
    failure = {"source": "test", "path": "a.yml", "sha256": "1" * 64, "document": "0", "stage": "parse",
               "profile": "*", "error": "~~~~\n```\n@someone [x](https://example.org)"}
    markdown = exclusion_baseline.render_markdown(
        {"proposals": [{**failure, "index": 0, "field": "error", "old": "Old", "new": failure["error"]}],
         "new_failures": [{**failure, "error": "@someone ~~~"}], "stale": [], "skipped": []})
    assert markdown.count("@someone") == 2 and "@someone" not in outside_fences(markdown)
