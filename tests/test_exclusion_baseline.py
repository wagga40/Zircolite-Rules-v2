import json
import sys

import pytest
from test_generation import SPEC, detection, source

import exclusion_baseline
import gen_ruleset
from exclusion_baseline import apply, rebaseline
from exclusion_records import normalize_error
from rule_conversion import compile_source

EMPTY = {"proposals": [], "new_failures": [], "stale": [], "redundant": [], "unused_classes": [],
         "class_usage": [], "drafts": [], "skipped": []}


def broken_source(tmp_path):
    root = source(tmp_path)
    (root / "rules" / "broken.yml").write_text("title: Broken\ndetection: [\n")
    return root


def reviewed(report, **changes):
    """Records for a report's failures, without the report-only approval flags."""
    return [{**{key: value for key, value in failure.items() if key not in ("approved", "drifted")},
             "source": "test", "reason": "Reviewed invalid YAML", **changes} for failure in report["failures"]]


def test_reworded_error_is_proposed_and_validates_after_apply(tmp_path):
    root = broken_source(tmp_path)
    _, report = compile_source("test", SPEC, root, [])
    exclusions = reviewed(report, error="Old wording")
    _, report = compile_source("test", SPEC, root, exclusions)
    assert report["status"] == "failed"
    result = rebaseline(exclusions, [report])
    proposal, = result["proposals"]
    assert (proposal["index"], proposal["old"]) == (0, "Old wording")
    assert proposal["new"] == normalize_error(report["failures"][0]["error"])
    assert result["new_failures"] == result["stale"] == []
    updated = apply(exclusions, result)
    assert updated[0]["reason"] == "Reviewed invalid YAML"
    _, report = compile_source("test", SPEC, root, updated)
    assert report["status"] == "validated"
    assert rebaseline(updated, [report]) == EMPTY


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
    assert result == {**EMPTY, "skipped": ["unreachable"]}


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
    assert json.loads(path.read_text())[0]["error"] == normalize_error(report["failures"][0]["error"])
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
    assert exclusion_baseline.subtract(control, control) == EMPTY
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


KEYWORDS = {"class": "fulltext-keywords", "source": "*", "stage": "convert", "profile": "*",
            "error_pattern": r"Keyword search requires fulltext_field and a populated TEXT column; configure "
                             r"fulltext_field and re-ingest old events\.", "reason": "No full-text column"}


def keyword_report(tmp_path, exclusions=()):
    rule = detection(id="11111111-1111-4111-8111-111111111111",
                     detection={"keywords": ["mimikatz"], "condition": "keywords"})
    return compile_source("test", SPEC, source(tmp_path, [detection(), rule]), list(exclusions))[1]


def test_an_any_profile_record_is_re_pinned_once_for_every_profile(tmp_path):
    report = keyword_report(tmp_path)
    record = {**reviewed(report)[0], "profile": "*", "sha256": "0" * 64}
    report = keyword_report(tmp_path, [record])
    assert report["status"] == "validated" and all(failure["drifted"] for failure in report["failures"])
    proposal, = rebaseline([record], [report])["proposals"]
    assert (proposal["field"], proposal["profile"], proposal["new"]) == ("sha256", "*", report["failures"][0]["sha256"])


def test_class_records_are_counted_but_never_rewritten(tmp_path):
    report = keyword_report(tmp_path, [KEYWORDS])
    result = rebaseline([KEYWORDS], [report])
    assert result["class_usage"] == [{"class": "fulltext-keywords", "failures": 2}]
    assert apply([KEYWORDS], result, prune=True) == [KEYWORDS]
    unused = rebaseline([KEYWORDS], [compile_source("test", SPEC, source(tmp_path / "plain"), [])[1]])
    assert [item["class"] for item in unused["unused_classes"]] == ["fulltext-keywords"]
    assert apply([KEYWORDS], unused, prune=True) == [KEYWORDS]


def test_records_a_class_covers_are_removed_without_changing_an_approval(tmp_path):
    report = keyword_report(tmp_path)
    records = [KEYWORDS, *reviewed(report)]
    result = rebaseline(records, [report])
    assert [item["index"] for item in result["redundant"]] == [1, 2]
    updated = apply(records, result, only={"redundant"})
    assert updated == [KEYWORDS]
    assert exclusion_baseline.approval_changes(records, updated, [report]) == {
        "newly_approved": [], "no_longer_approved": [], "drift_changed": []}


def test_compare_lists_newly_approved_failures(tmp_path, monkeypatch, capsys):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "test.json").write_text(json.dumps(keyword_report(tmp_path / "source")))
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text("[]")
    new.write_text(json.dumps([KEYWORDS]))
    monkeypatch.setattr(sys, "argv", ["exclusion_baseline.py", str(reports), "--exclusions", str(new),
                                      "--compare", str(old), "--exit-code"])
    assert exclusion_baseline.main() == 1
    assert "2 newly approved, 0 no longer approved" in capsys.readouterr().out


def test_drafts_approve_nothing_and_survive_pruning(tmp_path, monkeypatch):
    _, report = compile_source("test", SPEC, broken_source(tmp_path / "source"), [])
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "test.json").write_text(json.dumps(report))
    path = tmp_path / "exclusions.json"
    path.write_text("[]")
    monkeypatch.setattr(sys, "argv", ["exclusion_baseline.py", str(reports), "--exclusions", str(path), "--draft-new"])
    exclusion_baseline.main()
    draft, = json.loads(path.read_text())
    assert draft["reason"] == "" and draft["path"] == "rules/broken.yml" and "approved" not in draft
    _, report = compile_source("test", SPEC, broken_source(tmp_path / "source"), [draft])
    assert report["status"] == "failed"
    result = rebaseline([draft], [report])
    assert len(result["new_failures"]) == 1 and result["stale"] == [] and len(result["drafts"]) == 1
    assert apply([draft], result, prune=True) == [draft]


def publish(tmp_path, exclusions):
    """Two published sources: good validates with one drifted record, bad fails."""
    roots = {"good": broken_source(tmp_path / "good"), "bad": broken_source(tmp_path / "bad")}
    registry = {name: SPEC for name in roots}
    output = tmp_path / "published"
    gen_ruleset.generate(registry, list(roots), output, tmp_path / "cache", exclusions, roots)
    (tmp_path / "sources.json").write_text(json.dumps(registry))
    return roots, registry, output


def auto(tmp_path, output, path, *extra):
    return ["exclusion_baseline.py", str(output / "reports"), "--exclusions", str(path), "--validated-only",
            "--apply", "--manifest", str(output / "release-manifest.json"),
            "--registry", str(tmp_path / "sources.json"), *extra]


def test_the_publish_run_re_pins_and_prunes_only_validated_sources(tmp_path, monkeypatch):
    _, report = compile_source("good", SPEC, broken_source(tmp_path / "probe"), [])
    edited = {**reviewed(report, source="good")[0], "sha256": "0" * 64}
    gone = {**edited, "path": "rules/gone.yml"}
    exclusions = [edited, gone, {**gone, "source": "bad"}]
    roots, registry, output = publish(tmp_path, exclusions)
    manifest = json.loads((output / "release-manifest.json").read_text())
    assert manifest["sources"]["good"]["status"] == "current" and manifest["sources"]["bad"]["status"] != "current"
    path = tmp_path / "exclusions.json"
    path.write_text(json.dumps(exclusions))
    monkeypatch.setattr(sys, "argv", auto(tmp_path, output, path))
    assert exclusion_baseline.main() == 0
    updated = json.loads(path.read_text())
    assert updated == [{**edited, "sha256": report["failures"][0]["sha256"]}, {**gone, "source": "bad"}]
    # Re-pinning changes nothing that is published.
    published = {name: (output / name).read_bytes() for name in ("rules_good_windows_sysmon.json",
                                                                 "provenance/good.json")}
    gen_ruleset.generate(registry, ["good"], output, tmp_path / "cache", updated, {"good": roots["good"]})
    assert {name: (output / name).read_bytes() for name in published} == published
    assert not any(f.get("drifted") for f in json.loads((output / "reports" / "good.json").read_text())["failures"])


def test_the_publish_run_refuses_to_prune_too_much_or_change_an_approval(tmp_path, monkeypatch):
    _, report = compile_source("good", SPEC, broken_source(tmp_path / "probe"), [])
    record = reviewed(report, source="good")[0]
    exclusions = [record, {**record, "path": "rules/gone.yml"}]
    _, _, output = publish(tmp_path, exclusions)
    path = tmp_path / "exclusions.json"
    path.write_text(json.dumps(exclusions))
    before = path.read_bytes()
    monkeypatch.setattr(sys, "argv", auto(tmp_path, output, path, "--max-prune", "0"))
    with pytest.raises(SystemExit, match="Refusing to prune 1 records"):
        exclusion_baseline.main()
    monkeypatch.setattr(sys, "argv", auto(tmp_path, output, path))
    monkeypatch.setattr(exclusion_baseline, "apply", lambda *args, **kwargs: [])
    with pytest.raises(SystemExit, match="Refusing to change approvals"):
        exclusion_baseline.main()
    assert path.read_bytes() == before


def test_the_publish_run_never_rewords(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["exclusion_baseline.py", "reports", "--validated-only", "--apply",
                                      "--only", "reword"])
    with pytest.raises(SystemExit):
        exclusion_baseline.main()
