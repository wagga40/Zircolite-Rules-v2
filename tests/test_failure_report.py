import json
import sys

import pytest

import failure_report
from exclusion_baseline import render_markdown as render_baseline
from failure_report import MAX_ISSUE, annotations, failed_sources, fingerprint, render_issue

FAILURE = {"approved": False, "document": "0", "error": "Keyword search requires fulltext_field\nsecond line",
           "path": "rules/a.yml", "profile": "sysmon", "sha256": "1" * 64, "stage": "convert"}
MANIFEST = {"sources": {
    "current": {"status": "current", "revision": "a" * 40},
    "rules": {"status": "stale", "error": "1 unexpected failures; see reports/rules.json",
              "last_success": "2026-10-11T09:15:15+00:00"},
    "offline": {"status": "unavailable", "error": "Fetch failed"},
}}
REPORTS = {"rules": {"source": "rules", "status": "failed", "failures": [FAILURE, {**FAILURE, "approved": True}]},
           "offline": {"source": "offline", "status": "failed", "error": "Fetch failed"}}


def test_only_sources_whose_latest_attempt_failed_are_listed_with_unapproved_failures():
    failed = failed_sources(MANIFEST, REPORTS)
    assert [item["source"] for item in failed] == ["offline", "rules"]
    assert failed[0]["failures"] == [] and failed[1]["failures"] == [FAILURE]
    assert failed_sources({"sources": {"current": {"status": "current"}}}, {}) == []
    # A failure is known by its status, even when the exception had no message.
    silent, = failed_sources({"sources": {"silent": {"status": "stale", "error": ""}}}, {})
    assert silent["error"] and annotations([silent])


def test_fingerprint_ignores_run_details_but_not_the_failures():
    failed = failed_sources(MANIFEST, REPORTS)
    later = failed_sources({"sources": {**MANIFEST["sources"], "rules": {
        **MANIFEST["sources"]["rules"], "last_success": "2026-10-12T00:00:00+00:00"}}}, REPORTS)
    assert fingerprint(failed) == fingerprint(later)
    changed = failed_sources(MANIFEST, {**REPORTS, "rules": {"failures": [{**FAILURE, "sha256": "2" * 64}]}})
    assert fingerprint(failed) != fingerprint(changed)
    assert f"failure-fingerprint: {fingerprint(failed)}" in render_issue(failed, "https://run")


def test_issue_keeps_upstream_text_inside_a_fence_it_cannot_close():
    # A source error keeps every line; a rule failure contributes its first.
    hostile = {"status": "stale", "error": "Fetch failed\n~~~~\n@someone [link](https://example.org)",
               "last_success": "2026-10-11T09:15:15+00:00"}
    manifest = {"sources": {**MANIFEST["sources"], "rules": hostile}}
    body = render_issue(failed_sources(manifest, {"rules": {"failures": [{**FAILURE, "error": "~~~~~ x"}]}}),
                        "https://run")
    section = body.split("### rules (stale, last validated 2026-10-11T09:15:15+00:00)\n\n")[1]
    fence = section.split("\n")[0]
    assert set(fence) == {"~"} and len(fence) > 4
    assert section.index("@someone") < section.index(f"\n{fence}\n", len(fence))
    assert "### offline (unavailable, never validated)" in body


def test_long_failure_lists_are_truncated():
    many = [{**FAILURE, "path": f"rules/{index}.yml"} for index in range(25)]
    body = render_issue(failed_sources(MANIFEST, {"rules": {"failures": many}}), "https://run")
    assert "rules/19.yml" in body and "rules/20.yml" not in body
    assert "... and 5 more" in body


def test_annotations_escape_workflow_command_data():
    rules = next(item for item in failed_sources(MANIFEST, REPORTS) if item["source"] == "rules")
    warning, = annotations([{**rules, "error": "100% failed, see: a\nb"}])
    assert warning.startswith("::warning title=rules kept its previous rules::100%25 failed, see: a%0Ab%0A")
    assert "\n" not in warning


def test_cli_writes_feedback_only_when_a_source_failed(tmp_path, monkeypatch, capsys):
    (tmp_path / "reports").mkdir()
    for name, report in REPORTS.items():
        (tmp_path / "reports" / f"{name}.json").write_text(json.dumps(report))
    (tmp_path / "release-manifest.json").write_text(json.dumps(MANIFEST))
    exclusions = tmp_path / "exclusions.json"
    exclusions.write_text("[]")
    summary, issue = tmp_path / "summary.md", tmp_path / "issue.md"
    summary.write_text("Earlier summary\n")
    argv = ["failure_report.py", "--output-dir", str(tmp_path), "--exclusions", str(exclusions),
            "--run-url", "https://run", "--summary", str(summary), "--issue", str(issue)]
    monkeypatch.setattr(sys, "argv", argv)
    assert failure_report.main() == 0
    assert capsys.readouterr().out.count("::warning ") == 2
    assert summary.read_text().startswith("Earlier summary\n## Failed sources")
    assert "## Exclusion baseline" in summary.read_text()
    assert "[the latest run](https://run)" in issue.read_text()
    issue.unlink()
    (tmp_path / "release-manifest.json").write_text(json.dumps({"sources": {"current": {"status": "current"}}}))
    assert failure_report.main() == 0
    assert not issue.exists() and capsys.readouterr().out == ""


def test_feedback_stays_within_github_limits():
    sources = {f"s{index:02}": {"status": "stale", "error": "x" * 5000 + "\n" + "line\n" * 40}
               for index in range(13)}
    failed = failed_sources({"sources": sources}, {})
    body = render_issue(failed, "https://run")
    assert len(body) <= MAX_ISSUE and body.startswith("<!-- failure-fingerprint: ")
    assert body.rstrip().endswith("the conversion-reports artifact has the full reports.")
    assert "... and 21 more lines" in body
    cut = failure_report.truncate("z" * 100, 80)  # one line longer than the limit
    assert len(cut) <= 80 and cut.startswith("zzz")
    warnings = annotations(failed)
    assert len(warnings) == 10 and warnings[-1].startswith("::warning title=4 more sources")


def test_unencodable_upstream_text_cannot_break_the_feedback():
    lone = {**MANIFEST["sources"]["rules"], "error": "bad \ud800 value"}
    failed = failed_sources({"sources": {"rules": lone}}, {})
    annotations(failed)[0].encode()
    assert "\\ud800" in annotations(failed)[0]
    assert render_baseline({"proposals": [], "stale": [], "skipped": [],
                            "new_failures": [{**FAILURE, "source": "rules", "error": ""}]})


def test_failures_reach_the_summary_even_when_the_baseline_fails(tmp_path, monkeypatch):
    (tmp_path / "reports").mkdir()
    (tmp_path / "release-manifest.json").write_text(json.dumps(MANIFEST))
    exclusions = tmp_path / "exclusions.json"
    exclusions.write_text("not json")
    summary, issue = tmp_path / "summary.md", tmp_path / "issue.md"
    monkeypatch.setattr(sys, "argv", ["failure_report.py", "--output-dir", str(tmp_path), "--exclusions",
                                      str(exclusions), "--run-url", "https://run", "--summary", str(summary),
                                      "--issue", str(issue)])
    with pytest.raises(json.JSONDecodeError):
        failure_report.main()
    assert issue.exists() and "## Failed sources" in summary.read_text()


def test_since_limits_the_report_to_sources_attempted_in_this_run():
    manifest = {"sources": {
        "today": {"status": "stale", "error": "A", "last_attempt": "2026-10-15T01:30:00+00:00"},
        "removed": {"status": "stale", "error": "B", "last_attempt": "2026-09-01T01:30:00+00:00"}}}
    since = failure_report.parse_time("2026-10-15T01:23:00+00:00")
    assert [item["source"] for item in failed_sources(manifest, {}, since)] == ["today"]
    assert len(failed_sources(manifest, {})) == 2


def test_fingerprint_ignores_paths_and_numbers_in_source_errors():
    def failed(error):
        return failed_sources({"sources": {"s": {"status": "stale", "error": error}}}, {})
    assert fingerprint(failed("Fetch failed in /tmp/abc123/.rules-stage-x9: read 512 bytes")) == fingerprint(
        failed("Fetch failed in /tmp/zzz999/.rules-stage-q1: read 4096 bytes"))
    assert fingerprint(failed("Fetch failed")) != fingerprint(failed("License is empty"))


def test_drifted_exclusions_warn_without_opening_the_issue(tmp_path, monkeypatch, capsys):
    (tmp_path / "reports").mkdir()
    drifted = {**FAILURE, "approved": True, "drifted": True}
    (tmp_path / "reports" / "current.json").write_text(json.dumps({"source": "current", "failures": [drifted]}))
    (tmp_path / "release-manifest.json").write_text(json.dumps({"sources": {"current": {"status": "current"}}}))
    exclusions = tmp_path / "exclusions.json"
    exclusions.write_text(json.dumps([{**FAILURE, "source": "current", "sha256": "0" * 64, "reason": "R"}]))
    summary, issue = tmp_path / "summary.md", tmp_path / "issue.md"
    monkeypatch.setattr(sys, "argv", ["failure_report.py", "--output-dir", str(tmp_path), "--exclusions",
                                      str(exclusions), "--run-url", "https://run", "--summary", str(summary),
                                      "--issue", str(issue)])
    assert failure_report.main() == 0
    warning, = capsys.readouterr().out.splitlines()
    assert warning.startswith("::warning title=1 excluded rule changed upstream::")
    assert "exclusion_baseline.py" in warning and not issue.exists()
    assert "re-pinned" in summary.read_text() and "## Failed sources" not in summary.read_text()
