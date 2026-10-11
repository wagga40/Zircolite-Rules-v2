import json
import sys
import uuid

import pytest
import yaml

import gen_ruleset
from rule_conversion import LEVELS
from ruleset_stats import DASHBOARD, END, FIGURES, START, read_release, update_readme_stats, verify_release
from test_generation import SPEC, detection, source
from test_sql_execution import definitions

README = "# Project\n\nHandwritten introduction: café.\n\n" + START + "\nold statistics\n" + END + "\n\nKeep this footer.\n"
ROW = "| [{0}](https://github.com/example/rules) | {1} |"


def dashboard(output):
    return (output / DASHBOARD).read_text()


def release(tmp_path, docs=None):
    root = source(tmp_path / "source", docs)
    output = tmp_path / "published"
    output.mkdir()
    (output / "README.md").write_text(README)
    args = ({"test": SPEC}, ["test"], output, tmp_path / "cache", [], {"test": root})
    assert not gen_ruleset.generate(*args)
    return root, output, args


def test_statistics_count_entries_ids_and_exact_levels(tmp_path):
    docs = [detection(id=str(uuid.uuid4()), level=level) for level in LEVELS]
    docs[0]["detection"] = {"a": {"Image": "a.exe"}, "b": {"Image": "b.exe"}, "condition": ["a", "b"]}
    _, output, _ = release(tmp_path, docs)
    _, rows = read_release(output)
    merged = next(row for row in rows if row["name"] == "rules_test_windows_merged.json")
    assert merged["entries"] == 12
    assert merged["unique_ids"] == 5
    assert merged["levels"] == dict.fromkeys(LEVELS, 2) | {"informational": 4}
    text, board = (output / "README.md").read_text(), dashboard(output)
    assert text.startswith(README.partition(START)[0])
    assert text.endswith(README.partition(END)[2])
    assert '<source media="(prefers-color-scheme: dark)" srcset="docs/assets/overview-dark.svg">' in text
    assert "1 of 1 sources current; 12 rules in rules_windows_all.json (5 unique)" in text
    assert "[dashboard](docs/dashboard.md)" in text
    assert "| 12 | 5 | 4 | 2 | 2 | 2 | 2 |" in board
    assert "[rules_test_windows_merged.json](../rules_test_windows_merged.json)" in board
    assert board.split("## Experimental correlation rulesets")[1].count("No published rulesets.") == 1
    assert ROW.format("test", "current") + " MIT |" in board
    paths = [output / "README.md", output / DASHBOARD, *sorted((output / FIGURES).glob("*.svg"))]
    assert len(paths) == 8
    before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
    update_readme_stats(output)
    assert [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths] == before
    verify_release(output)


def test_correlation_statistics_are_separate(tmp_path):
    _, output, _ = release(tmp_path, definitions())
    board = dashboard(output)
    assert "## Detection rulesets\n\nNo published rulesets." in board
    assert ("[rules_test_windows_sysmon_correlation.json](../experimental/rules_test_windows_sysmon_correlation.json)"
            in board)
    assert "_correlation_high.json" not in board
    assert "| 1 | 1 | 0 | 0 | 0 | 1 | 0 |" in board


def test_partial_failures_and_source_only_updates_keep_published_counts(tmp_path):
    roots = {name: source(tmp_path / name) for name in ("good", "bad")}
    registry = {name: SPEC for name in roots}
    output = tmp_path / "published"
    output.mkdir()
    (output / "README.md").write_text(README)
    args = (registry, list(roots), output, tmp_path / "cache", [])
    assert not gen_ruleset.generate(*args, roots)
    previous = (output / "rules_bad_windows_sysmon.json").read_bytes()
    (roots["bad"] / "rules/broken.yml").write_text("detection: [")
    (roots["good"] / "rules/second.yml").write_text(yaml.safe_dump(detection(id=str(uuid.uuid4()))))
    assert gen_ruleset.generate(*args, roots) == ["bad"]
    assert (output / "rules_bad_windows_sysmon.json").read_bytes() == previous
    _, rows = read_release(output)
    assert next(row for row in rows if row["name"] == "rules_bad_windows_sysmon.json")["entries"] == 1
    assert next(row for row in rows if row["name"] == "rules_good_windows_sysmon.json")["entries"] == 2
    assert ROW.format("bad", "stale") in dashboard(output)
    assert "Not current: bad (stale since 20" in (output / "README.md").read_text()
    assert not gen_ruleset.generate(registry, ["good"], output, tmp_path / "cache", [], roots)
    assert ROW.format("bad", "stale") in dashboard(output)
    verify_release(output)


def test_unavailable_source_has_no_invented_counts(tmp_path, monkeypatch):
    def unavailable(*args):
        raise TimeoutError("Unavailable")
    monkeypatch.setattr(gen_ruleset, "fetch_source", unavailable)
    (tmp_path / "README.md").write_text(README)
    assert gen_ruleset.generate({"test": SPEC}, ["test"], tmp_path, tmp_path / "cache", []) == ["test"]
    assert ROW.format("test", "unavailable") + " — | — | — | — |" in dashboard(tmp_path)
    assert "[rules_test" not in dashboard(tmp_path)
    assert "Not current: test (unavailable)." in (tmp_path / "README.md").read_text()
    verify_release(tmp_path)


def test_audit_leaves_readme_manifest_and_rules_unchanged(tmp_path):
    root, output, args = release(tmp_path)
    before = {p: p.read_bytes() for p in output.rglob("*") if p.is_file() and p.parent.name != "reports"}
    (root / "rules/example.yaml").write_text(yaml.safe_dump(detection(title="Updated")))
    assert not gen_ruleset.generate(*args, audit=True)
    assert all(p.read_bytes() == contents for p, contents in before.items())
    assert json.loads((output / "reports/test.json").read_text())["revision"] != json.loads(
        (output / "release-manifest.json").read_text())["sources"]["test"]["revision"]


@pytest.mark.parametrize("damage", ["hash", "count", "missing", "inventory"])
def test_invalid_artifacts_cannot_refresh_statistics(tmp_path, damage):
    _, output, _ = release(tmp_path)
    before = (output / "README.md").read_bytes()
    name = "rules_test_windows_sysmon.json"
    manifest = json.loads((output / "release-manifest.json").read_text())
    if damage == "hash":
        (output / name).write_text("[]")
    elif damage == "count":
        manifest["sources"]["test"]["rule_counts"][name] = 99
    elif damage == "inventory":
        manifest["sources"]["test"]["rule_counts"].pop(name)
    else:
        (output / name).unlink()
    gen_ruleset.write_json(output / "release-manifest.json", manifest)
    with pytest.raises((ValueError, FileNotFoundError)):
        update_readme_stats(output)
    assert (output / "README.md").read_bytes() == before
    with pytest.raises((ValueError, FileNotFoundError)):
        verify_release(output)


def test_stale_readme_is_rejected_and_offline_cli_repairs_it(tmp_path, monkeypatch):
    _, output, _ = release(tmp_path)
    (output / "README.md").write_text(README)
    with pytest.raises(ValueError, match="statistics are out of date"):
        verify_release(output)
    def no_fetch(*args, **kwargs):
        pytest.fail("Offline refresh must not fetch sources")
    monkeypatch.setattr(gen_ruleset, "fetch_source", no_fetch)
    monkeypatch.setattr(sys, "argv", ["gen_ruleset.py", "--output-dir", str(output), "--update-readme-stats"])
    assert gen_ruleset.main() == 0
    verify_release(output)


@pytest.mark.parametrize("content", ["No markers", END + START, START + START + END])
def test_missing_or_ambiguous_markers_are_rejected(tmp_path, content):
    _, output, _ = release(tmp_path)
    (output / "README.md").write_text(content)
    with pytest.raises(ValueError, match="markers"):
        update_readme_stats(output)
    assert (output / "README.md").read_text() == content


def test_retained_legacy_variants_are_verified_but_not_advertised(tmp_path):
    from rule_sources import digest
    _, output, _ = release(tmp_path)
    name = "rules_test_windows_sysmon_high.json"
    raw = (output / "rules_test_windows_sysmon.json").read_bytes()
    (output / name).write_bytes(raw)
    manifest = json.loads((output / "release-manifest.json").read_text())
    details = manifest["sources"]["test"]
    details["status"] = "stale"
    details["artifacts"][name] = digest(raw)
    details["rule_counts"][name] = 1
    gen_ruleset.write_json(output / "release-manifest.json", manifest)
    gen_ruleset.rebuild_windows_all(output)
    update_readme_stats(output)
    assert name not in (output / "README.md").read_text() + dashboard(output)
    verify_release(output)
    (output / name).write_text("[]")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_release(output)


def test_dashboard_drift_is_rejected_and_repaired(tmp_path):
    _, output, _ = release(tmp_path)
    (output / DASHBOARD).write_text("edited by hand\n")
    with pytest.raises(ValueError, match="dashboard.md is out of date"):
        verify_release(output)
    (output / DASHBOARD).unlink()
    with pytest.raises(ValueError, match="dashboard.md is out of date"):
        verify_release(output)
    update_readme_stats(output)
    (output / FIGURES / "tactics-dark.svg").unlink()
    with pytest.raises(ValueError, match="tactics-dark.svg is out of date"):
        verify_release(output)
    update_readme_stats(output)
    verify_release(output)


def test_dashboard_counts_distinct_rules_by_tactic_category_and_severity(tmp_path):
    docs = [detection(tags=["attack.execution", "attack.t1059"]),
            detection(id=str(uuid.uuid4()), tags=["attack.defense_evasion", "attack.execution"], level="low"),
            detection(id=str(uuid.uuid4()), logsource={"product": "windows", "service": "security"},
                      detection={"s": {"EventID": 4624}, "condition": "s"}, level="low")]
    _, output, _ = release(tmp_path, docs)
    section = dashboard(output).split("## Inside `rules_windows_all.json`")[1].split("## Detection rulesets")[0]
    assert "| 0 | 2 | 0 | 1 | 0 |" in section
    assert "| Execution | 2 |\n| Defense Evasion | 1 |\n| (no tactic tag) | 1 |" in section
    # Generic variants become Security 4688 rules; they still count as process_creation.
    assert "| process_creation | 2 |\n| service: security | 1 |" in section


def test_figures_are_valid_animated_svg_in_both_themes(tmp_path):
    import xml.etree.ElementTree as ET
    docs = [detection(id=str(uuid.uuid4()), level=level, tags=["attack.execution"]) for level in LEVELS]
    _, output, _ = release(tmp_path, docs)
    names = sorted(path.name for path in (output / FIGURES).glob("*.svg"))
    assert names == [f"{chart}-{theme}.svg" for chart in ("logsources", "overview", "tactics")
                     for theme in ("dark", "light")]
    for name in names:
        text = (output / FIGURES / name).read_text()
        root = ET.fromstring(text)
        assert root.get("role") == "img" and root.find("{http://www.w3.org/2000/svg}title") is not None
        assert "@keyframes" in text and "prefers-reduced-motion: reduce" in text
    card = (output / FIGURES / "overview-light.svg").read_text()
    assert ">1 of 1 sources current<" in card and ">10<" in card
    assert (output / FIGURES / "overview-dark.svg").read_text() != card
    assert "| Execution | 5 |" in dashboard(output) and "<summary>ATT&CK tactic table</summary>" in dashboard(output)
