import json
import sys
import uuid

import pytest
import yaml

import gen_ruleset
from rule_conversion import LEVELS
from ruleset_stats import END, START, read_release, update_readme_stats, verify_release
from test_generation import SPEC, detection, source
from test_sql_execution import definitions

README = "# Project\n\nHandwritten introduction: café.\n\n" + START + "\nold statistics\n" + END + "\n\nKeep this footer.\n"


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
    text = (output / "README.md").read_text()
    assert "| 12 | 5 | 4 | 2 | 2 | 2 | 2 |" in text
    assert text.startswith(README.partition(START)[0])
    assert text.endswith(README.partition(END)[2])
    assert "[rules_test_windows_merged.json](rules_test_windows_merged.json)" in text
    assert "### Experimental correlation rulesets\n\nNo published rulesets." in text
    assert "| test | current |" in text
    before = (output / "README.md").read_bytes()
    modified = (output / "README.md").stat().st_mtime_ns
    update_readme_stats(output)
    assert (output / "README.md").read_bytes() == before
    assert (output / "README.md").stat().st_mtime_ns == modified
    verify_release(output)


def test_correlation_statistics_are_separate(tmp_path):
    _, output, _ = release(tmp_path, definitions())
    text = (output / "README.md").read_text()
    assert "### Detection rulesets\n\nNo published rulesets." in text
    assert "[rules_test_windows_sysmon_correlation.json](experimental/rules_test_windows_sysmon_correlation.json)" in text
    assert "_correlation_high.json" not in text
    assert "| 1 | 1 | 0 | 0 | 0 | 1 | 0 |" in text


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
    assert "| bad | stale |" in (output / "README.md").read_text()
    assert not gen_ruleset.generate(registry, ["good"], output, tmp_path / "cache", [], roots)
    assert "| bad | stale |" in (output / "README.md").read_text()
    verify_release(output)


def test_unavailable_source_has_no_invented_counts(tmp_path, monkeypatch):
    def unavailable(*args):
        raise TimeoutError("Unavailable")
    monkeypatch.setattr(gen_ruleset, "fetch_source", unavailable)
    (tmp_path / "README.md").write_text(README)
    assert gen_ruleset.generate({"test": SPEC}, ["test"], tmp_path, tmp_path / "cache", []) == ["test"]
    text = (tmp_path / "README.md").read_text()
    assert "| test | unavailable | — | — |" in text
    assert "[rules_test" not in text
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
    assert name not in (output / "README.md").read_text()
    verify_release(output)
    (output / name).write_text("[]")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_release(output)
