import json
import pytest
import yaml

import gen_ruleset
from rule_bundles import WINDOWS_ALL, windows_all_files
from rule_conversion import identity
from rule_sources import digest, json_bytes
from test_generation import SPEC, detection, source
from test_ruleset_stats import README
from test_sql_execution import definitions


def test_all_windows_sources_merge_without_losing_variants(tmp_path):
    extra = detection(id="8e25d1af-f393-476b-bdb3-b1ad947877c9", title="Community A")
    native = detection(id="7c791d13-e8f4-4463-ba9d-a67bc3ad0d76", logsource={"product": "windows"})
    linux = detection(id="5514b44c-81b9-4e51-a038-7ea4999ea857", logsource={"product": "linux"})
    roots = {
        "sigmahq": source(tmp_path / "sigmahq", [detection(), linux]),
        "community_a": source(tmp_path / "community_a", [detection(title="Duplicate official"), extra]),
        "community_b": source(tmp_path / "community_b", [dict(extra, title="Community B")]),
        "native": source(tmp_path / "native", [native, *definitions()]),
    }
    registry = {name: dict(SPEC) for name in roots}
    registry["sigmahq"]["profiles"] = ["sysmon", "generic", "linux"]
    registry["native"]["profiles"] = ["native"]
    output = tmp_path / "published"
    output.mkdir()
    (output / "README.md").write_text(README)
    assert not gen_ruleset.generate(registry, list(reversed(roots)), output, tmp_path / "cache", [], roots)
    combined = json.loads((output / WINDOWS_ALL).read_text())
    assert len(combined) == 5
    assert len({identity(rule) for rule in combined}) == 5
    assert {rule["id"] for rule in combined} == {detection()["id"], extra["id"], native["id"]}
    assert all(rule["result_type"] == "event" and rule["logsource"]["product"] == "windows" for rule in combined)
    assert all(rule["title"].startswith("Community A") for rule in combined if rule["id"] == extra["id"])
    assert len([rule for rule in combined if rule["id"] == detection()["id"]]) == 2
    assert sorted(p.name for p in output.glob("rules_windows_all*.json")) == [WINDOWS_ALL]
    provenance = json.loads((output / "provenance/windows_all.json").read_text())
    assert provenance["duplicates_removed"] == 2
    assert set(provenance["inputs"]) == set(roots)
    assert provenance["inputs"]["native"]["artifacts"].keys() == {"rules_native_windows_native.json"}
    assert "[rules_windows_all.json](rules_windows_all.json)" in (output / "README.md").read_text()
    gen_ruleset.verify_release(output)

    before = (output / WINDOWS_ALL).read_bytes()
    (output / "rules_unregistered_windows_merged.json").write_text("not an input")
    assert not gen_ruleset.generate(registry, ["community_a"], output, tmp_path / "cache", [], roots)
    assert (output / WINDOWS_ALL).read_bytes() == before
    assert windows_all_files(output, json.loads((output / "release-manifest.json").read_text()))[0][WINDOWS_ALL] == before


def test_partial_updates_use_retained_sources_and_audit_does_not_publish(tmp_path):
    roots = {
        "good": source(tmp_path / "good", [detection()]),
        "bad": source(tmp_path / "bad", [detection(id="8e25d1af-f393-476b-bdb3-b1ad947877c9")]),
    }
    registry = dict.fromkeys(roots, SPEC)
    output = tmp_path / "published"
    args = (registry, list(roots), output, tmp_path / "cache", [], roots)
    assert not gen_ruleset.generate(*args)
    before = (output / WINDOWS_ALL).read_bytes()
    (roots["bad"] / "rules/broken.yaml").write_text("detection: [")
    (roots["good"] / "rules/new.yaml").write_text(yaml.safe_dump(detection(id="7c791d13-e8f4-4463-ba9d-a67bc3ad0d76")))
    assert gen_ruleset.generate(*args, audit=True) == ["bad"]
    assert (output / WINDOWS_ALL).read_bytes() == before
    assert gen_ruleset.generate(*args) == ["bad"]
    combined = json.loads((output / WINDOWS_ALL).read_text())
    assert len(combined) == 6
    manifest = json.loads((output / "release-manifest.json").read_text())
    aggregate = manifest["aggregates"]["windows_all"]
    assert aggregate["status"] == "stale"
    assert aggregate["inputs"]["bad"]["revision"] == manifest["sources"]["bad"]["revision"]
    gen_ruleset.verify_release(output)


def test_bundle_verification_detects_tampering_and_stale_inputs(tmp_path):
    root = source(tmp_path / "source")
    output = tmp_path / "published"
    assert not gen_ruleset.generate({"test": SPEC}, ["test"], output, tmp_path / "cache", [], {"test": root})
    (output / WINDOWS_ALL).write_text("[]")
    with pytest.raises(ValueError, match="hash mismatch"):
        gen_ruleset.verify_release(output)
    gen_ruleset.rebuild_windows_all(output)

    path = output / "release-manifest.json"
    manifest = json.loads(path.read_text())
    name = "rules_test_windows_merged.json"
    changed = json.loads((output / name).read_text())
    changed[0]["title"] = "Updated source metadata"
    raw = json_bytes(changed)
    (output / name).write_bytes(raw)
    manifest["sources"]["test"]["artifacts"][name] = digest(raw)
    gen_ruleset.write_json(path, manifest)
    with pytest.raises(ValueError, match="Combined Windows ruleset is out of date"):
        gen_ruleset.verify_release(output)
    gen_ruleset.rebuild_windows_all(output)
    gen_ruleset.verify_release(output)


def test_bundle_promotion_rolls_back_on_failure(tmp_path, monkeypatch):
    root = source(tmp_path / "source")
    output = tmp_path / "published"
    assert not gen_ruleset.generate({"test": SPEC}, ["test"], output, tmp_path / "cache", [], {"test": root})
    paths = [output / WINDOWS_ALL, output / "provenance/windows_all.json", output / "release-manifest.json"]
    before = {path: path.read_bytes() for path in paths}
    original = gen_ruleset.os.replace
    def fail(src, dst):
        if str(dst).endswith(WINDOWS_ALL):
            raise OSError("Cannot promote bundle")
        return original(src, dst)
    monkeypatch.setattr(gen_ruleset.os, "replace", fail)
    with pytest.raises(OSError, match="Cannot promote bundle"):
        gen_ruleset.rebuild_windows_all(output)
    assert all(path.read_bytes() == raw for path, raw in before.items())
