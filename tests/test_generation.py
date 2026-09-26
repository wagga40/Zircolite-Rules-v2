import json
import uuid
from copy import deepcopy

import pytest
import yaml

import gen_ruleset
from rule_conversion import artifact_rules, compile_source, merge_rulesets
from rule_sources import Document, adapt, json_bytes

SPEC = {"repository": "example/rules", "branch": "main", "directories": ["rules"],
        "adapter": "community", "profiles": ["sysmon", "generic"],
        "license": "MIT", "license_file": "LICENSE"}


def detection(**changes):
    value = {
        "title": "Example", "id": "6b575854-347f-44cc-a48b-1e4e1e62f569",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Image|endswith": "\\evil.exe"}, "condition": "selection"},
        "level": "high",
    }
    value.update(changes)
    return value


def source(tmp_path, documents=None):
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "rules").mkdir(exist_ok=True)
    (tmp_path / "LICENSE").write_text("Test license\n")
    (tmp_path / "rules" / "example.yaml").write_text(yaml.safe_dump_all(documents or [detection()]))
    return tmp_path


def test_all_conditions_and_profile_variants_are_preserved(tmp_path):
    value = detection(detection={"a": {"Image": "a.exe"}, "b": {"Image": "b.exe"}, "condition": ["a", "b"]})
    outputs, report = compile_source("test", SPEC, source(tmp_path, [value]), [])
    assert report["status"] == "validated"
    assert len(outputs["sysmon"]["events"]) == 2
    assert len(outputs["generic"]["events"]) == 2
    merged = merge_rulesets(outputs["sysmon"]["events"], outputs["generic"]["events"])
    assert len(merged) == 4
    assert len({tuple(r["rule"]) for r in merged}) == 4


def test_unbounded_channel_is_not_discarded(tmp_path):
    rule = detection(logsource={"product": "windows"}, detection={
        "a": {"EventID": 1}, "b": {"Channel": "Security"}, "condition": "a or b"})
    outputs, report = compile_source("test", SPEC, source(tmp_path, [rule]), [])
    assert report["status"] == "validated"
    assert outputs["sysmon"]["events"][0]["channel"] == []


def test_profiles_exclude_unmapped_categories_and_wrong_platforms(tmp_path):
    rules = [detection(), detection(id=str(uuid.uuid4()), logsource={"product": "linux"}),
             detection(id=str(uuid.uuid4()), logsource={"product": "windows", "category": "file_event"})]
    outputs, report = compile_source("test", SPEC, source(tmp_path, rules), [])
    assert len(outputs["sysmon"]["events"]) == 2
    assert len(outputs["generic"]["events"]) == 1
    assert report["exclusions"]


def test_metadata_adapter_has_stable_id_and_preserves_original():
    data = detection(id=123, tags=["sysmon", "attack.t1003"], references="https://example.org",
                     logsource={"product": "windows", "category": ["ps_script", "ps_module"]})
    document = Document("rules/example.yaml", "abc", "0", data)
    variants = adapt(document, SPEC)
    assert data["id"] == 123
    assert len(variants) == 2
    assert variants[0].changes["tags"]["original"] == ["sysmon", "attack.t1003"]
    assert variants[0].data["references"] == ["https://example.org"]
    assert {v.data["id"] for v in variants} == {v.data["id"] for v in adapt(document, SPEC)}
    assert len({v.data["id"] for v in variants}) == 2


def test_exact_official_overlap_only_and_full_rulesets(tmp_path):
    outputs, _ = compile_source("test", SPEC, source(tmp_path), [])
    official = deepcopy(outputs)
    official["sysmon"]["events"][0]["rule"] = ["SELECT * FROM logs WHERE 0"]
    artifacts, overlap = artifact_rules("test", outputs, official)
    assert overlap["generic/events"] == 1
    assert "rules_test_windows_sysmon.json" in artifacts
    assert "rules_test_windows_generic.json" not in artifacts
    assert all(name.startswith("rules_test_") for name in artifacts)
    assert not any(name.endswith(("_high.json", "_medium.json")) for name in artifacts)
    assert all(rule["level"] == "high" for rules in artifacts.values() for rule in rules)


def test_hash_bound_exclusions_do_not_hide_changed_errors(tmp_path):
    root = source(tmp_path)
    broken = root / "rules" / "broken.yml"
    broken.write_text("title: Broken\ndetection: [\n")
    _, report = compile_source("test", SPEC, root, [])
    assert report["status"] == "failed"
    exclusions = [{**f, "source": "test", "reason": "Reviewed invalid YAML"} for f in report["failures"]]
    _, report = compile_source("test", SPEC, root, exclusions)
    assert report["status"] == "validated"
    broken.write_text(broken.read_text() + "# upstream changed\n")
    _, report = compile_source("test", SPEC, root, exclusions)
    assert report["status"] == "failed"


def test_reproducible_corpus_output(tmp_path):
    root = source(tmp_path)
    first = compile_source("test", SPEC, root, [])
    second = compile_source("test", SPEC, root, [])
    assert json_bytes(first) == json_bytes(second)


def test_failed_source_retains_previous_success_while_other_source_updates(tmp_path):
    roots = {name: source(tmp_path / name) for name in ("good", "bad")}
    registry = {name: SPEC for name in roots}
    output = tmp_path / "published"
    assert not gen_ruleset.generate(registry, list(roots), output, tmp_path / "cache", [], roots)
    before = (output / "rules_bad_windows_sysmon.json").read_bytes()
    previous = json.loads((output / "release-manifest.json").read_text())["sources"]["bad"]
    (roots["bad"] / "rules" / "bad.yml").write_text("detection: [")
    (roots["good"] / "rules" / "example.yaml").write_text(yaml.safe_dump(detection(title="Updated")))
    assert gen_ruleset.generate(registry, list(roots), output, tmp_path / "cache", [], roots) == ["bad"]
    assert (output / "rules_bad_windows_sysmon.json").read_bytes() == before
    manifest = json.loads((output / "release-manifest.json").read_text())
    assert manifest["sources"]["bad"]["status"] == "stale"
    assert manifest["sources"]["bad"]["revision"] == previous["revision"]
    assert manifest["sources"]["good"]["status"] == "current"
    assert json.loads((output / "rules_good_windows_sysmon.json").read_text())[0]["title"] == "Updated"


def test_fetch_failure_and_empty_source_cannot_publish(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise TimeoutError("Source unavailable")
    monkeypatch.setattr(gen_ruleset, "fetch_source", fail)
    assert gen_ruleset.generate({"test": SPEC}, ["test"], tmp_path, tmp_path / "cache", []) == ["test"]
    assert not list(tmp_path.glob("rules_*.json"))
    empty = source(tmp_path / "empty")
    (empty / "rules" / "example.yaml").unlink()
    assert gen_ruleset.generate({"test": SPEC}, ["test"], tmp_path, tmp_path / "cache", [], {"test": empty}) == ["test"]


def test_audit_never_promotes_and_does_not_change_manifest(tmp_path):
    root = source(tmp_path / "source")
    output = tmp_path / "output"
    assert not gen_ruleset.generate({"test": SPEC}, ["test"], output, tmp_path / "cache", [], {"test": root}, audit=True)
    assert not list(output.glob("rules_*.json"))
    assert not (output / "release-manifest.json").exists()
    assert (output / "reports" / "test.json").exists()


def test_promotion_rolls_back_files_on_error(tmp_path, monkeypatch):
    (tmp_path / "first.json").write_bytes(b"old")
    real_replace = gen_ruleset.os.replace
    def fail_once(src, dst):
        if str(dst).endswith("second.json"):
            raise OSError("Simulated disk failure")
        return real_replace(src, dst)
    monkeypatch.setattr(gen_ruleset.os, "replace", fail_once)
    with pytest.raises(OSError):
        gen_ruleset.promote(tmp_path, {"first.json": b"new", "second.json": b"new"}, ["first.json"])
    assert (tmp_path / "first.json").read_bytes() == b"old"
    assert not (tmp_path / "second.json").exists()


def test_changed_sql_fails_validation_before_release(tmp_path, monkeypatch):
    from rule_conversion import sqliteBackend
    original = sqliteBackend.convert_rule
    def invalid(self, *args, **kwargs):
        entries = original(self, *args, **kwargs)
        entries[0]["rule"] = ["SELECT FROM logs"]
        return entries
    monkeypatch.setattr(sqliteBackend, "convert_rule", invalid)
    _, report = compile_source("test", SPEC, source(tmp_path), [])
    assert report["status"] == "failed"
    assert all(f["stage"] == "validate" for f in report["failures"])


def test_release_hash_gate_rejects_changed_artifact(tmp_path):
    root = source(tmp_path / "source")
    output = tmp_path / "published"
    gen_ruleset.generate({"test": SPEC}, ["test"], output, tmp_path / "cache", [], {"test": root})
    gen_ruleset.verify_release(output)
    (output / "rules_test_windows_sysmon.json").write_text("[]")
    with pytest.raises(ValueError, match="hash mismatch"):
        gen_ruleset.verify_release(output)


def test_full_rulesets_preserve_every_severity(tmp_path):
    from rule_conversion import LEVELS
    docs = [detection(id=str(uuid.uuid4()), level=level) for level in LEVELS]
    outputs, report = compile_source("test", SPEC, source(tmp_path, docs), [])
    assert report["status"] == "validated"
    artifacts, _ = artifact_rules("test", outputs, {})
    assert len(artifacts) == 3
    assert all({rule["level"] for rule in rules} == set(LEVELS) for rules in artifacts.values())


@pytest.mark.parametrize("product", ["Windows", "WINDOWS", "Linux", ["Windows", "LINUX"]])
def test_product_capitalization_is_normalized_with_provenance(tmp_path, product):
    spec = dict(SPEC, profiles=["sysmon", "linux"])
    value = detection(logsource={"product": product})
    outputs, report = compile_source("test", spec, source(tmp_path, [value]), [])
    assert report["status"] == "validated"
    expected = {p.lower() for p in product} if isinstance(product, list) else {product.lower()}
    for profile, platform in (("sysmon", "windows"), ("linux", "linux")):
        assert bool(outputs[profile]["events"]) == (platform in expected)
    assert all(p["adaptations"]["logsource"]["original"]["product"] == product for p in report["provenance"])
    assert value["logsource"]["product"] == product


def test_product_normalization_does_not_change_official_or_unknown_products():
    for spec, product in ((dict(SPEC, adapter="sigmahq"), "Windows"), (SPEC, "CustomOS")):
        value = detection(logsource={"product": product})
        assert adapt(Document("rule.yml", "hash", "0", value), spec)[0].data["logsource"]["product"] == product


@pytest.mark.parametrize("action", ["correlation", "global", "reset", "repeat"])
def test_unsupported_actions_are_reviewable_failures(tmp_path, action):
    action_doc = {"action": action, "title": "Legacy content"}
    root = source(tmp_path, [detection(), action_doc])
    _, report = compile_source("test", SPEC, root, [])
    assert report["status"] == "failed"
    assert report["ignored"] == []
    failure, = report["failures"]
    assert (failure["stage"], failure["document"], failure["profile"]) == ("discovery", "1", "*")
    assert failure["error"] == f"Unsupported Sigma collection action: {action!r}"
    exclusion = {**failure, "source": "test", "reason": "Reviewed unsupported collection action"}
    _, report = compile_source("test", SPEC, root, [exclusion])
    assert report["status"] == "validated"
    (root / "rules" / "example.yaml").write_text(yaml.safe_dump_all([detection(), dict(action_doc, title="Changed")]))
    _, report = compile_source("test", SPEC, root, [exclusion])
    assert report["status"] == "failed"


@pytest.mark.parametrize("recorded", [False, True])
def test_retired_variants_are_removed_only_after_success(tmp_path, recorded):
    from rule_sources import digest
    root = source(tmp_path / "source")
    output = tmp_path / "published"
    registry = {"test": SPEC}
    args = (registry, ["test"], output, tmp_path / "cache", [])
    assert not gen_ruleset.generate(*args, {"test": root})
    retired = "rules_test_windows_generic_high.json"
    data = (output / "rules_test_windows_generic.json").read_bytes()
    (output / retired).write_bytes(data)
    experimental = output / "experimental" / "rules_test_windows_merged_correlation_medium.json"
    experimental.parent.mkdir(exist_ok=True)
    experimental.write_text("[]")
    unrelated = output / "notes_high.json"
    unrelated.write_text("keep me")
    if recorded:
        path = output / "release-manifest.json"
        manifest = json.loads(path.read_text())
        details = manifest["sources"]["test"]
        details["artifacts"][retired] = digest(data)
        details["rule_counts"][retired] = 1
        gen_ruleset.write_json(path, manifest)
    broken = root / "rules" / "broken.yaml"
    broken.write_text("detection: [")
    assert gen_ruleset.generate(*args, {"test": root}) == ["test"]
    assert (output / retired).read_bytes() == data
    assert experimental.exists()
    broken.unlink()
    assert not gen_ruleset.generate(*args, {"test": root}, audit=True)
    assert (output / retired).exists() and experimental.exists()
    assert not gen_ruleset.generate(*args, {"test": root})
    assert not (output / retired).exists() and not experimental.exists()
    assert unrelated.read_text() == "keep me"
    manifest = json.loads((output / "release-manifest.json").read_text())
    assert retired not in manifest["sources"]["test"]["artifacts"]
    assert retired not in manifest["sources"]["test"]["rule_counts"]
    gen_ruleset.verify_release(output)


def test_retirement_is_rolled_back_on_promotion_error(tmp_path, monkeypatch):
    root = source(tmp_path / "source")
    output = tmp_path / "published"
    args = ({"test": SPEC}, ["test"], output, tmp_path / "cache", [], {"test": root})
    assert not gen_ruleset.generate(*args)
    retired = output / "rules_test_windows_generic_high.json"
    retired.write_bytes(b"old variant")
    original = gen_ruleset.os.replace
    def fail(src, dst):
        if str(dst).endswith("rules_test_windows_sysmon.json"):
            raise OSError("Simulated promotion failure")
        return original(src, dst)
    monkeypatch.setattr(gen_ruleset.os, "replace", fail)
    assert gen_ruleset.generate(*args) == ["test"]
    assert retired.read_bytes() == b"old variant"
    assert json.loads((output / "release-manifest.json").read_text())["sources"]["test"]["status"] == "stale"
