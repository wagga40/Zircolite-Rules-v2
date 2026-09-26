"""Assert matching behavior, including the experimental correlation contract."""

import json
import os
import re
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import ensure_fields, execute_plan
from sigma.collection import SigmaCollection
from test_generation import SPEC, detection, source

from rule_conversion import compile_source, validate_entry


def convert(documents, **options):
    return json.loads(sqliteBackend(timestamp_field="SystemTime", event_id_field="row_id",
                                   **options).convert(
        SigmaCollection.from_dicts(documents), "zircolite"))


def database(entry, rows):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.create_function("regexp", 2, lambda p, v: bool(v is not None and re.search(p, str(v))))
    connection.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY)")
    ensure_fields(connection, {"logs": sorted(set(entry["required_fields"]) | set().union(*(set(r) for r in rows)))})
    for row in rows:
        fields = ",".join('"' + f.replace('"', '""') + '"' for f in row)
        connection.execute(f"INSERT INTO logs ({fields}) VALUES ({','.join('?' for _ in row)})", tuple(row.values()))
    return connection


@pytest.mark.parametrize("selection,condition,rows,expected", [
    ({"s": {"Image": "evil.exe"}, "filter": {"User": "SYSTEM"}}, "s and not filter",
     [{"Image": "evil.exe"}, {"Image": "evil.exe", "User": "SYSTEM"}], [1]),
    ({"s": {"User|exists": False}}, "s", [{"Image": "anything"}, {"User": "x"}], [1]),
    ({"s": {"Flag": True}}, "s", [{"Flag": "true"}, {"Flag": 1}, {"Flag": 0}], [1, 2]),
    ({"s": {"Group": "admins"}}, "s", [{"Group": "ADMINS"}, {"Group": "users"}], [1]),
    ({"s": {"CommandLine|re": "don't"}}, "s", [{"CommandLine": "don't run"}, {"CommandLine": "run"}], [1]),
    ({"s": {"Image|cased": "a[*]?.exe"}}, "s", [{"Image": "a[*]?.exe"}, {"Image": "abx.exe"}], [1]),
    ({"s": {"EventXML.Address": "::%16777216"}}, "s",
     [{"EventXML.Address": "::%16777216"}, {"EventXML.Address": "::1"}], [1]),
    ({"s": {"EventXML.Param3": "127.0.0.1"}}, "s",
     [{"EventXML.Param3": "127.0.0.1"}, {"EventXML.Param3": "10.0.0.1"}], [1]),
    ({"s": {"New Value|startswith": "HKLM\\"}}, "s",
     [{"New Value": "HKLM\\test"}, {"New Value": "other"}], [1]),
])
def test_detection_matching(selection, condition, rows, expected):
    entry = convert([detection(detection={**selection, "condition": condition})])[0]
    validate_entry(entry)
    connection = database(entry, rows)
    try:
        assert [r["row_id"] for r in connection.execute(entry["rule"][0])] == expected
    finally:
        connection.close()


def test_event_sql_naming_a_collation_is_rejected():
    entry = convert([detection(detection={"s": {"Group": "admins"}, "condition": "s"})], collate_nocase=True)[0]
    assert "COLLATE NOCASE" in entry["rule"][0]
    with pytest.raises(ValueError, match="collation"):
        validate_entry(entry)
    literal = convert([detection(detection={"s": {"CommandLine|contains": "collate"}, "condition": "s"})])[0]
    validate_entry(literal)


@pytest.mark.parametrize("quoted", [False, True])
def test_missing_column_is_rejected_even_with_double_quotes(quoted):
    entry = convert([detection()])[0]
    field = '"missing"' if quoted else "missing"
    entry["rule"] = [f"SELECT * FROM logs WHERE {field}='value'"]
    with pytest.raises(sqlite3.OperationalError, match="no such column"):
        validate_entry(entry)


def test_export_validation_rejects_malformed_attack_tags():
    entry = convert([detection(tags=["attack.11136.001"])])[0]
    with pytest.raises(ValueError, match="Malformed ATT&CK tag"):
        validate_entry(entry)


@pytest.mark.parametrize("profile", ["sysmon", "generic", "native"])
@pytest.mark.parametrize("upstream,column,modifier,value,matching,other", [
    ("EventXML.Address", "Address", "startswith", "::%", "::%16777216", "::1"),
    ("EventXML.Param3", "Param3", "", "127.0.0.1", "127.0.0.1", "10.0.0.1"),
    ("New Value", "NewValue", "startswith", "HKLM\\", "HKLM\\SOFTWARE\\test", "other"),
])
def test_windows_fields_match_zircolite_columns(tmp_path, profile, upstream, column, modifier, value, matching, other):
    field = upstream + ("|" + modifier if modifier else "")
    rule = detection(logsource={"product": "windows"}, detection={
        "s": {field: value}, "condition": "s"})
    outputs, report = compile_source("test", dict(SPEC, profiles=[profile]), source(tmp_path, [rule]), [])
    assert report["status"] == "validated"
    entry, = outputs[profile]["events"]
    assert entry["required_fields"] == [column]
    # Explicit consumer schema: never create columns from compiler metadata,
    # which would conceal a mismatch with Zircolite's flattened event fields.
    with sqlite3.connect(":memory:") as connection:
        connection.execute(f'CREATE TABLE logs(row_id INTEGER PRIMARY KEY, "{column}" TEXT COLLATE NOCASE)')
        connection.executemany(f'INSERT INTO logs("{column}") VALUES (?)', [(matching,), (other,), (None,)])
        assert [r[0] for r in connection.execute(entry["rule"][0])] == [1]


def test_windows_field_mapping_does_not_change_linux_fields(tmp_path):
    rule = detection(logsource={"product": "linux"}, detection={
        "s": {"EventXML.Address": "value"}, "condition": "s"})
    outputs, report = compile_source("test", dict(SPEC, profiles=["linux"]), source(tmp_path, [rule]), [])
    assert report["status"] == "validated"
    assert outputs["linux"]["events"][0]["required_fields"] == ["EventXML.Address"]


def test_long_or_chain_executes():
    entry = convert([detection(detection={
        "selection": {"Image|contains": [f"token{i}" for i in range(4500)]}, "condition": "selection"})])[0]
    validate_entry(entry)
    connection = database(entry, [{"Image": "token4499"}, {"Image": "clean"}])
    try:
        assert [r["row_id"] for r in connection.execute(entry["rule"][0])] == [1]
    finally:
        connection.close()


def correlation(kind="event_count", condition=None, **extra):
    return {"title": "Count example", "id": "05e6ed0a-846c-4b7b-a75c-447b729c2e41",
            "correlation": {"type": kind, "rules": ["base"], "group-by": ["Computer"],
                            "timespan": "5m", "condition": condition or {"gte": 2}, **extra}, "level": "high"}


def event(seconds, **extra):
    timestamp = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return {"SystemTime": timestamp.isoformat(), "Computer": "host", "EventID": 1, **extra}


def definitions(corr=None):
    return [detection(name="base", logsource={"product": "windows", "service": "security"},
                      detection={"s": {"EventID": 1}, "condition": "s"}, level="informational"),
            corr or correlation()]


def test_correlation_windows_thresholds_grouping_evidence_and_standalone_sql():
    entry = convert(definitions())[0]
    validate_entry(entry)
    rows = [event(0), event(60), event(900), event(960), event(960, Computer="other"),
            event(961, Computer=None), event(962, SystemTime="invalid")]
    connection = database(entry, rows)
    try:
        standalone = [dict(row) for row in connection.execute(entry["rule"][0])]
        alerts, diagnostics = execute_plan(connection, entry["correlation_plan"])
        assert len(standalone) == 2
        assert [json.loads(row["event_ids"]) for row in standalone] == [["0:1", "0:2"], ["0:3", "0:4"]]
        assert all(row["metric_value"] == 2 for row in standalone)
        assert [[item["event"]["row_id"] for item in alert["evidence"]] for alert in alerts] == [[1, 2], [3, 4]]
        assert diagnostics == {"invalid_timestamp": 1, "missing_group_key": 1}
        assert "invalid" not in json.dumps(standalone)
    finally:
        connection.close()


def test_reference_only_rules_are_hidden_and_correlations_separate(tmp_path):
    outputs, report = compile_source("test", SPEC, source(tmp_path, definitions()), [])
    assert report["status"] == "validated"
    assert outputs["sysmon"]["events"] == []
    assert len(outputs["sysmon"]["correlations"]) == 1
    entry = outputs["sysmon"]["correlations"][0]
    assert entry["schema_version"] == 2 and entry["result_type"] == "correlation"
    assert "SystemTime" in entry["required_fields"]


def test_generate_true_and_multi_file_references(tmp_path):
    import yaml
    docs = definitions(correlation(generate=True))
    root = source(tmp_path, docs[:1])
    (root / "rules" / "correlation.yml").write_text(yaml.safe_dump(docs[1]))
    outputs, report = compile_source("test", SPEC, root, [])
    assert report["status"] == "validated"
    assert len(outputs["sysmon"]["events"]) == 1
    assert len(outputs["sysmon"]["correlations"]) == 1
    assert outputs["sysmon"]["events"][0]["rule"][0].startswith("SELECT ")


def test_missing_reference_cannot_publish(tmp_path):
    _, report = compile_source("test", SPEC, source(tmp_path, [correlation(), detection()]), [])
    assert report["status"] == "failed"
    assert any(f["stage"] == "references" for f in report["failures"])


def test_ambiguous_expanded_reference_cannot_publish(tmp_path):
    docs = definitions()
    docs[0]["logsource"] = {"product": "windows", "category": ["ps_script", "ps_module"]}
    _, report = compile_source("test", SPEC, source(tmp_path, docs), [])
    assert report["status"] == "failed"
    assert any("2 definitions" in f["error"] for f in report["failures"])


def test_template_dependency_is_excluded_without_rewriting_correlation(tmp_path):
    docs = definitions()
    docs[0]["detection"]["s"]["Computer"] = "%domain_controllers%"
    docs.append(detection(id="bdc1b8b7-8494-4d86-81b8-8c4d4b2cec3c"))
    spec = dict(SPEC, repository="mdecrevoisier/SIGMA-detection-rules")
    outputs, report = compile_source("test", spec, source(tmp_path, docs), [])
    assert report["status"] == "validated"
    assert not outputs["sysmon"]["correlations"]
    assert any("excluded correlation dependency" in e["reason"] for e in report["exclusions"])


def test_correlation_plans_are_reproducible(tmp_path):
    from rule_sources import json_bytes
    root = source(tmp_path, definitions())
    assert json_bytes(compile_source("test", SPEC, root, [])) == json_bytes(compile_source("test", SPEC, root, []))


@pytest.mark.parametrize("dependency", ["outside_profile", "excluded_template", "missing"])
def test_unselected_correlations_do_not_hide_standalone_rules(tmp_path, dependency):
    docs = definitions(correlation("temporal"))
    docs[1]["correlation"]["rules"].append("other")
    spec = dict(SPEC, repository="mdecrevoisier/SIGMA-detection-rules")
    if dependency != "missing":
        other = detection(name="other", id="bf1967d9-9b07-43df-9c9f-0034f6b658b5")
        if dependency == "outside_profile":
            other["logsource"] = {"product": "linux"}
        else:
            other["detection"]["selection"]["Computer"] = "%domain_controllers%"
        docs.append(other)
    root = source(tmp_path, docs)
    outputs, report = compile_source("test", spec, root, [])
    if dependency == "missing":
        assert report["status"] == "failed"
        exclusions = [{**failure, "source": "test", "reason": "Reviewed missing dependency"}
                      for failure in report["failures"]]
        outputs, report = compile_source("test", spec, root, exclusions)
    assert report["status"] == "validated"
    for profile in SPEC["profiles"]:
        assert [rule["id"] for rule in outputs[profile]["events"]] == [docs[0]["id"]]
        assert outputs[profile]["correlations"] == []


def test_official_correlation_baseline_matches_full_and_source_only_runs(tmp_path):
    import gen_ruleset
    roots = {name: source(tmp_path / name, definitions()) for name in ("sigmahq", "community")}
    registry = {name: SPEC for name in roots}
    output = tmp_path / "published"
    assert not gen_ruleset.generate(registry, list(roots), output, tmp_path / "cache", [], roots)
    first = (output / "provenance/community.json").read_bytes()
    manifest = (output / "release-manifest.json").read_bytes()
    report = json.loads(first)
    assert report["official_duplicates_removed"]["sysmon/correlations"] == 1
    baseline = report["official_baseline"]
    assert baseline["revision"].startswith("local-sha256:")
    assert "experimental/rules_windows_sysmon_correlation.json" in baseline["artifacts"]
    assert not list((output / "experimental").glob("rules_community*.json"))
    assert not gen_ruleset.generate(registry, ["community"], output, tmp_path / "cache", [], roots)
    assert (output / "provenance/community.json").read_bytes() == first
    assert (output / "release-manifest.json").read_bytes() == manifest
    gen_ruleset.verify_release(output)


def test_tampered_official_baseline_cannot_update_community(tmp_path):
    import gen_ruleset
    roots = {name: source(tmp_path / name, definitions()) for name in ("sigmahq", "community")}
    registry = {name: SPEC for name in roots}
    output = tmp_path / "published"
    assert not gen_ruleset.generate(registry, list(roots), output, tmp_path / "cache", [], roots)
    previous = (output / "provenance/community.json").read_bytes()
    (output / "experimental/rules_windows_sysmon_correlation.json").write_text("[]")
    assert gen_ruleset.generate(registry, ["community"], output, tmp_path / "cache", [], roots) == ["community"]
    assert (output / "provenance/community.json").read_bytes() == previous
    assert not gen_ruleset.generate(registry, list(roots), output, tmp_path / "cache", [], roots)
    gen_ruleset.verify_release(output)


@pytest.mark.skipif(not os.environ.get("SQLITE_MIN_BINARY"), reason="Set SQLITE_MIN_BINARY to SQLite 3.38 CLI")
@pytest.mark.parametrize("kind", ["event_count", "value_count", "value_sum", "value_avg", "value_median", "value_percentile", "temporal", "temporal_ordered"])
@pytest.mark.parametrize("materialized", [False, True])
def test_minimum_sqlite_correlation_contract(kind, materialized):
    condition = {"gte": 1}
    if kind.startswith("value_"):
        condition["field"] = "Bytes"
    if kind == "value_percentile":
        condition["percentile"] = 50
    docs = definitions(correlation(kind, condition))
    if kind.startswith("temporal"):
        docs[1]["correlation"]["rules"].append("second")
        docs.append(detection(name="second", id="bf1967d9-9b07-43df-9c9f-0034f6b658b5",
                              detection={"s": {"EventID": 2}, "condition": "s"}))
    entry = convert(docs)[0]
    connection = database(entry, [event(0, Bytes=10), event(1, Bytes=20), event(2, EventID=2)])
    expected = [dict(row) for row in connection.execute(entry["rule"][0])]
    script = "\n".join(connection.iterdump()) + "\n"
    connection.close()
    if materialized:
        plan = entry["correlation_plan"]
        for stage in plan["prepare"]:
            script += f'CREATE TEMP TABLE {stage["name"]} AS {stage["select"]};\n'
        script += plan["query"] + ";"
    else:
        script += entry["rule"][0] + ";"
    completed = subprocess.run([os.environ["SQLITE_MIN_BINARY"], "-json", ":memory:"],
                               input=script, text=True, capture_output=True, check=True)
    actual = json.loads(completed.stdout)
    assert [r["metric_value"] for r in actual] == [r["metric_value"] for r in expected]
    assert [json.loads(r["event_ids"]) for r in actual] == [json.loads(r["event_ids"]) for r in expected]
