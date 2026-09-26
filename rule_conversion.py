"""Profile selection, dependency-aware conversion, and executable SQL validation."""

import re
import sqlite3
from collections import Counter, defaultdict
from copy import deepcopy
from functools import lru_cache

from sigma.backends.sqlite import sqliteBackend
from sigma.backends.sqlite.runtime import ensure_fields, execute_plan
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_audit_pipeline, windows_logsource_pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from rule_sources import adapt, read_documents, template_reason, validate_attack_tags

LEVELS = ["informational", "low", "medium", "high", "critical"]


def artifact_name(source, profile, kind):
    prefix = "rules" if source == "sigmahq" else f"rules_{source}"
    base = f"{prefix}_linux" if profile == "linux" else f"{prefix}_windows_{profile}"
    return f"experimental/{base}_correlation.json" if kind == "correlations" else f"{base}.json"


def retired_artifacts(source, profiles):
    """Known severity variants, including files predating the release manifest."""
    profiles = set(profiles)
    if {"sysmon", "generic"} <= profiles:
        profiles.add("merged")
    return {
        artifact_name(source, profile, kind).removesuffix(".json") + suffix + ".json"
        for profile in profiles
        for kind in ("events", "correlations")
        for suffix in ("_medium", "_high")
    }


def pipeline_for(profile):
    # These upstream aliases refer to Windows event leaves. Zircolite uses
    # the leaf name and removes punctuation/spaces when flattening events.
    windows_fields = ProcessingPipeline(items=[ProcessingItem(
        FieldMappingTransformation({"EventXML.Address": "Address", "EventXML.Param3": "Param3",
                                    "New Value": "NewValue"}),
        identifier="zircolite_windows_fields",
    )])
    if profile == "sysmon":
        return sysmon_pipeline() + windows_logsource_pipeline() + windows_fields
    if profile == "generic":
        return windows_audit_pipeline() + windows_logsource_pipeline() + windows_fields
    if profile == "native":
        return windows_fields
    if profile == "linux":
        return None
    raise ValueError(f"Unknown profile: {profile}")


@lru_cache
def logsource_conditions(profile):
    return tuple(condition for item in pipeline_for(profile).items
                 for condition in item.rule_conditions if isinstance(condition, LogsourceCondition))


def detection_fields(detection):
    if getattr(detection, "field", None):
        yield detection.field
    for item in getattr(detection, "detection_items", []):
        yield from detection_fields(item)


def applicable(rule, profile):
    product = rule.logsource.product
    if product != ("linux" if profile == "linux" else "windows"):
        return False, f"logsource product {product!r} is outside this profile"
    if profile in ("native", "linux"):
        return True, ""
    source = rule.logsource
    # Explicit Windows event fields need no invented Channel restriction.
    if any("Channel" in set(detection_fields(d)) for d in rule.detection.detections.values()):
        return True, ""
    if source.category is None and source.service is None:
        return True, ""
    for condition in logsource_conditions(profile):
        if condition.match(rule):
            return True, ""
    return False, "no mapping for logsource in this profile"


def sql_tokens(query):
    """Split SQL into string/identifier literals, words and single characters."""
    for match in re.finditer(r"'(?:''|[^'])*'|`(?:``|[^`])*`|\"(?:\"\"|[^\"])*\"|\w+|[^\s]", query):
        yield match.group()


def sql_regexes(query):
    """Read regex literals outside other SQL string/identifier literals."""
    previous = ""
    for token in sql_tokens(query):
        if previous.upper() == "REGEXP" and token.startswith("'"):
            yield token[1:-1].replace("''", "'")
        previous = token


def validate_entry(entry):
    if entry.get("schema_version") != 2:
        raise ValueError("Expected backend schema_version 2")
    if not entry.get("id") or not entry.get("title") or entry.get("level") not in LEVELS:
        raise ValueError("Invalid required rule metadata")
    if not isinstance(entry.get("required_fields"), list):
        raise ValueError("Missing required_fields")
    if not isinstance(entry.get("rule"), list) or not entry["rule"]:
        raise ValueError("Rule contains no queries")
    validate_attack_tags(entry.get("tags", []))
    connection = sqlite3.connect(":memory:")
    # Do not let a missing double-quoted column silently become a string.
    connection.setconfig(sqlite3.SQLITE_DBCONFIG_DQS_DML, False)
    connection.create_function("regexp", 2, lambda p, v: bool(v is not None and re.search(p, str(v))))
    try:
        connection.execute("CREATE TABLE logs(row_id INTEGER PRIMARY KEY)")
        for query in entry["rule"]:
            for pattern in sql_regexes(query):
                re.compile(pattern)
        if entry.get("result_type") == "correlation":
            if sqlite3.sqlite_version_info < (3, 38):
                raise ValueError("Correlations require SQLite >=3.38")
            plan = entry["correlation_plan"]
            ensure_fields(connection, plan["required_fields"])
            for query in entry["rule"]:
                connection.execute("EXPLAIN " + query).fetchall()
            execute_plan(connection, plan, include_events=False)
        elif entry.get("result_type") == "event":
            if entry.get("source_table") != "logs":
                raise ValueError("Zircolite detection table must be logs")
            # Zircolite declares every column NOCASE; an explicit collation is
            # either redundant or changes what the rule matches.
            if any(token.upper() == "COLLATE" for query in entry["rule"] for token in sql_tokens(query)):
                raise ValueError("Event SQL must not name a collation")
            ensure_fields(connection, {"logs": entry["required_fields"]})
            for query in entry["rule"]:
                connection.execute("EXPLAIN " + query).fetchall()
        else:
            raise ValueError("Unknown result_type")
    finally:
        connection.close()


def identity(entry):
    # Backend-generated SQL is canonical. Do not collapse whitespace inside literals.
    return entry["id"], tuple(entry["rule"])


def sort_rules(rules):
    return sorted(rules, key=lambda r: (LEVELS.index(r["level"]), r["id"], tuple(r["rule"]), r["title"]))


def deduplicate(rules):
    found = {}
    for rule in rules:
        found.setdefault(identity(rule), rule)
    return sort_rules(found.values())


def merge_rulesets(sysmon, generic):
    rules = deduplicate([*generic, *sysmon])
    variants = Counter(rule["id"] for rule in rules)
    generic_keys = {identity(rule) for rule in generic}
    return [dict(rule, title=rule["title"] + (
        " - Generic" if identity(rule) in generic_keys else " - Sysmon"
    )) if variants[rule["id"]] > 1 else rule for rule in rules]


def error_record(document, stage, profile, error):
    return {**document.location(), "stage": stage, "profile": profile, "error": str(error)}


def approved_failure(source, failure, exclusions):
    keys = ("path", "sha256", "document", "stage", "profile", "error")
    return any(item.get("source") == source and all(item.get(k) == failure.get(k) for k in keys)
               and item.get("reason") for item in exclusions)


def compile_source(source, spec, root, exclusions):
    documents, failures, ignored = read_documents(root, spec)
    report = {"source": source, "input_documents": len(documents), "ignored": ignored,
              "exclusions": [], "failures": failures, "provenance": [], "profiles": {}}
    parsed = []
    excluded_references = {}
    for original in documents:
        try:
            variants = adapt(original, spec)
        except Exception as exc:
            failures.append(error_record(original, "adapt", "*", exc))
            continue
        for document in variants:
            report["provenance"].append({**document.location(), "id": document.data.get("id"),
                                         "adaptations": document.changes})
            reason = template_reason(document, spec)
            if document.data.get("status") in ("deprecated", "unsupported"):
                reason = "excluded upstream status: " + document.data["status"]
            if reason:
                report["exclusions"].append({**document.location(), "profile": "*", "reason": reason})
                for reference in (document.data.get("id"), document.data.get("name")):
                    if reference:
                        excluded_references[reference] = reason
                continue
            try:
                rules = SigmaCollection.from_dicts([deepcopy(document.data)], resolve_references=False).rules
                if len(rules) != 1:
                    raise ValueError("Expected one rule per adapted document")
                parsed.append((rules[0], document))
            except Exception as exc:
                failures.append(error_record(document, "parse", "*", exc))

    outputs = {}
    for profile in spec["profiles"]:
        pairs = deepcopy(parsed)
        by_reference = defaultdict(list)
        for rule, document in pairs:
            for reference in {str(rule.id), rule.name} - {None, ""}:
                by_reference[reference].append(rule)
        eligibility = {}

        def eligible(rule, stack=()):
            key = id(rule)
            if key in eligibility:
                return eligibility[key]
            if key in stack:
                raise ValueError("Cyclic correlation reference")
            if not isinstance(rule, SigmaCorrelationRule):
                result = applicable(rule, profile)
            else:
                names = [ref.reference for ref in rule.rules] if rule.rules is not None else list(
                    rule.condition.get_referenced_rules()
                )
                result = (True, "")
                for name in names:
                    candidates = by_reference[name]
                    if not candidates and name in excluded_references:
                        result = (False, "excluded correlation dependency: " + excluded_references[name])
                        continue
                    if len(candidates) != 1:
                        raise ValueError(f"Correlation reference {name!r} has {len(candidates)} definitions")
                    child = candidates[0]
                    allowed, reason = eligible(child, (*stack, key))
                    if not allowed:
                        result = (False, "correlation dependency outside profile: " + reason)
            eligibility[key] = result
            return result

        selected = []
        origins = {}
        for rule, document in pairs:
            try:
                allowed, reason = eligible(rule)
            except Exception as exc:
                failures.append(error_record(document, "references", profile, exc))
                continue
            if allowed:
                selected.append(rule)
                origins[id(rule)] = document
            else:
                report["exclusions"].append({**document.location(), "profile": profile, "reason": reason})
        # Only selected correlations may hide their dependencies. Eligibility
        # checks must not change the output of an otherwise standalone rule.
        collection = SigmaCollection(selected)
        collection.resolve_rule_references()
        backend = sqliteBackend(pipeline_for(profile), timestamp_field="SystemTime",
                                timestamp_format="iso", event_id_field="row_id")
        backend.init_processing_pipeline("zircolite")
        events, correlations, converted, reference_only = [], [], 0, 0
        for rule in collection:
            document = origins[id(rule)]
            try:
                is_correlation = isinstance(rule, SigmaCorrelationRule)
                entries = (backend.convert_correlation_rule(rule, "zircolite") if is_correlation
                           else backend.convert_rule(rule, "zircolite"))
                converted += 1
                if not rule._output:
                    reference_only += 1
                    continue
            except Exception as exc:
                failures.append(error_record(document, "convert", profile, exc))
                continue
            for entry in entries:
                try:
                    entry["filename"] = document.path
                    validate_entry(entry)
                    (correlations if is_correlation else events).append(entry)
                except Exception as exc:
                    failures.append(error_record(document, "validate", profile, exc))
        outputs[profile] = {"events": deduplicate(events), "correlations": deduplicate(correlations)}
        report["profiles"][profile] = {
            "eligible": len(selected), "converted": converted, "reference_only": reference_only,
            "events": len(outputs[profile]["events"]), "correlations": len(outputs[profile]["correlations"]),
        }
    for failure in failures:
        failure["approved"] = bool(approved_failure(source, failure, exclusions))
    report["status"] = "failed" if any(not f["approved"] for f in failures) else "validated"
    if not any(result["events"] or result["correlations"] for result in outputs.values()):
        report["status"] = "failed"
        report["error"] = "Source produced no validated rules"
    return outputs, report


def artifact_rules(source, outputs, official):
    """Keep source namespaces separate and remove only exact official duplicates."""
    result, overlap = {}, {}
    for profile, categories in outputs.items():
        for kind, rules in categories.items():
            keys = {identity(rule) for rule in official.get(profile, {}).get(kind, [])}
            kept = [rule for rule in rules if identity(rule) not in keys]
            overlap[f"{profile}/{kind}"] = len(rules) - len(kept)
            result.setdefault(profile, {})[kind] = kept
    if "sysmon" in result and "generic" in result:
        result["merged"] = {
            kind: merge_rulesets(result["sysmon"][kind], result["generic"][kind])
            for kind in ("events", "correlations")
        }
    artifacts = {}
    for profile, kinds in result.items():
        for kind, rules in kinds.items():
            if not rules and (source != "sigmahq" or kind == "correlations"):
                continue
            artifacts[artifact_name(source, profile, kind)] = rules
    return artifacts, overlap
