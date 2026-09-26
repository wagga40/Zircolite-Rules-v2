"""Build cross-source rulesets from published, hash-verified detection inputs."""

import json
from pathlib import Path

from rule_conversion import artifact_name, deduplicate
from rule_sources import digest, json_bytes

WINDOWS_ALL = "rules_windows_all.json"
WINDOWS_ALL_PROVENANCE = "provenance/windows_all.json"


def windows_all_files(output, manifest):
    rules, inputs = [], {}
    for source, details in sorted(manifest["sources"].items(), key=lambda item: (item[0] != "sigmahq", item[0])):
        published = details.get("rule_counts", {})
        merged = artifact_name(source, "merged", "events")
        profiles = ("merged", "native") if merged in published else ("sysmon", "generic", "native")
        names = [artifact_name(source, profile, "events") for profile in profiles
                 if artifact_name(source, profile, "events") in published]
        inputs[source] = {
            "repository": details["repository"], "revision": details.get("revision"),
            "status": details["status"], "license": details.get("license"),
            "artifacts": {name: details["artifacts"][name] for name in names},
        }
        for name in names:
            if Path(name).is_absolute() or ".." in Path(name).parts:
                raise ValueError("Unsafe artifact path")
            raw = (output / name).read_bytes()
            if digest(raw) != details["artifacts"][name]:
                raise ValueError(f"Windows bundle input hash mismatch: {source}/{name}")
            entries = json.loads(raw)
            if not isinstance(entries, list) or len(entries) != published[name]:
                raise ValueError(f"Windows bundle input count mismatch: {source}/{name}")
            if any(rule.get("result_type") != "event" or rule.get("logsource", {}).get("product") != "windows"
                   for rule in entries):
                raise ValueError(f"Expected only Windows detections: {name}")
            rules.extend(entries)
    if not rules:
        return {}, None
    combined = deduplicate(rules)
    status = "current" if all(item["status"] == "current" for item in inputs.values()) else "stale"
    provenance = {
        "name": "windows_all", "status": status, "inputs": inputs,
        "input_entries": len(rules), "entries": len(combined),
        "duplicates_removed": len(rules) - len(combined),
        "deduplication": "Same ID and SQL; prefer SigmaHQ, then source name order. Distinct SQL variants remain.",
    }
    files = {WINDOWS_ALL: json_bytes(combined), WINDOWS_ALL_PROVENANCE: json_bytes(provenance)}
    details = {"status": status, "inputs": inputs,
               "artifacts": {name: digest(raw) for name, raw in files.items()},
               "rule_counts": {WINDOWS_ALL: len(combined)}}
    return files, details
