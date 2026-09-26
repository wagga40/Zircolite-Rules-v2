"""Verify published artifacts and render their README statistics without fetching sources."""

import json
import os
import tempfile
from collections import Counter
from pathlib import Path

from rule_bundles import windows_all_files
from rule_conversion import LEVELS
from rule_sources import digest

START = "<!-- ruleset-stats:start -->"
END = "<!-- ruleset-stats:end -->"


def is_ruleset(name):
    path = Path(name)
    return (path.parent in (Path("."), Path("experimental"))
            and path.name.startswith("rules_") and path.suffix == ".json")


def read_release(output):
    """Return statistics only after verifying every manifest-listed artifact."""
    path = output / "release-manifest.json"
    manifest = json.loads(path.read_bytes()) if path.exists() else {}
    if not manifest.get("sources"):
        raise ValueError("No release manifest")
    rulesets = []
    owners = {}
    groups = list(manifest["sources"].items()) + list(manifest.get("aggregates", {}).items())
    for source, details in sorted(groups):
        artifacts = details.get("artifacts", {})
        counts = details.get("rule_counts", {})
        if set(counts) != {name for name in artifacts if is_ruleset(name)}:
            raise ValueError(f"Ruleset count inventory mismatch: {source}")
        for name, expected in sorted(artifacts.items()):
            if Path(name).is_absolute() or ".." in Path(name).parts:
                raise ValueError("Unsafe artifact path")
            if name in owners:
                raise ValueError(f"Artifact has multiple owners: {name}")
            owners[name] = source
            raw = (output / name).read_bytes()
            if digest(raw) != expected:
                raise ValueError(f"Artifact hash mismatch: {source}/{name}")
            if name not in counts:
                continue
            rules = json.loads(raw)
            if not isinstance(rules, list) or len(rules) != counts[name]:
                raise ValueError(f"Rule count mismatch: {source}/{name}")
            if any(not isinstance(rule, dict) or not isinstance(rule.get("id"), str)
                   or not rule["id"] or rule.get("level") not in LEVELS for rule in rules):
                raise ValueError(f"Invalid rule metadata: {source}/{name}")
            # A failed source may still own pre-migration variants. Verify them,
            # but the README inventory advertises only the full rulesets.
            if Path(name).stem.endswith(("_medium", "_high")):
                continue
            levels = Counter(rule["level"] for rule in rules)
            rulesets.append({"source": source, "name": name, "entries": len(rules),
                             "unique_ids": len({rule["id"] for rule in rules}),
                             "levels": {level: levels[level] for level in LEVELS}})
    if "windows_all" in manifest.get("aggregates", {}):
        _, expected = windows_all_files(output, manifest)
        if manifest["aggregates"]["windows_all"] != expected:
            raise ValueError("Combined Windows ruleset is out of date; regenerate the rulesets")
    return manifest, rulesets


def render_statistics(manifest, rulesets):
    lines = [
        "Generated from the hash-verified published artifacts. Entries count exported rule objects;",
        "unique IDs count distinct IDs within each file. Different SQL variants can share an ID.",
        "Profiles overlap, so their counts must not be added to estimate unique threat coverage.",
        "Severity columns are exact levels, not minimum-severity thresholds.",
        "",
        "### Source freshness",
        "",
        "Stale sources retain their last successful files and counts. Unavailable sources have no published rulesets.",
        "",
        "| Source | Status | Published revision | Last successful generation (UTC) |",
        "|---|---|---|---|",
    ]
    for source, details in sorted(manifest["sources"].items(), key=lambda item: (item[0] != "sigmahq", item[0])):
        revision = details.get("revision")
        if revision and not revision.startswith("local-sha256:"):
            revision = f"[{revision[:12]}](https://github.com/{details['repository']}/tree/{revision})"
        elif revision:
            revision = f"`{revision}`"
        lines.append(f"| {source} | {details['status']} | {revision or '—'} | {details.get('last_success', '—')} |")
    if "windows_all" in manifest.get("aggregates", {}):
        status = manifest["aggregates"]["windows_all"]["status"]
        lines.extend(["", f"Combined Windows ruleset status: **{status}**. It includes available published Windows detections; "
                      "stale sources contribute their retained rules, and unavailable sources contribute none."])
    for title, experimental in (("Detection rulesets", False), ("Experimental correlation rulesets", True)):
        lines.extend(["", f"### {title}", ""])
        selected = [row for row in rulesets if row["name"].startswith("experimental/") == experimental]
        if not selected:
            lines.append("No published rulesets.")
            continue
        lines.extend([
            "| Ruleset | Entries | Unique IDs | Informational | Low | Medium | High | Critical |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for row in sorted(selected, key=lambda row: (row["source"] != "windows_all", row["source"] != "sigmahq", row["source"], row["name"])):
            counts = [row["entries"], row["unique_ids"], *(row["levels"][level] for level in LEVELS)]
            lines.append(f"| [{Path(row['name']).name}]({row['name']}) | "
                         + " | ".join(f"{count:,}" for count in counts) + " |")
    return "\n".join(lines)


def readme_with_statistics(output, manifest, rulesets):
    original = (output / "README.md").read_bytes().decode("utf-8")
    if original.count(START) != 1 or original.count(END) != 1 or original.index(START) >= original.index(END):
        raise ValueError("README must contain one ordered pair of ruleset-stats markers")
    before, _, rest = original.partition(START)
    _, _, after = rest.partition(END)
    updated = before + START + "\n\n" + render_statistics(manifest, rulesets) + "\n\n" + END + after
    return original, updated


def update_readme_stats(output):
    manifest, rulesets = read_release(output)
    original, updated = readme_with_statistics(output, manifest, rulesets)
    if original != updated:
        with tempfile.TemporaryDirectory(prefix=".stats-stage-", dir=output) as temporary:
            staged = Path(temporary) / "README.md"
            staged.write_bytes(updated.encode("utf-8"))
            os.replace(staged, output / "README.md")


def verify_release(output):
    manifest, rulesets = read_release(output)
    if (output / "README.md").exists():
        original, updated = readme_with_statistics(output, manifest, rulesets)
        if original != updated:
            raise ValueError("README statistics are out of date; run gen_ruleset.py --update-readme-stats")
