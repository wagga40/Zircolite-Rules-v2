"""Compare two hash-verified releases rule by rule."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from rule_sources import json_bytes
from ruleset_stats import read_release

CATEGORIES = ("added", "removed", "sql_changed", "metadata_changed")
LABELS = {"added": "Added", "removed": "Removed", "sql_changed": "SQL changed",
          "metadata_changed": "Metadata changed"}


def load_release(output):
    manifest, rulesets = read_release(output)
    return manifest, {row["name"]: json.loads((output / row["name"]).read_bytes()) for row in rulesets}


def variants(rules):
    """Group entries by ID; an ID's SQL variants are its distinct query lists."""
    grouped = defaultdict(dict)
    for rule in rules:
        grouped[rule["id"]][tuple(rule["rule"])] = rule
    return grouped


def summary(rule):
    return {"id": rule["id"], "title": rule.get("title"), "level": rule.get("level")}


def diff_rules(old, new):
    old, new = variants(old), variants(new)
    result = {category: [] for category in CATEGORIES}
    for rule_id in sorted(old.keys() | new.keys()):
        before, after = old.get(rule_id, {}), new.get(rule_id, {})
        if not before:
            result["added"].append(summary(next(iter(after.values()))))
            continue
        if not after:
            result["removed"].append(summary(next(iter(before.values()))))
            continue
        first = next(iter(after.values()))
        if before.keys() != after.keys():
            result["sql_changed"].append({**summary(first), "added": len(after.keys() - before.keys()),
                                          "removed": len(before.keys() - after.keys())})
        fields = sorted({key for sql in before.keys() & after.keys()
                         for key in before[sql].keys() | after[sql].keys()
                         if before[sql].get(key) != after[sql].get(key)})
        if fields:
            result["metadata_changed"].append({**summary(first), "fields": fields})
    return result


def source_state(details):
    return {"status": details["status"], "revision": details.get("revision")} if details else None


def diff_releases(published, candidate):
    (old_manifest, old_sets), (new_manifest, new_sets) = load_release(published), load_release(candidate)
    sources = {}
    for name in sorted(old_manifest["sources"].keys() | new_manifest["sources"].keys()):
        states = [source_state(m["sources"].get(name)) for m in (old_manifest, new_manifest)]
        sources[name] = {"published": states[0], "candidate": states[1], "changed": states[0] != states[1]}
    artifacts, totals = {}, Counter()
    for name in sorted(old_sets.keys() | new_sets.keys()):
        old, new = old_sets.get(name), new_sets.get(name)
        changes = diff_rules(old or [], new or [])
        status = ("added" if old is None else "removed" if new is None
                  else "changed" if any(changes.values()) else "unchanged")
        artifacts[name] = {"status": status, "entries": [len(old or []), len(new or [])], **changes}
        totals.update({category: len(changes[category]) for category in CATEGORIES})
        totals[status] += 1
    return {"sources": sources, "artifacts": artifacts, "totals": dict(sorted(totals.items()))}


def changed(diff):
    return any(item["changed"] for item in diff["sources"].values()) or any(
        item["status"] != "unchanged" for item in diff["artifacts"].values())


def text(value):
    return str(value).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def render_markdown(diff, limit=50):
    lines = ["## Ruleset changes", ""]
    if not changed(diff):
        return "\n".join(lines + ["No source or rule changes.", ""])
    sources = {name: item for name, item in diff["sources"].items() if item["changed"]}
    if sources:
        lines.extend(["| Source | Published | Candidate |", "|---|---|---|"])
        for name, item in sources.items():
            states = [f"{s['status']} `{(s['revision'] or '—')[:12]}`" if s else "—"
                      for s in (item["published"], item["candidate"])]
            lines.append(f"| {name} | {states[0]} | {states[1]} |")
        lines.append("")
    artifacts = {name: item for name, item in diff["artifacts"].items() if item["status"] != "unchanged"}
    if not artifacts:
        return "\n".join(lines + ["No rule changes.", ""])
    lines.extend(["| Ruleset | Status | Entries | Added | Removed | SQL changed | Metadata changed |",
                  "|---|---|---:|---:|---:|---:|---:|"])
    for name, item in artifacts.items():
        counts = " | ".join(f"{len(item[category]):,}" for category in CATEGORIES)
        lines.append(f"| {name} | {item['status']} | {item['entries'][0]:,} → {item['entries'][1]:,} | {counts} |")
    for name, item in artifacts.items():
        lines.extend(["", f"<details><summary>{name}</summary>", ""])
        fields = Counter(field for rule in item["metadata_changed"] for field in rule["fields"])
        if fields:
            lines.append("Changed metadata fields: " + ", ".join(f"`{k}` ({v:,})" for k, v in sorted(fields.items())))
            lines.append("")
        for category in CATEGORIES:
            rules = item[category]
            if not rules:
                continue
            lines.append(f"**{LABELS[category]}**")
            lines.append("")
            for rule in rules[:limit]:
                detail = f" (+{rule['added']}/−{rule['removed']} SQL variants)" if category == "sql_changed" else ""
                lines.append(f"- `{rule['id']}` {text(rule['title'])} [{rule['level']}]{detail}")
            if len(rules) > limit:
                lines.append(f"- … and {len(rules) - limit:,} more")
            lines.append("")
        lines.append("</details>")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("published", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--json", type=Path, help="Also write the full diff as JSON")
    parser.add_argument("--limit", type=int, default=50, help="Rules listed per category and ruleset")
    parser.add_argument("--exit-code", action="store_true", help="Exit 1 when anything changed")
    args = parser.parse_args()
    diff = diff_releases(args.published.resolve(), args.candidate.resolve())
    if args.json:
        args.json.write_bytes(json_bytes(diff))
    sys.stdout.write(render_markdown(diff, args.limit))
    return 1 if args.exit_code and changed(diff) else 0


if __name__ == "__main__":
    sys.exit(main())
