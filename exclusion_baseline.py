"""Propose reviewed exclusion updates after an upstream or toolchain error change.

Only a failure at the exact location of one unused reviewed record is proposed;
new failures are listed for review and never approved.
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from gen_ruleset import write_json
from rule_conversion import approved_failure

LOCATION = ("source", "path", "sha256", "document", "stage", "profile")


def location(item):
    return tuple(item.get(key) for key in LOCATION)


def rebaseline(exclusions, reports):
    audited, skipped, unapproved, used = set(), [], [], set()
    for report in reports:
        # Fetch failures have no per-rule results to compare.
        if "failures" not in report:
            skipped.append(report.get("source"))
            continue
        audited.add(report["source"])
        for failure in report["failures"]:
            failure = {**failure, "source": report["source"]}
            matches = {index for index, item in enumerate(exclusions)
                       if approved_failure(report["source"], failure, [item])}
            used |= matches
            if not matches:
                unapproved.append(failure)
    unused = defaultdict(list)
    for index, item in enumerate(exclusions):
        if item.get("source") in audited and index not in used:
            unused[location(item)].append(index)
    failures = defaultdict(list)
    for failure in unapproved:
        failures[location(failure)].append(failure)
    proposals, new_failures = [], []
    for key, matches in failures.items():
        if len(matches) == 1 and len(unused.get(key, [])) == 1:
            index = unused.pop(key)[0]
            proposals.append({"index": index, **dict(zip(LOCATION, key, strict=True)),
                              "old": exclusions[index]["error"], "new": matches[0]["error"]})
        else:
            new_failures.extend(matches)
    stale = [{"index": index, **exclusions[index]} for indexes in unused.values() for index in indexes]
    return {"proposals": sorted(proposals, key=lambda item: item["index"]),
            "new_failures": sorted(new_failures, key=location),
            "stale": sorted(stale, key=lambda item: item["index"]), "skipped": sorted(skipped)}


def apply(exclusions, result, prune=False):
    updated = [dict(item) for item in exclusions]
    for proposal in result["proposals"]:
        updated[proposal["index"]]["error"] = proposal["new"]
    removed = {item["index"] for item in result["stale"]} if prune else set()
    return [item for index, item in enumerate(updated) if index not in removed]


def render_markdown(result):
    lines = ["## Exclusion baseline", ""]
    groups = defaultdict(list)
    for proposal in result["proposals"]:
        groups[proposal["old"], proposal["new"]].append(proposal)
    lines.append(f"{len(result['proposals'])} proposed message updates, {len(result['new_failures'])} new "
                 f"failures, {len(result['stale'])} unused records, {len(result['skipped'])} skipped sources.")
    for (old, new), proposals in sorted(groups.items(), key=lambda item: -len(item[1])):
        sources = sorted({proposal["source"] for proposal in proposals})
        lines.extend(["", f"### {len(proposals)} records ({', '.join(sources)})", "",
                      "```diff", f"- {old}", f"+ {new}", "```"])
    for title, items in (("New failures (need a fix or a reviewed record)", result["new_failures"]),
                         ("Unused records (prune with --prune)", result["stale"])):
        if items:
            lines.extend(["", f"### {title}", ""])
            lines.extend(f"- {item['source']} `{item['path']}` #{item['document']} {item['stage']}/{item['profile']}: "
                         f"{item['error'].splitlines()[0]}" for item in items)
    if result["skipped"]:
        lines.extend(["", "Skipped (no per-rule results): " + ", ".join(result["skipped"])])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", type=Path, help="Report directory of an --audit or generation run")
    parser.add_argument("--exclusions", type=Path, default=Path(__file__).resolve().parent / "exclusions.json")
    parser.add_argument("--apply", action="store_true", help="Write the proposed message updates")
    parser.add_argument("--prune", action="store_true", help="With --apply, also remove unused records")
    parser.add_argument("--json", type=Path, help="Also write the full result as JSON")
    parser.add_argument("--exit-code", action="store_true", help="Exit 1 when anything needs review")
    args = parser.parse_args()
    if args.prune and not args.apply:
        parser.error("--prune requires --apply")
    exclusions = json.loads(args.exclusions.read_bytes())
    reports = [json.loads(path.read_bytes()) for path in sorted(args.reports.glob("*.json"))]
    result = rebaseline(exclusions, reports)
    if args.json:
        write_json(args.json, result)
    if args.apply:
        write_json(args.exclusions, apply(exclusions, result, args.prune))
    sys.stdout.write(render_markdown(result))
    return 1 if args.exit_code and any(result[key] for key in ("proposals", "new_failures", "stale")) else 0


if __name__ == "__main__":
    sys.exit(main())
