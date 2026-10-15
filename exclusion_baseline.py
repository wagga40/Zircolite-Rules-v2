"""Propose reviewed exclusion updates after an upstream or toolchain change.

A failure is paired with one unused reviewed record when only one field
differs: the error text at the same rule content (a toolchain rewording), or
the content hash with the same error (an upstream edit that fails as reviewed).
Anything else is listed for review and never approved.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from gen_ruleset import write_json
from rule_conversion import approved_failure

LOCATION = ("source", "path", "sha256", "document", "stage", "profile")
# The record's identity across an upstream edit: everything but the content hash.
CONTENT = ("source", "path", "document", "stage", "profile", "error")


def location(item):
    return tuple(item.get(key) for key in LOCATION)


def content(item):
    return tuple(item.get(key) for key in CONTENT)


def fenced(lines, info=""):
    """A fenced block no line of upstream text can close."""
    text = "\n".join(lines)
    fence = "~" * max(3, 1 + max((len(run) for run in re.findall(r"~+", text)), default=0))
    return f"{fence}{info}\n{text}\n{fence}"


def pair(failures, unused, exclusions, key, field):
    """Pair each failure with the one unused record that shares its key."""
    records, grouped = defaultdict(list), defaultdict(list)
    for index in unused:
        records[key(exclusions[index])].append(index)
    for failure in failures:
        grouped[key(failure)].append(failure)
    proposals, remaining = [], []
    for value, matches in grouped.items():
        if len(matches) == 1 and len(records.get(value, [])) == 1:
            index = records[value][0]
            unused.remove(index)
            proposals.append({"index": index, "field": field, **dict(zip(LOCATION, location(matches[0]), strict=True)),
                              "error": matches[0]["error"], "old": exclusions[index][field], "new": matches[0][field]})
        else:
            remaining.extend(matches)
    return proposals, remaining


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
    unused = [index for index, item in enumerate(exclusions) if item.get("source") in audited and index not in used]
    reworded, unapproved = pair(unapproved, unused, exclusions, location, "error")
    edited, new_failures = pair(unapproved, unused, exclusions, content, "sha256")
    stale = [{"index": index, **exclusions[index]} for index in unused]
    return {"proposals": sorted(reworded + edited, key=lambda item: item["index"]),
            "new_failures": sorted(new_failures, key=location),
            "stale": sorted(stale, key=lambda item: item["index"]), "skipped": sorted(skipped)}


def subtract(result, control):
    """Keep only what the control run, at the same inputs, did not also report."""
    return {key: [item for item in items if item not in control[key]] for key, items in result.items()}


def apply(exclusions, result, prune=False):
    updated = [dict(item) for item in exclusions]
    for proposal in result["proposals"]:
        updated[proposal["index"]][proposal["field"]] = proposal["new"]
    removed = {item["index"] for item in result["stale"]} if prune else set()
    return [item for index, item in enumerate(updated) if index not in removed]


def describe(item):
    return (f"{item['source']} {item['path']} #{item['document']} {item['stage']}/{item['profile']}: "
            f"{next(iter((item.get('error') or '').splitlines()), '')}")


def render_markdown(result):
    lines = ["## Exclusion baseline", ""]
    reworded = [proposal for proposal in result["proposals"] if proposal["field"] == "error"]
    edited = [proposal for proposal in result["proposals"] if proposal["field"] == "sha256"]
    lines.append(f"{len(reworded)} proposed message updates, {len(edited)} records to re-pin, "
                 f"{len(result['new_failures'])} new failures, {len(result['stale'])} unused records, "
                 f"{len(result['skipped'])} skipped sources.")
    groups = defaultdict(list)
    for proposal in reworded:
        groups[proposal["old"], proposal["new"]].append(proposal)
    for (old, new), proposals in sorted(groups.items(), key=lambda item: -len(item[1])):
        sources = sorted({proposal["source"] for proposal in proposals})
        lines.extend(["", f"### {len(proposals)} records ({', '.join(sources)})", "",
                      fenced([f"- {line}" for line in old.splitlines()] + [f"+ {line}" for line in new.splitlines()],
                             "diff")])
    for title, items in (("Rules edited upstream that fail as reviewed (re-pinned by --apply)", edited),
                         ("New failures (need a fix or a reviewed record)", result["new_failures"]),
                         ("Unused records (prune with --prune)", result["stale"])):
        if items:
            lines.extend(["", f"### {title}", "", fenced([describe(item) for item in items])])
    if result["skipped"]:
        lines.extend(["", "Skipped (no per-rule results): " + ", ".join(result["skipped"])])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", type=Path, help="Report directory of an --audit or generation run")
    parser.add_argument("--exclusions", type=Path, default=Path(__file__).resolve().parent / "exclusions.json")
    parser.add_argument("--control", type=Path, metavar="REPORTS",
                        help="Report directory of a run at the same inputs; omit what it also reports")
    parser.add_argument("--apply", action="store_true", help="Write the proposed message updates and re-pins")
    parser.add_argument("--prune", action="store_true", help="With --apply, also remove unused records")
    parser.add_argument("--json", type=Path, help="Also write the full result as JSON")
    parser.add_argument("--exit-code", action="store_true", help="Exit 1 when anything needs review")
    args = parser.parse_args()
    if args.prune and not args.apply:
        parser.error("--prune requires --apply")
    if args.control and args.apply:
        parser.error("--control reports a difference; it cannot be applied")
    exclusions = json.loads(args.exclusions.read_bytes())

    def load(directory):
        return rebaseline(exclusions, [json.loads(path.read_bytes()) for path in sorted(directory.glob("*.json"))])
    result = load(args.reports)
    if args.control:
        result = subtract(result, load(args.control))
    if args.json:
        write_json(args.json, result)
    if args.apply:
        write_json(args.exclusions, apply(exclusions, result, args.prune))
    sys.stdout.write(render_markdown(result))
    return 1 if args.exit_code and any(result[key] for key in ("proposals", "new_failures", "stale")) else 0


if __name__ == "__main__":
    sys.exit(main())
