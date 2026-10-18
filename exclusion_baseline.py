"""Propose reviewed exclusion updates after an upstream or toolchain change.

A failure is paired with one unused reviewed record when only one field
differs: the error text at the same rule content (a toolchain rewording), or
the content hash with the same error (an upstream edit that fails as reviewed).
Class records are never reworded, re-pinned or pruned. Anything else is
listed for review and never approved.

The daily publish runs --validated-only --apply: it re-pins and prunes only
for sources validated at their published revision, and writes nothing that
would change whether a failure is approved.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from exclusion_records import RULE_KEYS, approval, check_exclusions, is_class, matches, normalize_error, subsumes
from gen_ruleset import read_json, write_json

ROOT = Path(__file__).resolve().parent
LOCATION = ("source", "path", "sha256", "document", "stage", "profile")
# Listed for review, and what --exit-code fails on.
REVIEW = ("proposals", "new_failures", "stale", "redundant")
ACTIONS = {"reword": "error", "repin": "sha256", "prune": "stale", "redundant": "redundant"}


def location(item):
    return tuple(item.get(key) for key in LOCATION)


def fenced(lines, info=""):
    """A fenced block no line of upstream text can close."""
    text = "\n".join(lines)
    fence = "~" * max(3, 1 + max((len(run) for run in re.findall(r"~+", text)), default=0))
    return f"{fence}{info}\n{text}\n{fence}"


def indexed(exclusions, indexes):
    return [{"index": index, **exclusions[index]} for index in sorted(indexes)]


def new_value(failure, field):
    return normalize_error(failure["error"]) if field == "error" else failure[field]


def pair(failures, unused, exclusions, field):
    """Pair each unused record with the failures it matches in everything but field.

    A record takes its failures only when it is the sole candidate of each and
    they agree on the new value; a record for one profile takes one failure. An
    edited collection action is never re-pinned, as approval never drifts it.
    """
    candidates = [[index for index in unused if matches(exclusions[index], failure["source"], failure, (field,))]
                  if field != "sha256" or failure["stage"] != "discovery" else [] for failure in failures]
    proposals, taken = [], set()
    for index in list(unused):
        mine = [position for position, found in enumerate(candidates) if index in found]
        values = {new_value(failures[position], field) for position in mine}
        if (mine and all(candidates[position] == [index] for position in mine) and len(values) == 1
                and (exclusions[index]["profile"] == "*" or len(mine) == 1)):
            unused.remove(index)
            taken.update(mine)
            first = failures[mine[0]]
            proposals.append({"index": index, "field": field, **dict(zip(LOCATION, location(first), strict=True)),
                              "profile": exclusions[index]["profile"], "error": first["error"],
                              "old": exclusions[index][field], "new": values.pop()})
    return proposals, [failure for position, failure in enumerate(failures) if position not in taken]


def rebaseline(exclusions, reports):
    audited, skipped, unapproved, used = set(), [], [], defaultdict(int)
    for report in reports:
        # Fetch failures have no per-rule results to compare.
        if "failures" not in report:
            skipped.append(report.get("source"))
            continue
        audited.add(report["source"])
        for failure in report["failures"]:
            failure = {**failure, "source": report["source"]}
            found = [index for index, record in enumerate(exclusions) if matches(record, report["source"], failure)]
            for index in found:
                used[index] += 1
            if not found:
                unapproved.append(failure)
    classes = [index for index, record in enumerate(exclusions) if is_class(record)]
    rules = [index for index, record in enumerate(exclusions) if not is_class(record)]
    unused = [index for index in rules
              if exclusions[index]["source"] in audited and exclusions[index]["reason"] and index not in used]
    reworded, unapproved = pair(unapproved, unused, exclusions, "error")
    edited, new_failures = pair(unapproved, unused, exclusions, "sha256")
    return {"proposals": sorted(reworded + edited, key=lambda item: item["index"]),
            "new_failures": sorted(new_failures, key=location),
            "stale": indexed(exclusions, unused),
            "redundant": indexed(exclusions, [index for index in rules
                                              if any(subsumes(exclusions[other], exclusions[index]) for other in classes)]),
            "unused_classes": indexed(exclusions, [index for index in classes if audited and index not in used
                                                   and exclusions[index]["source"] in ("*", *audited)]),
            "class_usage": [{"class": exclusions[index]["class"], "failures": used[index]} for index in classes],
            "drafts": indexed(exclusions, [index for index in rules if not exclusions[index]["reason"]]),
            "skipped": sorted(skipped)}


def subtract(result, control):
    """Keep only what the control run, at the same inputs, did not also report."""
    return {key: [item for item in items if item not in control[key]] if key not in ("class_usage", "drafts")
            else items for key, items in result.items()}


def chosen(prune=False, only=None):
    return set(only) if only is not None else {"reword", "repin", *(("prune",) if prune else ())}


def apply(exclusions, result, prune=False, only=None):
    """Write the chosen updates: by default rewordings and re-pins, and with prune unused records."""
    only = chosen(prune, only)
    updated = [dict(item) for item in exclusions]
    for proposal in result["proposals"]:
        if ("reword" if proposal["field"] == "error" else "repin") in only:
            updated[proposal["index"]][proposal["field"]] = proposal["new"]
    removed = {item["index"] for action in ("prune", "redundant") if action in only for item in result[ACTIONS[action]]}
    if any(updated[index] != record for index, record in enumerate(exclusions) if is_class(record)):
        raise AssertionError("Class records are never rewritten")
    return [item for index, item in enumerate(updated) if index not in removed]


def drafts(result):
    """Unreviewed records for the new failures; each approves nothing until given a reason."""
    records = []
    for failure in result["new_failures"]:
        record = {**{key: failure[key] for key in RULE_KEYS[:-2]}, "error": normalize_error(failure["error"]),
                  "reason": ""}
        if record not in records:
            records.append(record)
    return records


def canonical(exclusions, registry):
    """Errors without positions, per-profile copies merged into "*", and a stable order.

    Copies merge only at conversion and validation, and only when they cover
    every profile of the source, or every Windows profile: a Windows rule
    never reaches the Linux profile.
    """
    records, groups = [], defaultdict(list)
    for record in exclusions:
        record = dict(record) if is_class(record) else {**record, "error": normalize_error(record["error"])}
        if not is_class(record) and record["stage"] in ("convert", "validate") and record["profile"] != "*":
            groups[tuple(record[key] for key in RULE_KEYS if key != "profile")].append(record)
        elif record not in records:
            records.append(record)
    for group in groups.values():
        profiles = set(registry.get(group[0]["source"], {}).get("profiles", ()))
        covered = {record["profile"] for record in group}
        if len(covered) > 1 and covered in (profiles, profiles - {"linux"}):
            group = [{**group[0], "profile": "*"}]
        records.extend(record for record in group if record not in records)
    return sorted(records, key=lambda record: (not is_class(record), record.get("class", ""),
                                               *(record.get(key, "") for key in LOCATION), record.get("error", "")))


def approval_changes(old, new, reports):
    """Failures whose approval differs between two sets of records."""
    changes = {"newly_approved": [], "no_longer_approved": [], "drift_changed": []}
    for report in reports:
        for failure in report.get("failures", []):
            before, after = approval(report["source"], failure, old), approval(report["source"], failure, new)
            item = {"source": report["source"], **{key: failure.get(key) for key in LOCATION[1:]},
                    "error": failure["error"]}
            if before["approved"] != after["approved"]:
                changes["newly_approved" if after["approved"] else "no_longer_approved"].append(item)
            elif before != after:
                changes["drift_changed"].append(item)
    return changes


def validated(reports, manifest, registry):
    """Reports of sources validated and published at the report's revision."""
    sources = manifest.get("sources", {})
    return [report for report in reports
            if report.get("status") == "validated" and "failures" in report and report.get("source") in registry
            and sources.get(report["source"], {}).get("status") == "current"
            and sources[report["source"]].get("revision") == report.get("revision")]


def describe(item):
    return (f"{item['source']} {item['path']} #{item['document']} {item['stage']}/{item['profile']}: "
            f"{next(iter((item.get('error') or '').splitlines()), '')}")


def describe_class(item):
    return f"{item['class']} ({item['source']} {item['stage']}/{item['profile']}): {item['error_pattern']}"


def render_markdown(result):
    lines = ["## Exclusion baseline", ""]
    reworded = [proposal for proposal in result["proposals"] if proposal["field"] == "error"]
    edited = [proposal for proposal in result["proposals"] if proposal["field"] == "sha256"]
    lines.append(f"{len(reworded)} proposed message updates, {len(edited)} records to re-pin, "
                 f"{len(result['new_failures'])} new failures, {len(result['stale'])} unused records, "
                 f"{len(result.get('redundant', []))} records a class covers, "
                 f"{len(result['skipped'])} skipped sources.")
    if result.get("class_usage"):
        lines.extend(["", "Class records approved " + ", ".join(
            f"{item['failures']} × {item['class']}" for item in result["class_usage"]) + "."])
    groups = defaultdict(list)
    for proposal in reworded:
        groups[proposal["old"], proposal["new"]].append(proposal)
    for (old, new), proposals in sorted(groups.items(), key=lambda item: -len(item[1])):
        sources = sorted({proposal["source"] for proposal in proposals})
        lines.extend(["", f"### {len(proposals)} records ({', '.join(sources)})", "",
                      fenced([f"- {line}" for line in old.splitlines()] + [f"+ {line}" for line in new.splitlines()],
                             "diff")])
    for title, items, show in (
            ("Rules edited upstream that fail as reviewed (re-pinned by --apply)", edited, describe),
            ("New failures (need a fix or a reviewed record; --draft-new writes drafts)", result["new_failures"],
             describe),
            ("Unused records (prune with --apply --prune)", result["stale"], describe),
            ("Records a class covers (remove with --apply --only redundant)", result.get("redundant", []), describe),
            ("Class records nothing used", result.get("unused_classes", []), describe_class),
            ("Drafts awaiting a reason", result.get("drafts", []), describe)):
        if items:
            lines.extend(["", f"### {title}", "", fenced([show(item) for item in items])])
    if result["skipped"]:
        lines.extend(["", "Skipped (no per-rule results): " + ", ".join(result["skipped"])])
    return "\n".join(lines) + "\n"


def render_changes(changes):
    lines = ["## Approval changes", "",
             f"{len(changes['newly_approved'])} newly approved, {len(changes['no_longer_approved'])} no longer "
             f"approved, {len(changes['drift_changed'])} with changed drift."]
    for key, title in (("newly_approved", "Newly approved"), ("no_longer_approved", "No longer approved"),
                       ("drift_changed", "Drift changed")):
        if changes[key]:
            lines.extend(["", f"### {title}", "", fenced([describe(item) for item in changes[key]])])
    return "\n".join(lines) + "\n"


def actions(text):
    chosen = set(text.split(","))
    if not chosen <= ACTIONS.keys():
        raise argparse.ArgumentTypeError("choose from " + ", ".join(ACTIONS))
    return chosen


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reports", type=Path, nargs="?", help="Report directory of an --audit or generation run")
    parser.add_argument("--exclusions", type=Path, default=ROOT / "exclusions.json")
    parser.add_argument("--control", type=Path, metavar="REPORTS",
                        help="Report directory of a run at the same inputs; omit what it also reports")
    parser.add_argument("--apply", action="store_true", help="Write the proposed message updates and re-pins")
    parser.add_argument("--prune", action="store_true", help="With --apply, also remove unused records")
    parser.add_argument("--only", type=actions, metavar="ACTION[,ACTION]",
                        help="With --apply, write only these: " + ", ".join(ACTIONS))
    parser.add_argument("--max-prune", type=int, default=10, help="Refuse to prune more unused records (default 10)")
    parser.add_argument("--validated-only", action="store_true",
                        help="Only sources validated and published at their report's revision; with --apply, "
                             "only re-pins and pruning, refused if any approval would change")
    parser.add_argument("--manifest", type=Path, default=ROOT / "release-manifest.json")
    parser.add_argument("--registry", type=Path, default=ROOT / "sources.json")
    parser.add_argument("--draft-new", action="store_true",
                        help="Append a draft record, without a reason, for each new failure")
    parser.add_argument("--canonicalize", action="store_true",
                        help="Normalize errors, merge per-profile copies, sort the records, and exit")
    parser.add_argument("--compare", type=Path, metavar="OLD",
                        help="List failures whose approval differs under the OLD exclusions file, and exit")
    parser.add_argument("--json", type=Path, help="Also write the full result as JSON")
    parser.add_argument("--exit-code", action="store_true", help="Exit 1 when anything needs review")
    args = parser.parse_args()
    if args.prune and not args.apply:
        parser.error("--prune requires --apply")
    if args.only is not None and not args.apply:
        parser.error("--only requires --apply")
    if args.control and (args.apply or args.draft_new):
        parser.error("--control reports a difference; it cannot be applied")
    if args.validated_only and args.apply:
        args.only = args.only if args.only is not None else {"repin", "prune"}
        if not args.only <= {"repin", "prune"}:
            parser.error("--validated-only applies only repin and prune")
    if args.reports is None and not args.canonicalize:
        parser.error("a report directory is required")
    exclusions = json.loads(args.exclusions.read_bytes())
    check_exclusions(exclusions)
    registry = read_json(args.registry, {})
    if args.canonicalize:
        write_json(args.exclusions, canonical(exclusions, registry))
        return 0

    def load(directory):
        reports = [json.loads(path.read_bytes()) for path in sorted(directory.glob("*.json"))]
        return validated(reports, read_json(args.manifest, {}), registry) if args.validated_only else reports
    reports = load(args.reports)
    if args.compare:
        old = json.loads(args.compare.read_bytes())
        changes = approval_changes(old, exclusions, reports)
        if args.json:
            write_json(args.json, changes)
        sys.stdout.write(render_changes(changes))
        return 1 if args.exit_code and (changes["newly_approved"] or changes["no_longer_approved"]) else 0
    result = rebaseline(exclusions, reports)
    if args.control:
        result = subtract(result, rebaseline(exclusions, load(args.control)))
    if args.json:
        write_json(args.json, result)
    updated = exclusions
    if args.apply:
        updated = apply(exclusions, result, args.prune, args.only)
        pruned = len(result["stale"]) if "prune" in chosen(args.prune, args.only) else 0
        if pruned > args.max_prune:
            raise SystemExit(f"Refusing to prune {pruned} records (--max-prune {args.max_prune}); nothing written")
        if args.validated_only:
            changes = approval_changes(exclusions, updated, reports)
            if changes["newly_approved"] or changes["no_longer_approved"]:
                sys.stdout.write(render_changes(changes))
                raise SystemExit("Refusing to change approvals; nothing written")
    if args.draft_new:
        updated = updated + [record for record in drafts(result) if record not in updated]
    if updated != exclusions:
        write_json(args.exclusions, updated)
    sys.stdout.write(render_markdown(result))
    return 1 if args.exit_code and any(result[key] for key in REVIEW) else 0


if __name__ == "__main__":
    sys.exit(main())
