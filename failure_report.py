"""Report the sources a generation run kept at their previous rules.

Writes the tracking issue body, prints warning annotations, and appends the
failures and the exclusion baseline to a job summary. Rules edited upstream
that still fail as reviewed only warn: they stay excluded and need a re-pin.
Writes nothing when there is neither. Failure text comes from upstream rules,
so it stays in fenced blocks, where it cannot mention users or render links.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from exclusion_baseline import fenced, rebaseline
from exclusion_baseline import render_markdown as render_baseline

ROOT = Path(__file__).resolve().parent
FAILED = ("stale", "unavailable")
LISTED = 20  # lines and failures per source; the conversion-reports artifact has every one
# GitHub limits: 65,536 characters per issue body, 1 MiB per step summary, 10 warnings per step.
MAX_ISSUE, MAX_SUMMARY, MAX_WARNINGS = 60_000, 250_000, 10
KEYS = ("path", "document", "stage", "profile", "sha256", "error")
FIX = ("Each failure above needs review. If only the converter's wording of a reviewed error changed, the job "
       "summary's exclusion baseline proposes the new message, and `exclusion_baseline.py --apply` writes it. "
       "Otherwise fix the conversion or add a reviewed record to `exclusions.json`. A fetch error usually "
       "clears on a later run.")


def parse_time(text):
    return datetime.fromisoformat(text)


def failed_sources(manifest, reports, since=None):
    """Sources whose latest attempt failed, with the rule failures no reviewed record approves.

    With since, only sources attempted from then on: older entries belong to an
    earlier run or to a source no longer in the registry.
    """
    result = []
    for name, details in sorted(manifest.get("sources", {}).items()):
        attempted = details.get("last_attempt")
        if since and not (attempted and parse_time(attempted) >= since):
            continue
        if details.get("status") in FAILED:
            failures = [item for item in reports.get(name, {}).get("failures", []) if not item.get("approved")]
            result.append({"source": name, "status": details["status"],
                           "error": details.get("error") or "No error message was recorded.",
                           "last_success": details.get("last_success"), "failures": failures})
    return result


def drifted_failures(manifest, reports):
    """Approved failures of rules edited upstream, pending a re-pin."""
    return [failure for name in sorted(manifest.get("sources", {}))
            for failure in reports.get(name, {}).get("failures", []) if failure.get("drifted")]


def fingerprint(failed):
    """Identifies the failures alone, so a daily repeat of the same ones notifies nobody.

    Paths and numbers in a source error vary between runs, so they are ignored.
    """
    value = [[item["source"], re.sub(r"\S*[/\\]\S*|\d+", "#", item["error"]),
              [[failure.get(key) for key in KEYS] for failure in item["failures"]]] for item in failed]
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()[:16]


def first_line(text):
    return next(iter((text or "").splitlines()), "")


def capped(lines, noun):
    hidden = len(lines) - LISTED
    return lines[:LISTED] + ([f"... and {hidden} more {noun}"] if hidden > 0 else [])


def details(item):
    shown = [f"{failure['path']} #{failure['document']} {failure['stage']}/{failure['profile']}: "
             f"{first_line(failure.get('error'))}" for failure in item["failures"]]
    return [*capped(item["error"].splitlines(), "lines"), *capped(shown, "failures")]


def truncate(text, size):
    """Cut at a line boundary to stay within a GitHub size limit."""
    note = "\n\n... truncated; the conversion-reports artifact has the full reports.\n"
    if len(text) <= size:
        return text
    limit = size - len(note)
    cut = text.rfind("\n", 0, limit)
    return text[:cut if cut > 0 else limit] + note


def heading(item):
    since = f"last validated {item['last_success']}" if item.get("last_success") else "never validated"
    return f"### {item['source']} ({item['status']}, {since})"


def render_issue(failed, run_url):
    parts = [f"<!-- failure-fingerprint: {fingerprint(failed)} -->",
             "These sources could not be validated, so each keeps its last validated rules. "
             f"See [the latest run]({run_url}): its job summary has the exclusion baseline and its "
             "conversion-reports artifact the full reports. This issue closes after a clean run."]
    for item in failed:
        parts.extend([heading(item), fenced(details(item))])
    parts.append(FIX)
    return truncate("\n\n".join(parts) + "\n", MAX_ISSUE)


def render_failures(failed):
    count = f"{len(failed)} sources kept their" if len(failed) > 1 else "1 source kept its"
    lines = ["## Failed sources", "", f"{count} previous rules.", ""]
    for item in failed:
        lines.extend([heading(item), "", fenced(details(item)), ""])
    return "\n".join(lines) + "\n"


def escape(text, prop=False):
    """Encode workflow command data, and a property value when prop is set."""
    text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


def annotations(failed, drifted=()):
    lines = []
    if drifted:
        rules = f"{len(drifted)} excluded rule" + (" changed" if len(drifted) == 1 else "s changed")
        lines.append(f"::warning title={rules} upstream::They still fail as reviewed and stay excluded. Re-pin "
                     "their hashes with exclusion_baseline.py --apply on the conversion-reports artifact; "
                     "the job summary lists them.")
    room = MAX_WARNINGS - len(lines)
    shown = failed if len(failed) <= room else failed[:room - 1]
    lines += [f"::warning title={escape(item['source'] + ' kept its previous rules', True)}::"
              f"{escape(chr(10).join(details(item)[:6]))}" for item in shown]
    if len(shown) < len(failed):
        lines.append(f"::warning title={len(failed) - len(shown)} more sources kept their previous rules::"
                     "See the job summary and the tracking issue.")
    return lines


def write(path, text, mode="w"):
    with path.open(mode, encoding="utf-8", errors="backslashreplace") as handle:
        handle.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", type=Path, default=ROOT, help="Directory generation wrote to")
    parser.add_argument("--exclusions", type=Path, default=ROOT / "exclusions.json")
    parser.add_argument("--run-url", help="Run linked from the issue body")
    parser.add_argument("--summary", type=Path, help="Append the failures and exclusion baseline to this file")
    parser.add_argument("--issue", type=Path, help="Write the tracking issue body to this file")
    parser.add_argument("--since", type=parse_time, metavar="ISO-8601",
                        help="Report only sources attempted from this time on")
    args = parser.parse_args()
    if args.issue and not args.run_url:
        parser.error("--issue requires --run-url")
    output = args.output_dir.resolve()
    reports = {path.stem: json.loads(path.read_bytes()) for path in sorted((output / "reports").glob("*.json"))}
    manifest = json.loads((output / "release-manifest.json").read_bytes())
    failed, drifted = failed_sources(manifest, reports, args.since), drifted_failures(manifest, reports)
    if not failed and not drifted:
        return 0
    # Most important first: the issue notifies, and the baseline is the likeliest to fail.
    if args.issue and failed:
        write(args.issue, render_issue(failed, args.run_url))
    sys.stdout.write("".join(line + "\n" for line in annotations(failed, drifted)))
    if args.summary:
        if failed:
            write(args.summary, truncate(render_failures(failed), MAX_SUMMARY // 2), "a")
        baseline = rebaseline(json.loads(args.exclusions.read_bytes()), list(reports.values()))
        write(args.summary, truncate(render_baseline(baseline), MAX_SUMMARY // 2), "a")
    return 0


if __name__ == "__main__":
    sys.exit(main())
