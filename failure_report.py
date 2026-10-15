"""Report the sources a generation run kept at their previous rules.

Writes the tracking issue body, prints warning annotations, and appends the
failures and the exclusion baseline to a job summary. Writes nothing when every
source validated. Failure text comes from upstream rules, so the issue keeps it
in fenced blocks, where it cannot mention users or render links.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from exclusion_baseline import rebaseline
from exclusion_baseline import render_markdown as render_baseline

ROOT = Path(__file__).resolve().parent
FAILED = ("stale", "unavailable")
LISTED = 20  # lines and failures per source; the conversion-reports artifact has every one
# GitHub limits: 65,536 characters per issue body, 1 MiB per step summary, 10 warnings per step.
MAX_ISSUE, MAX_SUMMARY, MAX_WARNINGS = 60_000, 250_000, 10
KEYS = ("path", "document", "stage", "profile", "sha256", "error")
FIX = ("If an upstream edit changed a rule that still fails for its reviewed reason, the job summary's "
       "exclusion baseline pairs the new failure with its now unused record: re-pin that record's `sha256` "
       "in `exclusions.json`. Otherwise fix the conversion or add a reviewed record. A fetch error "
       "usually clears on a later run.")


def failed_sources(manifest, reports):
    """Sources whose latest attempt failed, with the rule failures no reviewed record approves."""
    result = []
    for name, details in sorted(manifest.get("sources", {}).items()):
        if details.get("status") in FAILED:
            failures = [item for item in reports.get(name, {}).get("failures", []) if not item.get("approved")]
            result.append({"source": name, "status": details["status"],
                           "error": details.get("error") or "No error message was recorded.",
                           "last_success": details.get("last_success"), "failures": failures})
    return result


def fingerprint(failed):
    """Identifies the failures alone, so a daily repeat of the same ones notifies nobody."""
    value = [[item["source"], item["error"], [[failure.get(key) for key in KEYS] for failure in item["failures"]]]
             for item in failed]
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


def fenced(lines):
    text = "\n".join(lines)
    fence = "~" * max(3, 1 + max((len(run) for run in re.findall(r"~+", text)), default=0))
    return f"{fence}\n{text}\n{fence}"


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


def annotations(failed):
    shown = failed if len(failed) <= MAX_WARNINGS else failed[:MAX_WARNINGS - 1]
    lines = [f"::warning title={escape(item['source'] + ' kept its previous rules', True)}::"
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
    args = parser.parse_args()
    if args.issue and not args.run_url:
        parser.error("--issue requires --run-url")
    output = args.output_dir.resolve()
    reports = {path.stem: json.loads(path.read_bytes()) for path in sorted((output / "reports").glob("*.json"))}
    failed = failed_sources(json.loads((output / "release-manifest.json").read_bytes()), reports)
    if not failed:
        return 0
    # Most important first: the issue notifies, and the baseline is the likeliest to fail.
    if args.issue:
        write(args.issue, render_issue(failed, args.run_url))
    sys.stdout.write("".join(line + "\n" for line in annotations(failed)))
    if args.summary:
        write(args.summary, truncate(render_failures(failed), MAX_SUMMARY // 2), "a")
        baseline = rebaseline(json.loads(args.exclusions.read_bytes()), list(reports.values()))
        write(args.summary, truncate(render_baseline(baseline), MAX_SUMMARY // 2), "a")
    return 0


if __name__ == "__main__":
    sys.exit(main())
