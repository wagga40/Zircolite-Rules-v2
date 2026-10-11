"""Verify published artifacts and render the README summary and dashboard without fetching sources."""

import json
import os
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from html import escape

from rule_bundles import WINDOWS_ALL, windows_all_files
from rule_conversion import LEVELS
from rule_sources import ATTACK_TACTICS, digest
from ruleset_charts import THEMES, bar_chart
from ruleset_charts import overview as overview_card

START = "<!-- ruleset-stats:start -->"
END = "<!-- ruleset-stats:end -->"
DASHBOARD = Path("docs/dashboard.md")
FIGURES = Path("docs/assets")
NO_TACTIC = "(no tactic tag)"


def is_ruleset(name):
    path = Path(name)
    return (path.parent in (Path("."), Path("experimental"))
            and path.name.startswith("rules_") and path.suffix == ".json")


def tactics(rule):
    names = {tag.partition(".")[2].replace("_", "-") for tag in rule.get("tags", [])
             if tag.startswith("attack.")}
    return [tactic for tactic in ATTACK_TACTICS if tactic in names] or [NO_TACTIC]


def coverage(rules, labels):
    """Distinct rule IDs per label; SQL variants of one rule count once."""
    return Counter(label for label, _ in {(label, rule["id"]) for rule in rules for label in labels(rule)})


def logsources(rules):
    """Distinct rules per Sigma category. Pipelines can turn a variant's category into a
    service (process_creation becomes Security 4688), so any category wins for an ID."""
    found = defaultdict(set)
    for rule in rules:
        source = rule.get("logsource") or {}
        found[rule["id"]].add((source.get("category"), source.get("service")))
    counts = Counter()
    for pairs in found.values():
        categories = {category for category, _ in pairs if category}
        counts.update(categories or {f"service: {service}" if service else "(product only)" for _, service in pairs})
    return counts


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
            ids = {rule["id"] for rule in rules}
            rulesets.append({"source": source, "name": name, "entries": len(rules), "unique_ids": len(ids),
                             "ids": ids, "levels": {level: levels[level] for level in LEVELS},
                             "severity": coverage(rules, lambda rule: [rule["level"]]),
                             "tactics": coverage(rules, tactics), "logsources": logsources(rules)})
    if "windows_all" in manifest.get("aggregates", {}):
        _, expected = windows_all_files(output, manifest)
        if manifest["aggregates"]["windows_all"] != expected:
            raise ValueError("Combined Windows ruleset is out of date; regenerate the rulesets")
    return manifest, rulesets


def updated(manifest):
    return max((details.get("last_success") or "" for details in manifest["sources"].values()), default="")[:10] or "—"


def summary(manifest, rulesets):
    """Headline figures shared by the README, the dashboard, and the overview card."""
    sources = manifest["sources"]
    detections = [row for row in rulesets if not row["name"].startswith("experimental/")]
    combined = next((row for row in rulesets if row["name"] == WINDOWS_ALL), None)
    union = lambda rows: len(set().union(*(row["ids"] for row in rows)))
    data = {"sources": len(sources), "current": sum(d["status"] == "current" for d in sources.values()),
            "windows_rules": f"{combined['entries']:,}" if combined else "—",
            "windows_unique": f"{combined['unique_ids']:,}" if combined else "—",
            "linux": f"{union([row for row in detections if row['name'].endswith('_linux.json')]):,}",
            "correlations": f"{union([row for row in rulesets if row['name'].startswith('experimental/')]):,}",
            "updated": updated(manifest), "severity": combined["severity"] if combined else Counter()}
    data["alt"] = (f"{data['current']} of {data['sources']} sources current; {data['windows_rules']} rules in "
                   f"{WINDOWS_ALL} ({data['windows_unique']} unique); {data['linux']} Linux rules; "
                   f"{data['correlations']} experimental correlations; updated {data['updated']}.")
    if combined:
        data["alt"] += " Severity of unique detections: " + ", ".join(
            f"{level} {data['severity'][level]:,}" for level in LEVELS) + "."
    return data


def behind(manifest):
    names = [f"{name} ({details['status']}"
             + (f" since {details['last_success'][:10]})" if details.get("last_success") else ")")
             for name, details in sorted(manifest["sources"].items()) if details["status"] != "current"]
    return ["", "Not current: " + ", ".join(names) + ". Stale sources keep their last good rules."] if names else []


def picture(name, alt, prefix):
    """A figure that follows the reader's GitHub theme."""
    return "\n".join(["<picture>",
                      f'  <source media="(prefers-color-scheme: dark)" srcset="{prefix}{name}-dark.svg">',
                      f'  <img alt="{escape(alt)}" src="{prefix}{name}-light.svg" width="100%">',
                      "</picture>"])


def figures(manifest, rulesets):
    data = summary(manifest, rulesets)
    combined = next((row for row in rulesets if row["name"] == WINDOWS_ALL), None)
    files = {}
    for theme in THEMES:
        files[FIGURES / f"overview-{theme}.svg"] = overview_card(data, theme)
        if combined:
            files[FIGURES / f"tactics-{theme}.svg"] = bar_chart(
                "ATT&CK tactics", f"Unique detections in {WINDOWS_ALL} per tactic; a rule can have several",
                [(label, count, label == NO_TACTIC) for label, count in tactic_rows(combined["tactics"])], theme)
            files[FIGURES / f"logsources-{theme}.svg"] = bar_chart(
                "Log sources", f"Unique detections in {WINDOWS_ALL} per Sigma category or service, top 15",
                [(label, count, False) for label, count in logsource_rows(combined["logsources"])], theme)
    return files


def ruleset_table(rows, prefix):
    if not rows:
        return ["No published rulesets."]
    lines = ["| Ruleset | Entries | Unique IDs | Info | Low | Medium | High | Critical |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for row in sorted(rows, key=lambda row: (row["source"] != "windows_all", row["source"] != "sigmahq",
                                             row["source"], row["name"])):
        counts = [row["entries"], row["unique_ids"], *(row["levels"][level] for level in LEVELS)]
        lines.append(f"| [{Path(row['name']).name}]({prefix}{row['name']}) | "
                     + " | ".join(f"{count:,}" for count in counts) + " |")
    return lines


def count_table(title, items):
    return [f"| {title} | Rules |", "|---|---:|", *(f"| {label} | {count:,} |" for label, count in items)]


def tactic_rows(counts):
    labels = {tactic: tactic.replace("-", " ").title().replace(" And ", " and ") for tactic in ATTACK_TACTICS}
    return [(labels.get(tactic, tactic), counts[tactic]) for tactic in (*ATTACK_TACTICS, NO_TACTIC) if counts[tactic]]


def logsource_rows(counts):
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:15]


def collapsed(summary_text, lines):
    return ["<details>", f"<summary>{summary_text}</summary>", "", *lines, "", "</details>"]


def render_summary(manifest, rulesets):
    return "\n".join([picture("overview", summary(manifest, rulesets)["alt"], f"{FIGURES.as_posix()}/"),
                      *behind(manifest), "",
                      f"Every ruleset, source, severity, ATT&CK tactic, and log source: [dashboard]({DASHBOARD.as_posix()})."])


def render_dashboard(manifest, rulesets):
    prefix = "../"
    lines = ["# Ruleset dashboard", "",
             "Generated from the verified release on every update; do not edit.", "",
             picture("overview", summary(manifest, rulesets)["alt"], "assets/"), *behind(manifest),
             "", "## Sources", "",
             "| Source | Status | License | Revision | Last success (UTC) | Detection rules |",
             "|---|---|---|---|---|---:|"]
    for name, details in sorted(manifest["sources"].items(), key=lambda item: (item[0] != "sigmahq", item[0])):
        revision = details.get("revision")
        if revision and not revision.startswith("local-sha256:"):
            revision = f"[{revision[:12]}](https://github.com/{details['repository']}/tree/{revision})"
        elif revision:
            revision = f"`{revision[:25]}…`"
        own = [row["ids"] for row in rulesets if row["source"] == name and not row["name"].startswith("experimental/")]
        rules = f"{len(set().union(*own)):,}" if own else "—"
        lines.append(f"| [{name}](https://github.com/{details['repository']}) | {details['status']} "
                     f"| {details.get('license') or '—'} | {revision or '—'} "
                     f"| {(details.get('last_success') or '—')[:16].replace('T', ' ')} | {rules} |")
    combined = next((row for row in rulesets if row["name"] == WINDOWS_ALL), None)
    if combined:
        lines.extend(["", f"## Inside `{WINDOWS_ALL}`", "",
                      "Counts are distinct rules; a rule with several tactics counts once per tactic.", "",
                      "| Info | Low | Medium | High | Critical |", "|---:|---:|---:|---:|---:|",
                      "| " + " | ".join(f"{combined['severity'][level]:,}" for level in LEVELS) + " |", "",
                      picture("tactics", "Unique detections per ATT&CK tactic; the table below lists the values.",
                              "assets/"), "",
                      *collapsed("ATT&CK tactic table", count_table("ATT&CK tactic", tactic_rows(combined["tactics"]))),
                      "", picture("logsources", "Unique detections per log source, top 15; the table below lists "
                                  "the values.", "assets/"), "",
                      *collapsed("Log source table", count_table("Log source (top 15)",
                                                               logsource_rows(combined["logsources"])))])
    lines.extend(["", "## Detection rulesets", "",
                  *ruleset_table([row for row in rulesets if not row["name"].startswith("experimental/")], prefix),
                  "", "## Experimental correlation rulesets", "",
                  "Zircolite 4.1 or newer runs these; see [experimental/](../experimental/README.md).", "",
                  *ruleset_table([row for row in rulesets if row["name"].startswith("experimental/")], prefix),
                  "", "Entries are exported rule objects; SQL variants of one rule share its ID. Profiles overlap, "
                  "so do not add counts across files. Severity columns are exact levels."])
    return "\n".join(lines) + "\n"


def readme_with_statistics(output, manifest, rulesets):
    original = (output / "README.md").read_bytes().decode("utf-8")
    if original.count(START) != 1 or original.count(END) != 1 or original.index(START) >= original.index(END):
        raise ValueError("README must contain one ordered pair of ruleset-stats markers")
    before, _, rest = original.partition(START)
    _, _, after = rest.partition(END)
    return original, before + START + "\n\n" + render_summary(manifest, rulesets) + "\n\n" + END + after


def documentation(output, release):
    """Current and refreshed README and dashboard text for a verified release."""
    manifest, rulesets = release
    original, readme = readme_with_statistics(output, manifest, rulesets)
    generated = {DASHBOARD: render_dashboard(manifest, rulesets), **figures(manifest, rulesets)}
    current = lambda name: (output / name).read_bytes().decode("utf-8") if (output / name).exists() else None
    return {Path("README.md"): (original, readme), **{name: (current(name), text) for name, text in generated.items()}}


def update_readme_stats(output):
    """Refresh the README summary and the dashboard; files are replaced atomically."""
    for name, (original, updated) in documentation(output, read_release(output)).items():
        if original != updated:
            (output / name).parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".stats-stage-", dir=output) as temporary:
                staged = Path(temporary) / name.name
                staged.write_bytes(updated.encode("utf-8"))
                os.replace(staged, output / name)


def verify_release(output):
    release = read_release(output)
    if (output / "README.md").exists():
        for name, (original, updated) in documentation(output, release).items():
            if original != updated:
                label = "README statistics are" if name.name == "README.md" else f"{name.as_posix()} is"
                raise ValueError(f"{label} out of date; run gen_ruleset.py --update-readme-stats")
