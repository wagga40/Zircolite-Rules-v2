"""Compare the installed converter stack with the one that built the published release."""

import argparse
import json
import sys
import tomllib
from importlib import metadata
from pathlib import Path

import requests
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from gen_ruleset import PACKAGES

ROOT = Path(__file__).resolve().parent


def installed_stack(names=PACKAGES):
    return {name: (metadata.version(name), metadata.requires(name) or []) for name in names}


def conflicts(stack):
    """Declared requirements between converter packages that the installed versions violate."""
    versions = {canonicalize_name(name): version for name, (version, _) in stack.items()}
    found = []
    for name, (version, requires) in sorted(stack.items()):
        for text in requires:
            requirement = Requirement(text)
            other = canonicalize_name(requirement.name)
            applies = requirement.marker is None or requirement.marker.evaluate({"extra": ""})
            if other in versions and applies and not requirement.specifier.contains(versions[other], prereleases=True):
                found.append(f"{name} {version} requires `{text}`; {other} {versions[other]} is installed")
    return found


def published_tools(manifest):
    sources = manifest.get("sources", {})
    details = sources.get("sigmahq") or next(iter(sources.values()), {})
    return details.get("tools", {})


def latest_release(name):
    response = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=(15, 60))
    response.raise_for_status()
    return response.json()["info"]["version"]


def assess(published, stack, latest, overrides):
    rows = [{"package": name, "published": published.get(name), "resolved": stack[name][0],
             "latest": latest.get(name)} for name in sorted(stack)]
    found = conflicts(stack)
    return {"packages": rows, "conflicts": found,
            "override_removable": bool(overrides) and not found,
            "upgraded": any(row["published"] != row["resolved"] for row in rows)}


def render_markdown(result, overrides):
    lines = ["## Converter versions", "", "| Package | Published | Resolved | Latest on PyPI |", "|---|---|---|---|"]
    for row in result["packages"]:
        lines.append(f"| {row['package']} | {row['published'] or '—'} | {row['resolved']} | {row['latest'] or '—'} |")
    lines.append("")
    if overrides:
        names = ", ".join(f"`{name}`" for name in sorted(overrides))
        lines.append(f"Resolution overrides for {names} are no longer needed: installed requirements agree."
                     if result["override_removable"] else f"Resolution overrides for {names} are still required:")
    elif result["conflicts"]:
        lines.append("Installed requirements conflict:")
    lines.extend(f"- {item}" for item in result["conflicts"])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "release-manifest.json")
    parser.add_argument("--pyproject", type=Path, default=ROOT / "pyproject.toml")
    parser.add_argument("--json", type=Path, help="Also write the assessment as JSON")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit 1 when versions differ from the release or an override is removable")
    args = parser.parse_args()
    overrides = tomllib.loads(args.pyproject.read_text()).get("tool", {}).get("pdm", {}).get(
        "resolution", {}).get("overrides", {})
    stack = installed_stack()
    result = assess(published_tools(json.loads(args.manifest.read_bytes())), stack,
                    {name: latest_release(name) for name in stack}, overrides)
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    sys.stdout.write(render_markdown(result, overrides))
    return 1 if args.exit_code and (result["upgraded"] or result["override_removable"]) else 0


if __name__ == "__main__":
    sys.exit(main())
