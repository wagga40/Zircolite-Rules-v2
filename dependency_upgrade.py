"""Turn the canary's resolution into a minimal upgrade, and check one before it is proposed.

Standard library only: the job that opens the pull request runs this with the
runner's own Python, never with the packages the upgrade would install.
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

# An exact pin on its own line of pyproject.toml's dependency list.
PIN_LINE = re.compile(r'^([ \t]*")([A-Za-z0-9][A-Za-z0-9._-]*)==([^"]+)(",?)[ \t]*$', re.M)
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!_-]+)")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")
VERSION = re.compile(r"[A-Za-z0-9.+!_-]{1,64}")
# Index packages only: a lock entry with a URL, path or VCS source is refused.
PACKAGE_KEYS = {"name", "version", "requires_python", "summary", "groups", "files", "dependencies", "marker"}
HASH = re.compile(r"sha256:[0-9a-f]{64}")


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_versions(text):
    """The version a pdm.lock pins for each package."""
    return {canonical(package["name"]): package["version"] for package in tomllib.loads(text).get("package", [])}


def pin_resolved(pyproject, lock):
    """The pyproject with each exact pin moved to its locked version; ranges stay as written."""
    versions = lock_versions(lock)
    return PIN_LINE.sub(lambda match: f"{match[1]}{match[2]}=={versions.get(canonical(match[2]), match[3])}"
                                      f"{match[4]}", pyproject)


def upgrade_changes(pyproject, proposed, lock, proposed_lock):
    """The package versions an upgrade changes; ValueError if it changes anything else.

    The proposal comes from a job that ran unreviewed packages, so only versions of
    packages already locked may change; a new dependency needs a deliberate update.
    """
    before, after = tomllib.loads(pyproject), tomllib.loads(proposed)
    old, new = before["project"].pop("dependencies", []), after["project"].pop("dependencies", [])
    if before != after or len(old) != len(new):
        raise ValueError("The upgrade changes pyproject.toml beyond dependency versions")
    for current, upgraded in zip(old, new):
        pins = PIN.fullmatch(current), PIN.fullmatch(upgraded)
        if current != upgraded and not (all(pins) and pins[0][1] == pins[1][1]):
            raise ValueError(f"The upgrade changes the requirement {current!r}, not only its pinned version")
    locked, relocked = tomllib.loads(lock), tomllib.loads(proposed_lock)
    if relocked["metadata"].get("strategy") != locked["metadata"].get("strategy") or \
            relocked["metadata"].get("groups") != locked["metadata"].get("groups"):
        raise ValueError("The upgrade changes how the lock is resolved")
    for package in relocked["package"]:
        files = package.get("files") or [{}]
        if set(package) - PACKAGE_KEYS or any(set(item) != {"file", "hash"} or not HASH.fullmatch(str(item["hash"]))
                                              for item in files):
            raise ValueError(f"The upgrade locks {package.get('name')!r} from outside the package index")
    versions, upgraded = lock_versions(lock), lock_versions(proposed_lock)
    if not all(NAME.fullmatch(name) and VERSION.fullmatch(version) for name, version in upgraded.items()):
        raise ValueError("The upgrade locks an unexpected package name or version")
    if upgraded.keys() - versions.keys():
        raise ValueError("The upgrade adds packages: " + ", ".join(sorted(upgraded.keys() - versions.keys())))
    return sorted((name, versions.get(name), upgraded.get(name)) for name in versions.keys() | upgraded.keys()
                  if versions.get(name) != upgraded.get(name))


def render_changes(changes):
    lines = ["| Package | Locked | Upgrade |", "|---|---|---|"]
    lines.extend(f"| {name} | {old or '—'} | {new or 'removed'} |" for name, old, new in changes)
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--propose", type=Path, metavar="PYPROJECT",
                      help="Print PYPROJECT with its exact pins moved to the versions in --lock")
    mode.add_argument("--same-versions", type=Path, nargs=2, metavar="LOCK",
                      help="Exit 1 unless both locks pin the same versions")
    mode.add_argument("--check", type=Path, metavar="DIRECTORY",
                      help="Check the upgrade in DIRECTORY against ./pyproject.toml and ./pdm.lock; print its changes")
    parser.add_argument("--lock", type=Path, default=Path("pdm.lock"))
    args = parser.parse_args()
    if args.propose:
        sys.stdout.write(pin_resolved(args.propose.read_text(), args.lock.read_text()))
        return 0
    if args.same_versions:
        first, second = (lock_versions(path.read_text()) for path in args.same_versions)
        return 0 if first == second else 1
    changes = upgrade_changes(Path("pyproject.toml").read_text(), (args.check / "pyproject.toml").read_text(),
                              args.lock.read_text(), (args.check / "pdm.lock").read_text())
    if not changes:
        raise SystemExit("The upgrade changes no package version")
    sys.stdout.write(render_changes(changes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
