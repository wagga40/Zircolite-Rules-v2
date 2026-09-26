"""Generate independently validated, reproducible Zircolite rulesets."""

import argparse
import importlib.metadata
import json
import os
import platform
import sqlite3
import sys
import tempfile
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from rule_bundles import windows_all_files
from rule_conversion import artifact_name, artifact_rules, compile_source, retired_artifacts
from rule_sources import digest, fetch_source, json_bytes, local_revision
from ruleset_stats import update_readme_stats, verify_release

ROOT = Path(__file__).resolve().parent
PACKAGES = ("pysigma", "pysigma-backend-sqlite", "pysigma-pipeline-sysmon", "pysigma-pipeline-windows")


def read_json(path, default):
    return json.loads(path.read_text()) if path.exists() else default


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(json_bytes(value))
    temporary.replace(path)


def promote(output, files, previous):
    """Stage a complete source, then replace it, rolling back on an I/O failure."""
    paths = set(files) | set(previous)
    for name in paths:
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("Unsafe artifact path")
    before = {name: (output / name).read_bytes() if (output / name).exists() else None for name in paths}
    with tempfile.TemporaryDirectory(prefix=".rules-stage-", dir=output) as temporary:
        staging = Path(temporary)
        for name, data in files.items():
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        try:
            for name in sorted(paths):
                destination = output / name
                if name in files:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(staging / name, destination)
                elif destination.exists():
                    destination.unlink()
        except Exception:
            for name, data in before.items():
                destination = output / name
                if data is None:
                    destination.unlink(missing_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
            raise


def existing_official(output, manifest):
    official, hashes = {}, {}
    details = manifest["sources"].get("sigmahq")
    for profile in ("sysmon", "generic", "linux"):
        official[profile] = {}
        for kind in ("events", "correlations"):
            name = artifact_name("sigmahq", profile, kind)
            official[profile][kind] = []
            if details is not None and name not in details.get("artifacts", {}):
                continue
            path = output / name
            if details is None and not path.exists():
                continue
            raw = path.read_bytes()
            hashes[name] = digest(raw)
            if details is not None and hashes[name] != details["artifacts"][name]:
                raise ValueError(f"Official baseline artifact hash mismatch: {name}")
            official[profile][kind] = json.loads(raw)
    return official, {"repository": (details or {}).get("repository", "SigmaHQ/sigma"),
                      "revision": (details or {}).get("revision"), "artifacts": hashes}


def rebuild_windows_all(output):
    """Atomically publish the bundle and its lineage after source promotions."""
    manifest = read_json(output / "release-manifest.json", {"sources": {}})
    files, details = windows_all_files(output, manifest)
    previous = manifest.get("aggregates", {}).get("windows_all", {})
    if details is None and not previous:
        return
    if details is None:
        del manifest["aggregates"]["windows_all"]
    else:
        manifest.setdefault("aggregates", {})["windows_all"] = details
    promote(output, {**files, "release-manifest.json": json_bytes(manifest)}, previous.get("artifacts", {}))


def generate(registry, sources, output, cache, exclusions, local_roots=None, revisions=None, audit=False):
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "release-manifest.json"
    manifest = read_json(manifest_path, {"schema_version": 1, "sources": {}})
    tools = {package: importlib.metadata.version(package) for package in PACKAGES}
    tools.update(python=platform.python_version(), sqlite=sqlite3.sqlite_version)
    official, official_baseline = None, None
    failed = []
    # Official output is the comparison baseline, including during a source-only run.
    ordered = sorted(sources, key=lambda name: (name != "sigmahq", name))
    for source in ordered:
        spec = registry[source]
        previous = manifest["sources"].get(source, {})
        revision = None
        now = datetime.now(UTC).isoformat(timespec="seconds")
        print(f"[{source}] Fetching and validating", flush=True)
        try:
            if source != "sigmahq" and official is None:
                official, official_baseline = existing_official(output, manifest)
            if source in (local_roots or {}):
                root = Path(local_roots[source]).resolve()
                revision = local_revision(root, spec)
            else:
                root, revision = fetch_source(spec, cache / source, (revisions or {}).get(source))
            license_bytes = (root / spec["license_file"]).read_bytes()
            if not license_bytes.strip():
                raise ValueError("Source license is empty")
            outputs, report = compile_source(source, spec, root, exclusions)
            report.update(repository=spec["repository"], revision=revision, tools=tools)
            if source != "sigmahq":
                report["official_baseline"] = official_baseline
            artifacts, overlaps = artifact_rules(source, outputs, {} if source == "sigmahq" else official)
            report["official_duplicates_removed"] = overlaps
            report["artifacts"] = {name: len(rules) for name, rules in artifacts.items()}
            if report["status"] != "validated":
                write_json(output / "reports" / f"{source}.json", report)
                reason = report.get("error") or f"{sum(not item['approved'] for item in report['failures'])} unexpected failures"
                raise ValueError(f"{reason}; see reports/{source}.json")
            files = {name: json_bytes(rules) for name, rules in artifacts.items()}
            files[f"licenses/{source}.txt"] = license_bytes
            # The successful report is kept with its rules; the latest attempt is separate.
            files[f"provenance/{source}.json"] = json_bytes(report)
            hashes = {name: digest(data) for name, data in files.items()}
            if not audit:
                unchanged = previous.get("revision") == revision and previous.get("artifacts") == hashes
                candidate = deepcopy(manifest)
                candidate["sources"][source] = {
                    "status": "current", "repository": spec["repository"], "revision": revision,
                    "license": spec["license"], "tools": tools, "artifacts": hashes,
                    "rule_counts": report["artifacts"],
                    "last_success": previous["last_success"] if unchanged else now,
                }
                promote(output, {**files, "release-manifest.json": json_bytes(candidate),
                                 f"reports/{source}.json": json_bytes(report)},
                        set(previous.get("artifacts", {})) | retired_artifacts(source, spec["profiles"]))
                manifest = candidate
            else:
                write_json(output / "reports" / f"{source}.json", report)
            if source == "sigmahq":
                official = outputs
                official_baseline = {
                    "repository": spec["repository"], "revision": revision,
                    "artifacts": {name: hashes[name] for profile in outputs for kind in outputs[profile]
                                  if (name := artifact_name(source, profile, kind)) in artifacts},
                }
            print(f"[{source}] Validated {sum(p['events'] for p in report['profiles'].values())} detections and "
                  f"{sum(p['correlations'] for p in report['profiles'].values())} correlations across profiles", flush=True)
        except Exception as exc:
            failed.append(source)
            latest = read_json(output / "reports" / f"{source}.json", {})
            if latest.get("revision") != revision or latest.get("status") != "failed":
                latest = {"source": source, "status": "failed", "revision": revision, "error": str(exc)}
                write_json(output / "reports" / f"{source}.json", latest)
            if not audit:
                manifest["sources"][source] = {
                    **previous, "status": "stale" if previous.get("artifacts") else "unavailable",
                    "repository": spec["repository"], "failed_revision": revision,
                    "last_attempt": now, "error": str(exc),
                }
                write_json(manifest_path, manifest)
            print(f"[{source}] FAILED: {exc}; previous rules retained", file=sys.stderr, flush=True)
    if not audit:
        rebuild_windows_all(output)
        if (output / "README.md").exists():
            update_readme_stats(output)
    return failed


def assignments(values):
    result = {}
    for value in values:
        name, separator, content = value.partition("=")
        if not separator or not name or not content:
            raise ValueError("Expected SOURCE=VALUE")
        result[name] = content
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", nargs="+", help="Registry source names; default: all")
    parser.add_argument("--output-dir", type=Path, default=ROOT)
    parser.add_argument("--cache-dir", type=Path, default=ROOT / ".cache" / "rule-sources")
    parser.add_argument("--registry", type=Path, default=ROOT / "sources.json")
    parser.add_argument("--exclusions", type=Path, default=ROOT / "exclusions.json")
    parser.add_argument("--source-root", action="append", default=[], metavar="SOURCE=PATH",
                        help="Explicit local input override, recorded with a content hash")
    parser.add_argument("--revision", action="append", default=[], metavar="SOURCE=SHA",
                        help="Fetch an immutable revision instead of resolving the branch")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--audit", action="store_true", help="Write validation reports only; never publish rules")
    mode.add_argument("--verify-release", action="store_true", help="Verify published hashes, counts, and README statistics and exit")
    mode.add_argument("--update-readme-stats", action="store_true", help="Refresh README statistics from verified local artifacts and exit")
    args = parser.parse_args()
    if args.verify_release:
        verify_release(args.output_dir.resolve())
        return 0
    if args.update_readme_stats:
        update_readme_stats(args.output_dir.resolve())
        return 0
    registry = read_json(args.registry, {})
    roots, revisions = assignments(args.source_root), assignments(args.revision)
    selected = args.sources or list(registry)
    unknown = (set(selected) | roots.keys() | revisions.keys()) - registry.keys()
    if unknown:
        parser.error("Unknown sources: " + ", ".join(sorted(unknown)))
    if roots.keys() & revisions.keys():
        parser.error("Use either a local root or a remote revision for each source")
    failed = generate(registry, selected, args.output_dir.resolve(), args.cache_dir.resolve(),
                      read_json(args.exclusions, []), roots, revisions, args.audit)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
