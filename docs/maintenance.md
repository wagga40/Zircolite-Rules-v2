# Maintenance

## Toolchain

Conversion uses pySigma-backend-sqlite 2.1.1 on pySigma 2.0.1 and Python 3.14. Versions are locked in `pdm.lock`, and the versions behind each source are recorded in `release-manifest.json`.

The Windows and Sysmon pipelines still declare `pysigma<2`. `pyproject.toml` overrides that constraint until they are re-released. The `sigma` and `pySigma-backend-sqlite` submodule entries are historical and never used.

```bash
pdm sync --no-self -G test
pdm run pytest -q                                # set SQLITE_MIN_BINARY to a SQLite 3.38 CLI for 16 more tests
pdm run python gen_ruleset.py                    # fetch, validate, and publish every source
pdm run python gen_ruleset.py --verify-release   # check hashes, counts, the README summary, dashboard, and figures
```

## Commands

Run each with `pdm run python`.

| Task | Command |
|---|---|
| Report without publishing | `gen_ruleset.py --audit --output-dir build/audit` |
| Update one source | `gen_ruleset.py --sources hayabusa` |
| Use a pinned revision | `gen_ruleset.py --sources tsale --revision tsale=<40-character SHA>` |
| Use a local checkout | `gen_ruleset.py --sources sigmahq --source-root sigmahq=./sigma --output-dir build/local` |
| Reproduce the published inputs | `gen_ruleset.py --revisions-from release-manifest.json --output-dir build/repro` |
| Compare two releases rule by rule | `ruleset_diff.py . build/repro` |
| Refresh the README summary, dashboard, and figures | `gen_ruleset.py --update-readme-stats` |
| Remove unused cached snapshots | `gen_ruleset.py --prune-cache` |

With unchanged tools, `--revisions-from` reproduces the published rulesets byte for byte. A diff against that output therefore isolates the effect of a code or dependency change.

The README and dashboard figures in `docs/assets/` are animated SVGs rendered by `ruleset_charts.py` from the verified release, in light and dark variants. They animate once, except for the status dot, and stay still for readers who prefer reduced motion.

## Validation and release

Each source goes through the same pipeline:

1. Fetch an immutable snapshot: `git ls-remote` resolves the branch, which needs no GitHub API quota, and the commit's archive is downloaded, retrying server errors.
2. Adapt metadata.
3. Resolve correlation references.
4. Select rules per profile.
5. Convert.
6. Prepare every query in a fresh SQLite database with its declared fields. Regexes and ATT&CK tags are checked, and correlation plans are executed.

A source is published only when every failure has a reviewed exclusion. Otherwise its previous files stay, the manifest marks it `stale`, and `gen_ruleset.py` exits with status 3. A fetch error also keeps the previous report. An uncaught error exits with 1.

### Exclusions

[exclusions.json](../exclusions.json) holds two kinds of reviewed record:

- A **rule record** names one failure: source, path, content hash, document, stage, profile (`*` for every profile), and error. Line, column, and character positions in the error are ignored.
- A **class record** approves every failure at the `parse` or `convert` stage whose error matches its `error_pattern`. Each covers a capability the backend or Zircolite lacks, such as keyword search or regexes RE2 rejects, so a new rule that needs it stays out without a record of its own.

| Failure | Outcome |
|---|---|
| Matches a record | The rule stays out and the source publishes. |
| Matches a rule record except for the hash: an upstream edit that fails as reviewed | The rule stays out, the source publishes, and the publish run re-pins the record. Never for a collection action such as `action: global`, which shapes sibling documents that do publish. |
| Anything else | The source keeps its previous rules until the conversion is fixed or a record is reviewed. |

For sources validated in that run, the publish run also drops rule records whose rule no longer fails, at most 10 at a time. It refuses any change that would approve or unapprove a failure. On a pull request, the job summary lists the published failures that a change to `exclusions.json` approves or no longer approves.

`exclusion_baseline.py <reports> --draft-new` appends a draft record for each new failure. A draft approves nothing until it has a `reason`, and the tests reject drafts, so none merges unreviewed.

| File | Contents |
|---|---|
| `release-manifest.json` | Status, revision, tool versions, hashes, and counts per source, plus the lineage of `rules_windows_all.json` |
| `reports/<source>.json` | Latest attempt: failures, exclusions, and counts per profile |
| `provenance/<source>.json` | The report for the published files, with metadata adaptations and the SigmaHQ baseline used to remove duplicates |
| `licenses/<source>.txt` | License text at the published revision |

Validation proves that the SQL runs, not that each rule detects what it intends on every log schema.

## Upgrading dependencies

The daily run never upgrades dependencies.

1. Update the lock deliberately, for example with `pdm update pysigma-backend-sqlite`.
2. Audit at the published revisions, then re-baseline exclusions whose error text changed:

   ```bash
   pdm run python gen_ruleset.py --audit --revisions-from release-manifest.json --output-dir build/audit
   pdm run python exclusion_baseline.py build/audit/reports           # review the proposals
   pdm run python exclusion_baseline.py build/audit/reports --apply   # update messages and hashes, keep reasons
   ```

   A rule record is updated only when exactly one field changed: the error at the same content, or the hash with the same error. Class records are never changed. New failures need a written reason.
3. Regenerate into `build/repro` and attach the output of `ruleset_diff.py . build/repro` to the pull request.

Do not commit regenerated rulesets: the daily update also commits them, and CI publishes after merge.

## CI

| Workflow | Runs | Does |
|---|---|---|
| `Update.yml` | Daily at 01:23 UTC, on pushes that change generation files, and on demand | Tests in a read-only job, then publishes changed sources, the README summary, the dashboard, and its figures. Adds a rule diff to the job summary, and a warning when an edited rule's record needs a re-pin. A source that fails keeps its previous rules. The run then ends green with a warning per source, plus the failures and exclusion baseline in the job summary. A *Rule source validation failures* issue stays open while a source fails and gets a comment when the failures change. The run fails when generation crashes, the issue cannot be updated, or no source validated; in that last case nothing is committed. |
| `Update.yml` | Pull requests, and runs on other branches | Tests and `--verify-release`; only `main` publishes |
| `dependency-canary.yml` | Weekly and on demand | Regenerates the published revisions twice: with the locked dependencies as a control, then with the newest allowed ones. Keeps a *Dependency canary* issue open while versions, tests, exclusions, or rules differ from the control. |

Security measures:

- Actions are pinned to commit SHAs, and Dependabot keeps the pins current.
- The SQLite 3.38 test build is checked against its published SHA3-256.
- The publish job never restores an Actions cache.
- The canary runs new packages in a job without write permissions.
