# Zircolite rules

Sigma rules compiled to validated SQLite JSON rulesets for [Zircolite](https://github.com/wagga40/Zircolite). The daily workflow updates each source independently. A source that fails validation keeps its previous rulesets; [release-manifest.json](release-manifest.json) identifies their revision and marks them stale.

Generation uses **pySigma-backend-sqlite 2.0.0**, pySigma 1.5.1 or later within major version 1, and Python 3.14. Exact package versions are recorded in `pdm.lock` and the manifest. Source revisions are resolved once and downloaded as immutable snapshots. Local submodule checkouts are not used or modified; the historical backend submodule entry remains for checkout compatibility.

## Available rulesets

Every ruleset contains all available severity levels. Severity reflects the upstream author's rating, not a comparable confidence score across sources. Missing levels are recorded as informational during adaptation.

| Source | Base filenames | Intended input |
|---|---|---|
| All sources | `rules_windows_all` | Combined Windows detections from SigmaHQ and all community sources |
| SigmaHQ | `rules_windows_sysmon`, `rules_windows_generic`, `rules_windows_merged` | Windows Sysmon, Windows Audit, or both |
| SigmaHQ | `rules_linux` | Linux logs using the Sigma field names |
| Hayabusa | `rules_hayabusa_windows_native` | Windows event logs; native Channel/EventID selections |
| Joe Security | `rules_joesecurity_windows_{sysmon,generic,merged}` | Windows logs |
| Micah Babinski | `rules_mbabinski_windows_{sysmon,generic,merged}` | Windows logs |
| mdecrevoisier | `rules_mdecrevoisier_windows_{sysmon,generic,merged}` | Windows logs |
| tsale | `rules_tsale_windows_{sysmon,generic,merged}` | Windows logs |

Add `.json` to a base filename. Source-specific files remain available; community rules are not added to the SigmaHQ-only files. A profile with no usable community rules produces no ruleset. Sysmon and Generic describe conversion mappings, not exclusive log channels: both retain applicable Windows service rules, while their category mappings target Sysmon and Windows Audit respectively. Each source's merged file combines both without losing distinct SQL variants sharing an ID.

**`rules_windows_all.json` combines Windows detections from all available sources**, using each source's merged file and Hayabusa's native rules. It has no Sysmon, Generic, or severity variants and excludes Linux rules and experimental correlations. Exact duplicates are removed by ID and SQL, preferring SigmaHQ metadata and then source name order; different SQL variants remain. It is rebuilt after every non-audit update, including source-only updates, using retained rules from stale sources. Its contributing revisions, file hashes, and source licenses are recorded in `provenance/windows_all.json` and the manifest's `aggregates.windows_all` entry. Original source licenses and authorship still apply.

```bash
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules-v2/main/rules_windows_all.json
python zircolite.py --evtx logs/ --ruleset rules_windows_all.json

# Or select a single source
python zircolite.py --evtx logs/ --ruleset rules_mbabinski_windows_merged.json
```

### Migrating severity-filtered downloads

The `_medium.json` and `_high.json` downloads are retired, including experimental variants. Their old names meant **medium and above** and **high and above**, and included critical rules. Those download URLs stop working once the source is migrated; previously downloaded variants stop receiving updates. Replace old URLs with the full filename and remove or archive obsolete local copies. A failed source keeps its previous artifacts until a successful update completes its migration.

Zircolite currently has no minimum-severity CLI option; `--rulefilter` filters titles. To select a minimum severity, install `jq` and filter the downloaded JSON into a separate local file:

```bash
# Medium, high, and critical
jq '[.[] | select(.level == "medium" or .level == "high" or .level == "critical")]' \
  rules_windows_merged.json > local_rules_medium_plus.json

# High and critical
jq '[.[] | select(.level == "high" or .level == "critical")]' \
  rules_windows_merged.json > local_rules_high_plus.json
python zircolite.py --evtx logs/ --ruleset local_rules_high_plus.json
```

## Ruleset statistics

This section updates automatically after generation. Refresh it without fetching sources with `pdm run python gen_ruleset.py --update-readme-stats`; `--verify-release` checks it against the published files. Latest conversion attempts and exclusion details remain in `reports/`.

<!-- ruleset-stats:start -->

Generated from the hash-verified published artifacts. Entries count exported rule objects;
unique IDs count distinct IDs within each file. Different SQL variants can share an ID.
Profiles overlap, so their counts must not be added to estimate unique threat coverage.
Severity columns are exact levels, not minimum-severity thresholds.

### Source freshness

Stale sources retain their last successful files and counts. Unavailable sources have no published rulesets.

| Source | Status | Published revision | Last successful generation (UTC) |
|---|---|---|---|
| sigmahq | current | [07ec293a5169](https://github.com/SigmaHQ/sigma/tree/07ec293a51695cb1131a2e05260247872b31e1e1) | 2026-09-26T19:32:46+00:00 |
| hayabusa | current | [1d9f8751f6b0](https://github.com/Yamato-Security/hayabusa-rules/tree/1d9f8751f6b0f2dd3eee1d44712c6a92541f5d08) | 2026-09-26T19:33:16+00:00 |
| joesecurity | current | [cb91be06c8c9](https://github.com/joesecurity/sigma-rules/tree/cb91be06c8c95ce63aa9aa5006a7835678136a96) | 2026-09-26T19:33:19+00:00 |
| mbabinski | current | [9dea7a5c15cf](https://github.com/mbabinski/Sigma-Rules/tree/9dea7a5c15cfd422ec320e7fabd93f0c3634181d) | 2026-09-26T19:33:20+00:00 |
| mdecrevoisier | current | [d61408af8769](https://github.com/mdecrevoisier/SIGMA-detection-rules/tree/d61408af8769c74c96296b7ccc92d4bc3abb15af) | 2026-09-26T19:33:22+00:00 |
| tsale | current | [f5190e6b6c5b](https://github.com/tsale/Sigma_rules/tree/f5190e6b6c5ba9e6729845f13ac916590e90b0d8) | 2026-09-26T19:33:25+00:00 |

Combined Windows ruleset status: **current**. It includes available published Windows detections; stale sources contribute their retained rules, and unavailable sources contribute none.

### Detection rulesets

| Ruleset | Entries | Unique IDs | Informational | Low | Medium | High | Critical |
|---|---:|---:|---:|---:|---:|---:|---:|
| [rules_windows_all.json](rules_windows_all.json) | 5,773 | 3,666 | 117 | 526 | 1,969 | 2,753 | 408 |
| [rules_linux.json](rules_linux.json) | 216 | 216 | 5 | 56 | 71 | 79 | 5 |
| [rules_windows_generic.json](rules_windows_generic.json) | 2,270 | 2,270 | 11 | 162 | 901 | 1,096 | 100 |
| [rules_windows_merged.json](rules_windows_merged.json) | 4,504 | 2,820 | 17 | 294 | 1,779 | 2,209 | 205 |
| [rules_windows_sysmon.json](rules_windows_sysmon.json) | 2,820 | 2,820 | 13 | 204 | 1,114 | 1,362 | 127 |
| [rules_hayabusa_windows_native.json](rules_hayabusa_windows_native.json) | 186 | 186 | 100 | 26 | 40 | 19 | 1 |
| [rules_joesecurity_windows_generic.json](rules_joesecurity_windows_generic.json) | 110 | 110 | 0 | 1 | 0 | 1 | 108 |
| [rules_joesecurity_windows_merged.json](rules_joesecurity_windows_merged.json) | 201 | 110 | 0 | 2 | 0 | 2 | 197 |
| [rules_joesecurity_windows_sysmon.json](rules_joesecurity_windows_sysmon.json) | 110 | 110 | 0 | 1 | 0 | 1 | 108 |
| [rules_mbabinski_windows_generic.json](rules_mbabinski_windows_generic.json) | 165 | 164 | 0 | 89 | 20 | 56 | 0 |
| [rules_mbabinski_windows_merged.json](rules_mbabinski_windows_merged.json) | 364 | 208 | 0 | 200 | 44 | 120 | 0 |
| [rules_mbabinski_windows_sysmon.json](rules_mbabinski_windows_sysmon.json) | 209 | 208 | 0 | 115 | 26 | 68 | 0 |
| [rules_mdecrevoisier_windows_generic.json](rules_mdecrevoisier_windows_generic.json) | 323 | 323 | 0 | 2 | 73 | 245 | 3 |
| [rules_mdecrevoisier_windows_merged.json](rules_mdecrevoisier_windows_merged.json) | 429 | 330 | 0 | 4 | 90 | 330 | 5 |
| [rules_mdecrevoisier_windows_sysmon.json](rules_mdecrevoisier_windows_sysmon.json) | 330 | 330 | 0 | 2 | 73 | 252 | 3 |
| [rules_tsale_windows_generic.json](rules_tsale_windows_generic.json) | 46 | 46 | 0 | 0 | 8 | 38 | 0 |
| [rules_tsale_windows_merged.json](rules_tsale_windows_merged.json) | 89 | 47 | 0 | 0 | 16 | 73 | 0 |
| [rules_tsale_windows_sysmon.json](rules_tsale_windows_sysmon.json) | 47 | 47 | 0 | 0 | 9 | 38 | 0 |

### Experimental correlation rulesets

| Ruleset | Entries | Unique IDs | Informational | Low | Medium | High | Critical |
|---|---:|---:|---:|---:|---:|---:|---:|
| [rules_hayabusa_windows_native_correlation.json](experimental/rules_hayabusa_windows_native_correlation.json) | 3 | 3 | 0 | 0 | 3 | 0 | 0 |
| [rules_mbabinski_windows_generic_correlation.json](experimental/rules_mbabinski_windows_generic_correlation.json) | 2 | 2 | 0 | 0 | 2 | 0 | 0 |
| [rules_mbabinski_windows_merged_correlation.json](experimental/rules_mbabinski_windows_merged_correlation.json) | 3 | 2 | 0 | 0 | 3 | 0 | 0 |
| [rules_mbabinski_windows_sysmon_correlation.json](experimental/rules_mbabinski_windows_sysmon_correlation.json) | 2 | 2 | 0 | 0 | 2 | 0 | 0 |
| [rules_mdecrevoisier_windows_generic_correlation.json](experimental/rules_mdecrevoisier_windows_generic_correlation.json) | 7 | 7 | 0 | 0 | 0 | 7 | 0 |
| [rules_mdecrevoisier_windows_merged_correlation.json](experimental/rules_mdecrevoisier_windows_merged_correlation.json) | 7 | 7 | 0 | 0 | 0 | 7 | 0 |
| [rules_mdecrevoisier_windows_sysmon_correlation.json](experimental/rules_mdecrevoisier_windows_sysmon_correlation.json) | 7 | 7 | 0 | 0 | 0 | 7 | 0 |

<!-- ruleset-stats:end -->

## Sources and adaptations

[sources.json](sources.json) declares the repositories, branches, input directories, adapters, profiles, and licenses:

| Repository | Content | Upstream license |
|---|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Main, emerging-threat, and threat-hunting collections; Windows and Linux products | DRL 1.1 |
| [Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) | Native `hayabusa/` rules; excludes the mirrored `sigma/` collection | DRL 1.1 |
| [joesecurity/sigma-rules](https://github.com/joesecurity/sigma-rules) | Sandbox-derived Windows detections | GPL 3.0 |
| [mbabinski/Sigma-Rules](https://github.com/mbabinski/Sigma-Rules) | Malware, intrusion, and threat-report detections | GPL 3.0 |
| [mdecrevoisier/SIGMA-detection-rules](https://github.com/mdecrevoisier/SIGMA-detection-rules) | Windows and Active Directory detection content | CC0 1.0 |
| [tsale/Sigma_rules](https://github.com/tsale/Sigma_rules) | Exploitation, malware, and Windows detections | GPL 3.0 |

Adapters normalize metadata such as scalar references, nonstandard status labels, list descriptions, non-Sigma tags, and Windows/Linux product capitalization in community rules. Original values are recorded in `provenance/<source>.json`. Missing or invalid IDs receive deterministic UUIDv5 identifiers. List-valued logsources become distinct alternatives with stable variant IDs; ambiguous correlation references fail validation.

Community ATT&CK tags are lowercased, known spelling errors and technique-name aliases are corrected, and duplicate tags are removed, with original tags retained in provenance. Empty ATT&CK tags and the ambiguous `attack.privilege_execution` label are removed without guessing a tactic. Unknown malformed ATT&CK tags fail validation. This offline check accepts current hyphenated and legacy underscore tactic names and checks identifier syntax; it does not verify every identifier against the latest ATT&CK catalog.

Upstream detection predicates are not rewritten to repair invalid conditions. Legacy aggregation syntax, malformed rules, and fieldless keyword detections remain visible exclusions. Collection actions, including legacy `action: correlation` and `global`/`reset`/`repeat`, are explicitly reported as unsupported and require a reviewed exclusion to publish the source. mdecrevoisier templates containing lower-case `%organization_value%` placeholders are excluded, along with dependent correlations. Windows environment-variable literals such as `%COMSPEC%` remain intact.

Applicability is based on product, explicit event fields, and installed pipeline mappings. An empty channel allow-list does not by itself exclude a rule. Exact official duplicates are removed by ID and generated SQL; different SQL variants remain and can still overlap semantically. Conversion counts are not a measure of unique threat coverage.

Windows conversion maps the upstream field aliases `EventXML.Address`, `EventXML.Param3`, and `New Value` to Zircolite's flattened columns `Address`, `Param3`, and `NewValue`. Both SQL and `required_fields` use these names. Other identifiers retain the backend's SQLite quoting.

## Experimental correlations

Correlation rulesets live only in [experimental/](experimental/README.md), with source/profile names ending in `_correlation.json`. These files use the backend's schema version 2, `required_fields`, and `correlation_plan` contract. They require SQLite 3.38 or newer with JSON support and a consumer that understands the new correlation result format.

**They are not default Zircolite rulesets.** Zircolite 4.1.0 or newer runs them and reports alert summaries with their evidence; older versions report the alert rows as ordinary events. Generating SQL alone does not provide that application integration.

## Validation and release behavior

Each source passes through discovery, metadata adaptation, reference resolution, profile selection, conversion, SQL preparation, and artifact staging. Both `.yml` and `.yaml` files and their documents are inspected; unsupported collection actions fail validation unless explicitly excluded. Reference-only rules stay available to selected correlations but are not accidentally exported; `generate: true` retains requested standalone outputs. Excluded correlations do not suppress otherwise applicable standalone detections. Local severity filtering operates on complete converted entries, preserving embedded correlation dependencies.

Every exported query is prepared in a fresh SQLite database with its declared fields and double-quoted string fallback disabled. ATT&CK tag format and regex literals are checked before export. Correlation standalone SQL and materialized plans are both validated. Tests execute positive and negative fixtures using Zircolite's flattened Windows columns, backend detection fixes, correlation windows/evidence, and all eight correlation types on SQLite 3.38 in CI.

[exclusions.json](exclusions.json) is a reviewed baseline for known upstream conversion failures. Each record binds the source, file hash, document, profile, stage, and exact error, with a reason. A changed file or error does not silently inherit approval. Policy exclusions such as another platform, deprecated status, or an unmapped logsource are listed separately in reports.

Successful sources replace their artifacts only after validation. Unexpected source failures leave the last good artifacts and provenance intact. CI publishes successful sources, failure status, and updated README statistics, then marks the run failed if any source failed. It verifies artifact hashes, counts, and README statistics before committing and never upgrades converter dependencies during the daily update.

- `release-manifest.json`: current/stale/unavailable source status, exact revisions, tool versions, counts, artifact hashes, last successful generation, and the combined Windows ruleset's input lineage under `aggregates.windows_all`.
- `reports/<source>.json`: latest attempt, including errors, exclusions, and profile counts.
- `provenance/<source>.json`: report belonging to the last successful artifacts, including original metadata adaptations and the official revision/artifact hashes used for community duplicate removal.
- `licenses/<source>.txt`: license text from the recorded source revision. Original YAML is available at `https://github.com/<repository>/tree/<revision>` using the repository and revision in the manifest.

The older `*_conversion.log` and `*_no_channel.log` files have been replaced by these reports. Passing conversion and preparation validates the generated SQL, not detection accuracy on every possible log schema. Future upstream defects are handled by release gates rather than a promise of error-free generation.

## Regenerating and testing

Use Python 3.14 and PDM:

```bash
pdm sync --no-self -G test
pdm run pytest -q
pdm run python gen_ruleset.py
pdm run python gen_ruleset.py --verify-release
```

The workflow runs daily at **01:23 UTC**, on manual dispatch, and when generation code/configuration changes. Pull requests run tests and verify checked-in artifacts and README statistics without publishing rules. Non-audit generation refreshes the README when the output directory contains one with the statistics markers.

```bash
# Audit without changing rulesets or the release manifest
pdm run python gen_ruleset.py --audit --output-dir build/audit

# Update just one source, comparing it with the current official output
pdm run python gen_ruleset.py --sources hayabusa

# Convert a source at a pinned revision (also match its official baseline to reproduce output)
pdm run python gen_ruleset.py --sources tsale --revision tsale=FULL_40_CHARACTER_SHA

# Explicit local input; provenance records a local content hash
pdm run python gen_ruleset.py --sources sigmahq --source-root sigmahq=./sigma --output-dir build/local
```

Community outputs depend on both the source revision and the official duplicate-removal baseline. To reproduce them, first generate SigmaHQ at the `official_baseline.revision` recorded in the community provenance, using the same tools and configuration, then generate the community source at its recorded revision. Verify that the official input hashes match `official_baseline.artifacts`. A source-only run uses the published official detections and correlations in its output directory; an empty directory has no official baseline. Audits write reports only and leave rulesets, the manifest, and README unchanged.

The source cache is under `.cache/rule-sources/`. Do not edit cached snapshots. To review a new failure, inspect its upstream YAML and the corresponding report, then fix the adapter or manually add a narrowly scoped exclusion with its exact hash and a reason. No command automatically approves newly failed rules. Dependency upgrades require a deliberate lock update (`pdm lock -G test`) and a full validation run.

Set `SQLITE_MIN_BINARY` to a SQLite 3.38 CLI to run the minimum-version tests locally; otherwise those 16 cases are skipped. CI builds this version explicitly.

## Licensing

Project code is declared MIT in `pyproject.toml`. Converted rules retain their source licenses and author metadata; they are not collectively relicensed as MIT. See [licenses/README.md](licenses/README.md) and the per-source license texts.
