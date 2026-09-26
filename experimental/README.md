# Experimental correlation rulesets

These files are generated and SQL-validated, but require integration with backend 2.0's correlation result contract in the consuming application. Zircolite 4.1.0 or newer runs them; older versions report their alert rows as ordinary events. Do not substitute them for the ordinary detection rulesets.

- SQLite >=3.38 with JSON functions is required.
- Windows timestamps use `SystemTime` in ISO format; evidence records use `row_id` in the `logs` table.
- Related files must be analyzed in a unified database for cross-file correlation.
- Preserve `required_fields`, `result_type`, `schema_version`, and `correlation_plan`. Use `sigma.backends.sqlite.runtime.execute_plan` to obtain alerts, event evidence, and diagnostics.
- Results describe qualifying occurrences, windows, group keys, metrics, and evidence. They are not ordinary event rows.
- Missing group keys and invalid timestamps exclude events; incomplete absence windows do not produce alerts. Preserve these diagnostics in the application.
- Each source/profile has one full-severity file. Dependencies, including low-severity reference-only rules, are embedded during conversion. Local filtering must preserve complete entries and their plans; see the [severity migration instructions](../README.md#migrating-severity-filtered-downloads).

For the result contract, see the [backend 2.0 migration guide](https://github.com/SigmaHQ/pySigma-backend-sqlite/blob/v2.0.0/docs/migration-v2.md). Source revisions, licenses, and counts are in [the release manifest](../release-manifest.json).
