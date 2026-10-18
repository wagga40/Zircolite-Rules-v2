# Experimental correlation rulesets

What these files are, and what Zircolite and SQLite versions they need: [Rulesets](../docs/rulesets.md#experimental-correlations). This page is for applications that run them.

- Windows timestamps use `SystemTime` in ISO format; evidence records use `row_id` in the `logs` table.
- Analyze related files in one database: a correlation only sees the events in its own.
- Keep `required_fields`, `result_type`, `schema_version`, and `correlation_plan`. `sigma.backends.sqlite.runtime.execute_plan` returns the alerts, their event evidence, and diagnostics.
- An alert describes a qualifying window: its group keys, metric, and evidence. It is not an event row.
- Events with a missing group key or an invalid timestamp are excluded, and an incomplete absence window raises no alert. Keep these diagnostics.
- Each source and profile has one file with every severity. Dependencies, including low-severity reference-only rules, are embedded at conversion, so a filter must keep whole entries and their plans.

For the result contract, see the [backend migration guide](https://github.com/SigmaHQ/pySigma-backend-sqlite/blob/v2.1.1/docs/migration-v2.md). Source revisions, licenses, and counts are in [the release manifest](../release-manifest.json).
