# Zircolite rules

[![Validate and publish](https://github.com/wagga40/Zircolite-Rules-v2/actions/workflows/Update.yml/badge.svg)](https://github.com/wagga40/Zircolite-Rules-v2/actions/workflows/Update.yml)

Ready-to-use [Zircolite](https://github.com/wagga40/Zircolite) rulesets, converted daily from SigmaHQ and community Sigma repositories and validated before release.

<!-- ruleset-stats:start -->

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/overview-dark.svg">
  <img alt="13 of 13 sources current; 7,344 rules in rules_windows_all.json (4,696 unique); 299 Linux rules; 31 experimental correlations; updated 2026-10-12. Severity of unique detections: informational 114, low 351, medium 2,078, high 1,867, critical 290." src="docs/assets/overview-light.svg" width="100%">
</picture>

Every ruleset, source, severity, ATT&CK tactic, and log source: [dashboard](docs/dashboard.md).

<!-- ruleset-stats:end -->

## Quick start

```bash
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules-v2/main/rules_windows_all.json
python zircolite.py --evtx logs/ --ruleset rules_windows_all.json
```

## Which ruleset?

| Logs | File |
|---|---|
| Windows, every source | `rules_windows_all.json` |
| Windows with Sysmon (SigmaHQ) | `rules_windows_sysmon.json` |
| Windows audit logs without Sysmon (SigmaHQ) | `rules_windows_generic.json` |
| Windows, both (SigmaHQ) | `rules_windows_merged.json` |
| Linux (SigmaHQ) | `rules_linux.json` |
| One community source | `rules_<source>_windows_{sysmon,generic,merged,native}.json`, `rules_<source>_linux.json` |
| Correlations, Zircolite 4.1+ | `experimental/*_correlation.json` (experimental) |

Every file holds all severity levels. Filter with `jq`, for example by severity or by the `source` and `license` each rule records:

```bash
jq '[.[] | select(.level == "high" or .level == "critical")]' rules_windows_all.json > high_plus.json
```

## Documentation

- [Dashboard](docs/dashboard.md): sources, freshness, counts, severities, ATT&CK tactics, and log sources, regenerated on every update.
- [Rulesets](docs/rulesets.md): profiles, the combined file, rule fields, filtering, and correlations.
- [Sources](docs/sources.md): repositories, licenses, and what is adapted or left out.
- [Maintenance](docs/maintenance.md): regenerating, validation, dependency upgrades, and CI.

## License

The generator is MIT. Rules keep their upstream licenses and authorship (DRL 1.1, GPL 3.0, CC0 1.0, Apache 2.0, MIT); see [licenses/](licenses/README.md).
