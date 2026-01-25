# Zircolite Rules

Pre-compiled Sigma rules converted to Zircolite JSON format, updated daily.

This repository automatically converts the [SigmaHQ](https://github.com/SigmaHQ/sigma) detection rules into JSON rulesets compatible with [Zircolite](https://github.com/wagga40/Zircolite), a standalone SIGMA-based detection tool for EVTX, Auditd, and Sysmon for Linux logs.

## Available Rulesets

The repository provides two ruleset types, each filtered by severity level:

### Sysmon Rulesets
For use with Sysmon event logs:
| File | Description |
|------|-------------|
| `rules_windows_sysmon.json` | All severity levels |
| `rules_windows_sysmon_medium.json` | Medium, High, and Critical only |
| `rules_windows_sysmon_high.json` | High and Critical only |

### Generic (Windows Audit) Rulesets
For use with standard Windows event logs:
| File | Description |
|------|-------------|
| `rules_windows_generic.json` | All severity levels |
| `rules_windows_generic_medium.json` | Medium, High, and Critical only |
| `rules_windows_generic_high.json` | High and Critical only |

## Usage

### Download and Use with Zircolite

Download the ruleset you need and use it with Zircolite:

```bash
# Using Sysmon rules
python3 zircolite.py --evtx logs/ --ruleset rules_windows_sysmon.json

# Using generic Windows rules (high severity only)
python3 zircolite.py --evtx logs/ --ruleset rules_windows_generic_high.json
```

### Direct Download Links

You can download the latest rulesets directly:

```bash
# Sysmon rulesets
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules/main/rules_windows_sysmon.json
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules/main/rules_windows_sysmon_medium.json
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules/main/rules_windows_sysmon_high.json

# Generic rulesets
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules/main/rules_windows_generic.json
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules/main/rules_windows_generic_medium.json
curl -O https://raw.githubusercontent.com/wagga40/Zircolite-Rules/main/rules_windows_generic_high.json
```

## How It Works

1. **Sigma Rules**: The official [SigmaHQ rules repository](https://github.com/SigmaHQ/sigma) is included as a Git submodule
2. **pySigma Backend**: Uses [pySigma-backend-sqlite](https://github.com/SigmaHQ/pySigma-backend-sqlite) to convert Sigma YAML rules to Zircolite's JSON format
3. **Pipelines**: Applies appropriate field mappings via pySigma pipelines:
   - **Sysmon**: `sysmon_pipeline` + `windows_logsource_pipeline`
   - **Generic**: `windows_audit_pipeline` + `windows_logsource_pipeline`
4. **Filtering**: Rules are sorted and filtered by severity level (informational, low, medium, high, critical)

## Automatic Updates

A GitHub Actions workflow runs daily at 1:00 AM UTC to:
1. Pull the latest Sigma rules from SigmaHQ
2. Convert all Windows rules to Zircolite format
3. Commit and push updated rulesets

## Conversion Logs

Each ruleset generation produces a detailed log file (`*_conversion.log`) containing:
- Total rules processed
- Success/failure counts and rates
- List of failed rules with error messages
- List of successfully converted rules

## Related Projects

- [Zircolite](https://github.com/wagga40/Zircolite) - SIGMA-based detection tool
- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM systems
- [pySigma](https://github.com/SigmaHQ/pySigma) - Python library for Sigma rule handling

## License

MIT License - See [LICENSE](LICENSE) for details.
