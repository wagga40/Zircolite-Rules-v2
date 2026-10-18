# Sources

Status, revisions, and counts are on the [dashboard](dashboard.md). Each source is declared in [sources.json](../sources.json):

- repository and branch;
- rule directories and optional `exclude` glob patterns for non-rule YAML;
- adapter, profiles, and license.

| Source | Repository | Content | License |
|---|---|---|---|
| sigmahq | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Main, emerging-threat, and threat-hunting rules | DRL 1.1 |
| hayabusa | [Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) | Native `hayabusa/` rules; its mirrored copy of SigmaHQ is not used | DRL 1.1 |
| joesecurity | [joesecurity/sigma-rules](https://github.com/joesecurity/sigma-rules) | Sandbox-derived Windows detections | GPL 3.0 |
| mbabinski | [mbabinski/Sigma-Rules](https://github.com/mbabinski/Sigma-Rules) | Malware, intrusion, and threat-report detections | GPL 3.0 |
| mdecrevoisier | [mdecrevoisier/SIGMA-detection-rules](https://github.com/mdecrevoisier/SIGMA-detection-rules) | Windows and Active Directory detections | CC0 1.0 |
| tsale | [tsale/Sigma_rules](https://github.com/tsale/Sigma_rules) | Exploitation, malware, and Windows detections | GPL 3.0 |
| lolrmm | [magicsword-io/LOLRMM](https://github.com/magicsword-io/LOLRMM) | Remote monitoring and management tools; legitimate RMM use matches too | Apache 2.0 |
| loldrivers | [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Six aggregated vulnerable and malicious driver rules for Sysmon driver loads | Apache 2.0 |
| reversinglabs | [reversinglabs/reversinglabs-siem-rules](https://github.com/reversinglabs/reversinglabs-siem-rules) | Ransomware detections | MIT |
| hatchepsoute | [Hatchepsoute/sigma-rules](https://github.com/Hatchepsoute/sigma-rules) | Vulnerability and campaign packs; some rules are broad | Apache 2.0 |
| wrg11 | [WRG-11/wrg-sigma-rules](https://github.com/WRG-11/wrg-sigma-rules) | Detections and correlations from `resources/examples/` | MIT |
| tyrian | [zshguy/tyrian-detection-pack](https://github.com/zshguy/tyrian-detection-pack) | Windows and Linux hunting rules | MIT |
| dragon | [frknaykc/Dragon-ThreatResearchHQ](https://github.com/frknaykc/Dragon-ThreatResearchHQ) | Threat-research detections | MIT |

## What is adapted

Community rules get metadata fixes only; detection logic is never rewritten. Each change is recorded with its original value in `provenance/<source>.json`.

- Scalar references, list descriptions, nonstandard status labels, and the capitalization of Windows and Linux product names are normalized.
- Missing or invalid IDs get deterministic UUIDv5 IDs.
- List-valued logsources become separate variants with stable IDs.
- ATT&CK tags are lowercased, known misspellings and technique-name aliases are corrected, and duplicates are removed. Unknown malformed ATT&CK tags fail validation.
- The Windows field aliases `EventXML.Address`, `EventXML.Param3`, and `New Value` map to Zircolite's `Address`, `Param3`, and `NewValue` columns.

## What is left out

| Rules | Reason |
|---|---|
| Other platforms (macOS, cloud, network, …) and log sources with no mapping in a profile | Outside the Windows and Linux profiles |
| Status `deprecated` or `unsupported` | Retired upstream |
| Keyword (fieldless) detections | They need a full-text column that Zircolite does not have |
| Legacy `\| count()` aggregations and collection actions | They need an authored Sigma correlation |
| Regexes with lookarounds or repeats over 1000 | pySigma 2 checks `\|re` values with RE2 |
| mdecrevoisier templates with `%organization_value%` placeholders | They need site-specific values |
| Invalid upstream rules | They are not repaired |

Policy exclusions are listed per source in `reports/<source>.json`.

A conversion failure blocks publication unless [exclusions.json](../exclusions.json) has a reviewed record for that rule or for its class of failure; see [Exclusions](maintenance.md#exclusions).
