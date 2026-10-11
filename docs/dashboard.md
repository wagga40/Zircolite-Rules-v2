# Ruleset dashboard

Generated from the verified release on every update; do not edit.

| Sources | Detection rulesets | [`rules_windows_all.json`](../rules_windows_all.json) | Linux rules | Experimental correlations | Last update (UTC) |
|---|---:|---|---:|---:|---|
| 6 (all current) | 18 | 5,789 rules, 3,676 unique | 216 | 12 | 2026-10-09 |

## Sources

| Source | Status | License | Revision | Last success (UTC) | Detection rules |
|---|---|---|---|---|---:|
| [sigmahq](https://github.com/SigmaHQ/sigma) | current | DRL-1.1 | [8a4813404ea3](https://github.com/SigmaHQ/sigma/tree/8a4813404ea3074890e0cda9272d4d1a8b2941d6) | 2026-10-08 07:29 | 3,044 |
| [hayabusa](https://github.com/Yamato-Security/hayabusa-rules) | current | DRL-1.1 | [04af3d207cae](https://github.com/Yamato-Security/hayabusa-rules/tree/04af3d207cae784183e0e5e82c1132ee866bbd67) | 2026-10-09 07:28 | 188 |
| [joesecurity](https://github.com/joesecurity/sigma-rules) | current | GPL-3.0 | [cb91be06c8c9](https://github.com/joesecurity/sigma-rules/tree/cb91be06c8c95ce63aa9aa5006a7835678136a96) | 2026-10-08 07:30 | 110 |
| [mbabinski](https://github.com/mbabinski/Sigma-Rules) | current | GPL-3.0 | [9dea7a5c15cf](https://github.com/mbabinski/Sigma-Rules/tree/9dea7a5c15cfd422ec320e7fabd93f0c3634181d) | 2026-10-08 07:30 | 208 |
| [mdecrevoisier](https://github.com/mdecrevoisier/SIGMA-detection-rules) | current | CC0-1.0 | [d61408af8769](https://github.com/mdecrevoisier/SIGMA-detection-rules/tree/d61408af8769c74c96296b7ccc92d4bc3abb15af) | 2026-10-08 07:30 | 330 |
| [tsale](https://github.com/tsale/Sigma_rules) | current | GPL-3.0 | [f5190e6b6c5b](https://github.com/tsale/Sigma_rules/tree/f5190e6b6c5ba9e6729845f13ac916590e90b0d8) | 2026-10-08 07:30 | 47 |

## Inside `rules_windows_all.json`

Counts are distinct rules; a rule with several tactics counts once per tactic.

| Info | Low | Medium | High | Critical |
|---:|---:|---:|---:|---:|
| 113 | 348 | 1,253 | 1,727 | 239 |

| ATT&CK tactic | Rules |
|---|---:|
| Reconnaissance | 14 |
| Resource Development | 28 |
| Initial Access | 111 |
| Execution | 1,009 |
| Persistence | 774 |
| Privilege Escalation | 616 |
| Defense Evasion | 195 |
| Defense Impairment | 333 |
| Stealth | 933 |
| Credential Access | 326 |
| Discovery | 200 |
| Lateral Movement | 193 |
| Collection | 80 |
| Command and Control | 255 |
| Exfiltration | 61 |
| Impact | 96 |
| (no tactic tag) | 255 |

| Log source (top 15) | Rules |
|---|---:|
| process_creation | 1,759 |
| service: security | 334 |
| file_event | 245 |
| registry_set | 232 |
| ps_script | 220 |
| image_load | 128 |
| service: system | 100 |
| service: sysmon | 80 |
| ps_module | 70 |
| network_connection | 69 |
| registry_event | 50 |
| process_access | 36 |
| ps_classic_script | 35 |
| service: application | 31 |
| dns_query | 29 |

## Detection rulesets

| Ruleset | Entries | Unique IDs | Info | Low | Medium | High | Critical |
|---|---:|---:|---:|---:|---:|---:|---:|
| [rules_windows_all.json](../rules_windows_all.json) | 5,789 | 3,676 | 117 | 526 | 1,975 | 2,763 | 408 |
| [rules_linux.json](../rules_linux.json) | 216 | 216 | 5 | 56 | 71 | 79 | 5 |
| [rules_windows_generic.json](../rules_windows_generic.json) | 2,277 | 2,277 | 11 | 162 | 904 | 1,100 | 100 |
| [rules_windows_merged.json](../rules_windows_merged.json) | 4,518 | 2,828 | 17 | 294 | 1,785 | 2,217 | 205 |
| [rules_windows_sysmon.json](../rules_windows_sysmon.json) | 2,828 | 2,828 | 13 | 204 | 1,118 | 1,366 | 127 |
| [rules_hayabusa_windows_native.json](../rules_hayabusa_windows_native.json) | 188 | 188 | 100 | 26 | 40 | 21 | 1 |
| [rules_joesecurity_windows_generic.json](../rules_joesecurity_windows_generic.json) | 110 | 110 | 0 | 1 | 0 | 1 | 108 |
| [rules_joesecurity_windows_merged.json](../rules_joesecurity_windows_merged.json) | 201 | 110 | 0 | 2 | 0 | 2 | 197 |
| [rules_joesecurity_windows_sysmon.json](../rules_joesecurity_windows_sysmon.json) | 110 | 110 | 0 | 1 | 0 | 1 | 108 |
| [rules_mbabinski_windows_generic.json](../rules_mbabinski_windows_generic.json) | 165 | 164 | 0 | 89 | 20 | 56 | 0 |
| [rules_mbabinski_windows_merged.json](../rules_mbabinski_windows_merged.json) | 364 | 208 | 0 | 200 | 44 | 120 | 0 |
| [rules_mbabinski_windows_sysmon.json](../rules_mbabinski_windows_sysmon.json) | 209 | 208 | 0 | 115 | 26 | 68 | 0 |
| [rules_mdecrevoisier_windows_generic.json](../rules_mdecrevoisier_windows_generic.json) | 323 | 323 | 0 | 2 | 73 | 245 | 3 |
| [rules_mdecrevoisier_windows_merged.json](../rules_mdecrevoisier_windows_merged.json) | 429 | 330 | 0 | 4 | 90 | 330 | 5 |
| [rules_mdecrevoisier_windows_sysmon.json](../rules_mdecrevoisier_windows_sysmon.json) | 330 | 330 | 0 | 2 | 73 | 252 | 3 |
| [rules_tsale_windows_generic.json](../rules_tsale_windows_generic.json) | 46 | 46 | 0 | 0 | 8 | 38 | 0 |
| [rules_tsale_windows_merged.json](../rules_tsale_windows_merged.json) | 89 | 47 | 0 | 0 | 16 | 73 | 0 |
| [rules_tsale_windows_sysmon.json](../rules_tsale_windows_sysmon.json) | 47 | 47 | 0 | 0 | 9 | 38 | 0 |

## Experimental correlation rulesets

Zircolite 4.1 or newer runs these; see [experimental/](../experimental/README.md).

| Ruleset | Entries | Unique IDs | Info | Low | Medium | High | Critical |
|---|---:|---:|---:|---:|---:|---:|---:|
| [rules_hayabusa_windows_native_correlation.json](../experimental/rules_hayabusa_windows_native_correlation.json) | 3 | 3 | 0 | 0 | 3 | 0 | 0 |
| [rules_mbabinski_windows_generic_correlation.json](../experimental/rules_mbabinski_windows_generic_correlation.json) | 2 | 2 | 0 | 0 | 2 | 0 | 0 |
| [rules_mbabinski_windows_merged_correlation.json](../experimental/rules_mbabinski_windows_merged_correlation.json) | 3 | 2 | 0 | 0 | 3 | 0 | 0 |
| [rules_mbabinski_windows_sysmon_correlation.json](../experimental/rules_mbabinski_windows_sysmon_correlation.json) | 2 | 2 | 0 | 0 | 2 | 0 | 0 |
| [rules_mdecrevoisier_windows_generic_correlation.json](../experimental/rules_mdecrevoisier_windows_generic_correlation.json) | 7 | 7 | 0 | 0 | 0 | 7 | 0 |
| [rules_mdecrevoisier_windows_merged_correlation.json](../experimental/rules_mdecrevoisier_windows_merged_correlation.json) | 7 | 7 | 0 | 0 | 0 | 7 | 0 |
| [rules_mdecrevoisier_windows_sysmon_correlation.json](../experimental/rules_mdecrevoisier_windows_sysmon_correlation.json) | 7 | 7 | 0 | 0 | 0 | 7 | 0 |

Entries are exported rule objects; SQL variants of one rule share its ID. Profiles overlap, so do not add counts across files. Severity columns are exact levels.
