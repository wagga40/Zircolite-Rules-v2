import sys
from pathlib import Path

# Add local pySigma-backend-sqlite to path before importing
sys.path.insert(0, str(Path(__file__).parent / "pySigma-backend-sqlite"))

from sigma.collection import SigmaCollection

# import pysigma-backend-sqlite from local folder
from sigma.backends.sqlite import sqliteBackend

from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline, windows_audit_pipeline

import json
from datetime import datetime

# Paths
rules_path_windows = r"./sigma/rules/windows/"
rules_path_linux = r"./sigma/rules/linux/"

# Ruleset configurations
# Format: (suffix, output_filename_template)
RULESET_CONFIGS = {
    "sysmon": "rules_windows_sysmon",
    "generic": "rules_windows_generic",
    "linux": "rules_linux",
}

# Level configurations for filtering
# Each entry: (suffix, min_level_index) - levels at or above this index are included
LEVEL_ORDER = ["informational", "low", "medium", "high", "critical"]
LEVEL_FILTERS = [
    ("", None),                    # All rules (no suffix, no filter)
    ("_medium", "medium"),         # Medium to critical
    ("_high", "high"),             # High to critical
]

def write_conversion_log(log_filename, name, total_rules, successful_rules, failed_rules):
    """Write a detailed conversion log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open(log_filename, 'w') as log:
        log.write(f"{'='*80}\n")
        log.write(f"SIGMA RULE CONVERSION LOG - {name.upper()}\n")
        log.write(f"{'='*80}\n")
        log.write(f"Timestamp: {timestamp}\n")
        log.write(f"Total rules processed: {total_rules}\n")
        log.write(f"Successful conversions: {len(successful_rules)}\n")
        log.write(f"Failed conversions: {len(failed_rules)}\n")
        log.write(f"Success rate: {len(successful_rules)/total_rules*100:.1f}%\n")
        log.write(f"{'='*80}\n\n")
        
        # Failed rules section
        log.write(f"FAILED RULES ({len(failed_rules)})\n")
        log.write(f"{'-'*80}\n")
        if failed_rules:
            for rule in failed_rules:
                log.write(f"\nPath:  {rule['path']}\n")
                log.write(f"Title: {rule['title']}\n")
                log.write(f"ID:    {rule['id']}\n")
                log.write(f"Error: {rule['error']}\n")
        else:
            log.write("No failed rules.\n")
        
        log.write(f"\n{'='*80}\n")
        log.write(f"SUCCESSFUL RULES ({len(successful_rules)})\n")
        log.write(f"{'-'*80}\n")
        for rule in successful_rules:
            log.write(f"{rule['path']}\n")
    
    print(f'[+] Log written to {log_filename}')


def convert_rule(backend, rule):
    """Convert a single rule, returning (result, error_info) tuple."""
    rule_path = str(getattr(rule.source, 'path', 'unknown') if rule.source else 'unknown')
    rule_title = getattr(rule, 'title', 'unknown')
    rule_id = str(getattr(rule, 'id', 'unknown'))
    
    try: 
        result = backend.convert_rule(rule, "zircolite")[0]
        return (result, None)
    except Exception as e:
        error_info = {
            'path': rule_path,
            'title': rule_title,
            'id': rule_id,
            'error': str(e)[:200]  # Truncate long error messages
        }
        return (None, error_info)

def ruleset_generator(name, base_output_name, input_rules, pipelines=None):
    """Generate ruleset and return the rules (does not save to file).
    If pipelines is None or empty, no pipeline is used (rules converted as-is)."""
    print(f'[+] Initialisation ruleset : {name}')
    if pipelines:
        # Add pipelines to one another
        combined_pipeline = pipelines[0]
        for pipeline in pipelines[1:]:
            combined_pipeline += pipeline
        sqlite_backend = sqliteBackend(combined_pipeline)
    else:
        # No pipeline: convert rules as-is (e.g. for Linux rules)
        sqlite_backend = sqliteBackend(None)

    rules = Path(input_rules)
    if rules.is_dir():
        pattern = "*.yml"
        rule_list = list(rules.rglob(pattern))
    else:
        sys.exit(f"Log path {rules} is not a directory")
    
    rule_collection = SigmaCollection.load_ruleset(rule_list)

    ruleset = []
    failed_rules = []
    successful_rules = []

    total_rules = len(rule_collection)
    print(f'[+] Conversion : {name} ({total_rules} rules)')

    # Process rules sequentially to avoid multiprocessing serialization issues
    # with pySigma's transformed detection items
    for i, rule in enumerate(rule_collection, 1):
        if i % 100 == 0 or i == total_rules:
            print(f'    Processing: {i}/{total_rules}', end='\r')
        
        result, error_info = convert_rule(sqlite_backend, rule)
        
        if result is not None:
            ruleset.append(result)
            successful_rules.append({
                'path': str(getattr(rule.source, 'path', 'unknown') if rule.source else 'unknown'),
                'title': getattr(rule, 'title', 'unknown'),
                'id': str(getattr(rule, 'id', 'unknown'))
            })
        else:
            failed_rules.append(error_info)
    
    print()  # New line after progress
    
    if failed_rules:
        print(f'[!] {len(failed_rules)} rules failed conversion')
    
    # Sort by level (low to critical)
    ruleset = sorted(ruleset, key=lambda d: LEVEL_ORDER.index(d.get('level', 'informational')))
    
    print(f'[+] Done: {len(ruleset)} rules converted')
    
    # Write conversion log
    log_filename = f"{base_output_name}_conversion.log"
    write_conversion_log(log_filename, name, total_rules, successful_rules, failed_rules)
    
    return ruleset


def filter_ruleset_by_level(ruleset, min_level):
    """Filter ruleset to include only rules at or above the minimum level."""
    if min_level is None:
        return ruleset
    
    min_level_index = LEVEL_ORDER.index(min_level)
    filtered = [
        rule for rule in ruleset 
        if LEVEL_ORDER.index(rule.get('level', 'informational')) >= min_level_index
    ]
    return filtered


def save_filtered_rulesets(base_name, ruleset):
    """Save filtered versions of the ruleset based on LEVEL_FILTERS."""
    for suffix, min_level in LEVEL_FILTERS:
        filtered = filter_ruleset_by_level(ruleset, min_level)
        output_filename = f"{base_name}{suffix}.json"
        
        with open(output_filename, 'w') as outfile:
            json.dump(filtered, outfile, indent=4, ensure_ascii=True)
        
        level_desc = f"{min_level}+" if min_level else "all"
        print(f'[+] Saved {output_filename}: {len(filtered)} rules ({level_desc})')


if __name__ == '__main__':
    # Generate sysmon ruleset
    sysmon_rules = ruleset_generator(
        "sysmon", 
        RULESET_CONFIGS["sysmon"], 
        rules_path_windows, 
        [sysmon_pipeline(), windows_logsource_pipeline()]
    )
    save_filtered_rulesets(RULESET_CONFIGS["sysmon"], sysmon_rules)
    
    print()  # Separator
    
    # Generate generic ruleset
    generic_rules = ruleset_generator(
        "generic", 
        RULESET_CONFIGS["generic"], 
        rules_path_windows, 
        [windows_audit_pipeline(), windows_logsource_pipeline()]
    )
    save_filtered_rulesets(RULESET_CONFIGS["generic"], generic_rules)

    print()  # Separator

    # Generate Linux ruleset (no pipeline)
    linux_rules = ruleset_generator(
        "linux",
        RULESET_CONFIGS["linux"],
        rules_path_linux,
        pipelines=None,
    )
    save_filtered_rulesets(RULESET_CONFIGS["linux"], linux_rules)
