import json
import re
import uuid
from pathlib import Path

import pytest
from test_generation import SPEC, detection, source

from exclusion_records import CLASS_STAGES, approval, check_exclusions, matches, normalize_error, subsumes
from rule_conversion import compile_source

ROOT = Path(__file__).resolve().parents[1]
RECORDS = json.loads((ROOT / "exclusions.json").read_text())
FAILURE = {"path": "rules/a.yml", "sha256": "1" * 64, "document": "0", "stage": "convert", "profile": "sysmon",
           "error": "Unbalanced parentheses or expression syntax error, found 'OR'  (at char 48), (line:1, col:49)"}
RECORD = {**FAILURE, "source": "test", "reason": "Reviewed"}
KEYWORDS = "Keyword search requires fulltext_field and a populated TEXT column; configure fulltext_field and " \
           "re-ingest old events."
CLASS = {"class": "fulltext-keywords", "source": "*", "stage": "convert", "profile": "*",
         "error_pattern": re.escape(KEYWORDS), "reason": "Zircolite has no full-text column"}


def by_class(name):
    return next(record for record in RECORDS if record.get("class") == name)


def test_positions_are_normalized_and_nothing_else():
    yaml_error = 'expected <block end>\n  in "<byte string>", line 19, column 2:\n     selection2:'
    assert normalize_error(yaml_error) == 'expected <block end>\n  in "<byte string>", line #, column #:\n     selection2:'
    assert normalize_error(FAILURE["error"]).endswith("(at char #), (line:#, col:#)")
    regex = "Regular expression 'a{1,3} line 4, column 5' is invalid"
    assert normalize_error(regex) == regex
    assert normalize_error(normalize_error(yaml_error)) == normalize_error(yaml_error)
    assert normalize_error(None) == ""


def test_a_moved_error_still_matches_its_record():
    moved = {**FAILURE, "error": FAILURE["error"].replace("48", "52").replace("49", "53")}
    assert matches(RECORD, "test", moved)
    assert not matches(RECORD, "test", {**moved, "error": moved["error"].replace("'OR'", "'AND'")})


def test_an_any_profile_record_matches_every_profile_but_not_the_reverse():
    everywhere = {**RECORD, "profile": "*"}
    assert all(matches(everywhere, "test", {**FAILURE, "profile": profile}) for profile in ("sysmon", "generic"))
    assert not matches(RECORD, "test", {**FAILURE, "profile": "*"})
    assert not matches(RECORD, "test", {**FAILURE, "profile": "generic"})


def test_a_draft_approves_nothing():
    assert not matches({**RECORD, "reason": ""}, "test", FAILURE)
    assert not matches({**CLASS, "reason": ""}, "test", {**FAILURE, "error": KEYWORDS})


def test_a_class_record_approves_new_keyword_rules_without_drift(tmp_path):
    rule = detection(id=str(uuid.uuid4()), detection={"keywords": ["mimikatz"], "condition": "keywords"})
    _, report = compile_source("test", SPEC, source(tmp_path, [detection(), rule]), [CLASS])
    assert report["status"] == "validated" and len(report["failures"]) == 2
    assert all(failure["approved"] and "drifted" not in failure for failure in report["failures"])


@pytest.mark.parametrize("change", [
    {"stage": "validate"}, {"stage": "yaml", "profile": "*"}, {"error": KEYWORDS + " (while converting)"},
    {"error": "Note: " + KEYWORDS}, {"error": KEYWORDS + "\nsecond line"}])
def test_a_class_record_never_approves_outside_its_pattern(change):
    assert matches(CLASS, "test", {**FAILURE, "error": KEYWORDS})
    assert not matches(CLASS, "test", {**FAILURE, "error": KEYWORDS, **change})


def test_a_class_record_is_scoped_by_source_and_profile():
    failure = {**FAILURE, "error": KEYWORDS}
    assert not matches({**CLASS, "source": "other"}, "test", failure)
    assert not matches({**CLASS, "profile": "generic"}, "test", failure)
    # A class approves what it matches; it never stands in for a rule record's drift.
    assert approval("test", failure, [CLASS]) == {"approved": True}
    assert not matches(CLASS, "test", failure, ignore=("sha256",))


def test_the_regex_classes_cover_only_what_python_accepts_and_re2_rejects():
    def parse_failure(pattern, reason):
        return {**FAILURE, "stage": "parse", "profile": "*",
                "error": f"Regular expression '{pattern}' is invalid: b'{reason}'"}
    records = [by_class("re2-lookaround"), by_class("re2-repetition")]
    # The messages RE2 gives for these patterns.
    for pattern, reason in (("a(?!b)", "invalid perl operator: (?!"), ("(?<=a)b", "invalid perl operator: (?<="),
                            ("(?<!a)b", "invalid perl operator: (?<!"), ("a(?=b)", "invalid perl operator: (?="),
                            ("a{1500,}", "invalid repetition size: {1500,}"),
                            ("a{2,1500}", "invalid repetition size: {2,1500}")):
        assert approval("test", parse_failure(pattern, reason), records)["approved"]
    for pattern, reason in (("(?P<n>a)(?P=n)", "invalid perl operator: (?P"),
                            ("a**", "bad repetition operator: **"), ("(a", "missing ): (a")):
        assert not approval("test", parse_failure(pattern, reason), records)["approved"]


def test_a_class_record_subsumes_only_reviewed_records_it_matches():
    rule = {**RECORD, "error": KEYWORDS}
    assert subsumes(CLASS, rule)
    assert not subsumes(CLASS, RECORD)
    assert not subsumes(CLASS, {**rule, "reason": ""})
    assert not subsumes({**CLASS, "profile": "sysmon"}, {**rule, "profile": "*"})


@pytest.mark.parametrize("record,problem", [
    ({**RECORD, "approved": "yes"}, "exactly the keys"),
    ({**RECORD, "sha256": "ABC"}, "sha256"),
    ({**RECORD, "stage": "fetch"}, "unknown stage"),
    ({**RECORD, "profile": "macos"}, "unknown profile"),
    ({**CLASS, "stage": "discovery"}, "approves only stages"),
    ({**CLASS, "reason": ""}, "needs a reason"),
    ({**CLASS, "error_pattern": "("}, "invalid error_pattern"),
    ({**CLASS, "error_pattern": ".*"}, "empty error"),
    ({**CLASS, "class": "Keywords"}, "class name"),
    ({**CLASS, "error": KEYWORDS}, "exactly the keys"),
    ({**RECORD, "document": 0}, "object of strings"),
])
def test_malformed_records_are_rejected(record, problem):
    with pytest.raises(ValueError, match=problem):
        check_exclusions([record])


def test_class_names_are_unique():
    with pytest.raises(ValueError, match="must be unique"):
        check_exclusions([CLASS, CLASS])


def test_the_checked_in_exclusions_are_reviewed_canonical_and_minimal():
    check_exclusions(RECORDS)
    registry = json.loads((ROOT / "sources.json").read_text())
    classes = [record for record in RECORDS if "class" in record]
    rules = [record for record in RECORDS if "class" not in record]
    assert all(record["reason"] for record in RECORDS), "drafts must be reviewed before they merge"
    assert all(record["source"] in registry for record in rules)
    assert all(record["source"] in ("*", *registry) for record in classes)
    assert all(record["stage"] in CLASS_STAGES for record in classes)
    assert all(record["error"] == normalize_error(record["error"]) for record in rules)
    assert not [record for record in rules if any(subsumes(other, record) for other in classes)]
    from exclusion_baseline import canonical
    assert canonical(RECORDS, registry) == RECORDS
