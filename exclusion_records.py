"""Reviewed exclusion records: their schema, and how they approve failures.

A rule record names one failure by path, content hash, document, stage,
profile ("*" for every profile) and error. A class record approves every
failure at its stage whose error matches its pattern: a capability the
backend or Zircolite lacks, reviewed once for every rule that needs it.
Errors are compared without YAML and parser positions, which move when an
unrelated line of the file changes.

A record without a reason is a draft and approves nothing until reviewed.
"""

import re

STAGES = ("discovery", "yaml", "adapt", "parse", "references", "convert", "validate")
PROFILES = ("sysmon", "generic", "native", "linux")
# Earlier stages fail on a file's structure, and validation on the SQL produced:
# neither describes a capability, so each such failure is reviewed on its own.
CLASS_STAGES = ("parse", "convert")
RULE_KEYS = ("source", "path", "sha256", "document", "stage", "profile", "error", "reason")
CLASS_KEYS = ("class", "source", "stage", "profile", "error_pattern", "reason")
POSITIONS = ((re.compile(r'(", line )\d+(, column )\d+'), r"\1#\2#"),
             (re.compile(r"(\(at char )\d+(\), \(line:)\d+(, col:)\d+\)"), r"\1#\2#\3#)"))


def normalize_error(text):
    """The error without line, column and character positions."""
    for pattern, replacement in POSITIONS:
        text = pattern.sub(replacement, text or "")
    return text


def is_class(record):
    return "class" in record


def matches(record, source, failure, ignore=()):
    """Whether a reviewed record approves a failure, disregarding the rule-record fields in ignore."""
    if not record.get("reason"):
        return False
    if is_class(record):
        return (not ignore and record["source"] in ("*", source) and record["stage"] == failure["stage"]
                and failure["stage"] in CLASS_STAGES and record["profile"] in ("*", failure["profile"])
                and re.fullmatch(record["error_pattern"], normalize_error(failure["error"])) is not None)
    return (record.get("source") == source
            and all(record.get(key) == failure.get(key) for key in ("path", "sha256", "document", "stage")
                    if key not in ignore)
            and ("profile" in ignore or record.get("profile") in ("*", failure.get("profile")))
            and ("error" in ignore or normalize_error(record.get("error")) == normalize_error(failure.get("error"))))


def approval(source, failure, records):
    """The approval of a failure: by a matching record, or as drift from one.

    A rule edited upstream that fails exactly as reviewed stays out, as it would
    after a re-pin. A collection action shapes the sibling documents that do
    publish, so an edit to one is always reviewed.
    """
    if any(matches(record, source, failure) for record in records):
        return {"approved": True}
    if failure["stage"] != "discovery" and any(matches(record, source, failure, ignore=("sha256",))
                                               for record in records):
        return {"approved": True, "drifted": True}
    return {"approved": False}


def subsumes(record, other):
    """Whether a class record approves everything a reviewed rule record does."""
    return (is_class(record) and not is_class(other) and bool(other.get("reason"))
            and record["source"] in ("*", other["source"]) and record["stage"] == other["stage"]
            and record["profile"] in ("*", other["profile"])
            and re.fullmatch(record["error_pattern"], normalize_error(other["error"])) is not None)


def check_exclusions(records):
    """Raise ValueError at the first malformed record."""
    if not isinstance(records, list):
        raise ValueError("Exclusions must be a list of records")
    names = set()
    for index, record in enumerate(records):
        def problem(text):
            return ValueError(f"Exclusion record {index}: {text}")
        if not isinstance(record, dict) or not all(isinstance(value, str) for value in record.values()):
            raise problem("must be an object of strings")
        keys = CLASS_KEYS if is_class(record) else RULE_KEYS
        if set(record) != set(keys):
            raise problem("must have exactly the keys " + ", ".join(keys))
        if record["profile"] not in ("*", *PROFILES):
            raise problem(f"unknown profile {record['profile']!r}")
        if not is_class(record):
            if record["stage"] not in STAGES:
                raise problem(f"unknown stage {record['stage']!r}")
            if not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
                raise problem("sha256 must be 64 lowercase hex digits")
            continue
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", record["class"]) or record["class"] in names:
            raise problem(f"class name {record['class']!r} must be unique, lowercase and hyphenated")
        names.add(record["class"])
        if record["stage"] not in CLASS_STAGES:
            raise problem("a class record approves only stages " + ", ".join(CLASS_STAGES))
        if not record["reason"]:
            raise problem("a class record needs a reason")
        try:
            pattern = re.compile(record["error_pattern"])
        except re.error as exc:
            raise problem(f"invalid error_pattern: {exc}") from None
        if pattern.fullmatch(""):
            raise problem("error_pattern must not match an empty error")
