"""Fetch immutable source snapshots and adapt metadata without editing upstream YAML."""

import itertools
import json
import re
import tarfile
import tempfile
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

import requests
import yaml

# Accept current hyphenated tactics and their legacy Sigma underscore forms.
# Keep validation offline and deterministic; this checks tag format, not whether
# every identifier exists in the latest ATT&CK release.
ATTACK_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "defense-impairment",
    "stealth", "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
}
ATTACK_ID = re.compile(r"(?:t[0-9]{4}(?:\.[0-9]{3})?|(?:g|s|ds|m|a)[0-9]{4})")
ATTACK_ALIASES = {
    # Hayabusa's rule references https://attack.mitre.org/techniques/T1136/001/.
    "11136.001": "t1136.001",
    "defense-evansion": "defense_evasion",
    "defense_evesion": "defense_evasion",
    "compiled.html.file": "t1218.001",
    "exploitation for privilege escalation": "t1068",
    "hidden.users": "t1564.002",
    "account_discovery": "t1087",
    "credential_dumping": "t1003",
    "valid_account": "t1078",
    "account_manipulation": "t1098",
    "": None,
    # Ambiguous mixture of execution/escalation: retain the rule's technique
    # tags and record removal in provenance instead of inventing a tactic.
    "privilege_execution": None,
}


def validate_attack_tags(tags):
    for tag in tags:
        if not isinstance(tag, str):
            raise TypeError(f"Invalid rule tag: {tag!r}")
        namespace, _, name = tag.partition(".")
        if namespace.lower() == "attack" and not (
            namespace == "attack" and (name.replace("_", "-") in ATTACK_TACTICS
                                       or ATTACK_ID.fullmatch(name))
        ):
            raise ValueError(f"Malformed ATT&CK tag: {tag!r}")


def normalize_tags(tags):
    result = []
    for tag in tags:
        if not isinstance(tag, str) or "." not in tag:
            continue
        namespace, _, name = tag.partition(".")
        if namespace.lower() == "attack":
            name = name.lower()
            name = ATTACK_ALIASES.get(name, name)
            if name is None:
                continue
            if re.fullmatch(r"[0-9]{4}(?:\.[0-9]{3})?", name):
                name = "t" + name
            if name.replace("_", "-") not in ATTACK_TACTICS:
                compact = re.sub(r"[\s._-]", "", name)
                name = next((tactic.replace("-", "_") for tactic in sorted(ATTACK_TACTICS)
                             if tactic.replace("-", "") == compact), name)
            tag = "attack." + name
        if tag not in result:
            result.append(tag)
    return result


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n").encode()


@dataclass
class Document:
    path: str
    sha256: str
    document: str
    data: dict
    changes: dict = field(default_factory=dict)

    def location(self):
        return {"path": self.path, "sha256": self.sha256, "document": self.document}


def fetch_source(spec, cache: Path, revision=None):
    """Resolve the branch once, then download only that immutable commit."""
    repository = spec["repository"]
    if revision is None:
        response = requests.get(
            f"https://api.github.com/repos/{repository}/commits/{spec['branch']}",
            timeout=(15, 60),
        )
        response.raise_for_status()
        revision = response.json()["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Source revision must be a complete commit SHA")
    cache.mkdir(parents=True, exist_ok=True)
    destination = cache / revision
    if not (destination / ".complete").exists():
        with tempfile.TemporaryDirectory(dir=cache) as temporary:
            temporary = Path(temporary)
            archive = temporary / "source.tar.gz"
            with requests.get(
                f"https://codeload.github.com/{repository}/tar.gz/{revision}",
                stream=True, timeout=(15, 120),
            ) as response:
                response.raise_for_status()
                with archive.open("wb") as handle:
                    for chunk in response.iter_content(1024 * 1024):
                        handle.write(chunk)
            unpacked = temporary / "unpacked"
            unpacked.mkdir()
            with tarfile.open(archive) as tar:
                # Rule data never needs links, devices or executable checkout hooks.
                if any(not (m.isfile() or m.isdir()) for m in tar.getmembers()):
                    raise ValueError("Source archive contains non-regular entries")
                tar.extractall(unpacked, filter="data")
            roots = list(unpacked.iterdir())
            if len(roots) != 1 or not roots[0].is_dir():
                raise ValueError("Expected one source archive root")
            (roots[0] / ".complete").write_text(revision + "\n")
            roots[0].rename(destination)
    return destination, revision


def discover(root: Path, spec):
    files = set()
    for name in spec["directories"]:
        directory = root / name
        if not directory.is_dir():
            raise ValueError(f"Missing configured rule directory: {name}")
        for extension in ("*.yml", "*.yaml"):
            files.update(directory.rglob(extension))
    if not files:
        raise ValueError("Source contains no YAML files")
    return sorted(files)


def local_revision(root, spec):
    """A content identity for explicit local overrides, never a fabricated Git SHA."""
    content = b"".join(
        str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0"
        for path in discover(root, spec)
    )
    content += (root / spec["license_file"]).read_bytes()
    return "local-sha256:" + digest(content)


def read_documents(root, spec):
    documents, failures, ignored = [], [], []
    for path in discover(root, spec):
        raw = path.read_bytes()
        location = {"path": path.relative_to(root).as_posix(), "sha256": digest(raw)}
        try:
            values = list(yaml.safe_load_all(raw))
        except yaml.YAMLError as exc:
            failures.append({**location, "document": "*", "stage": "yaml",
                             "profile": "*", "error": str(exc)})
            continue
        for index, value in enumerate(values):
            if isinstance(value, dict) and value.get("action") is not None:
                failures.append({
                    **location, "document": str(index), "stage": "discovery", "profile": "*",
                    "error": f"Unsupported Sigma collection action: {value['action']!r}",
                })
                continue
            if not isinstance(value, dict) or not (
                "detection" in value or "correlation" in value
            ):
                ignored.append({**location, "document": str(index), "reason": "not a rule"})
                continue
            documents.append(Document(**location, document=str(index), data=value))
    if not documents and not failures:
        raise ValueError("Source contains no detection or correlation documents")
    return documents, failures, ignored


def adapt(document: Document, spec):
    """Return explicit alternatives; all changed original metadata is recorded."""
    original = document.data
    data = deepcopy(original)
    if spec["adapter"] == "community":
        if isinstance(data.get("correlation"), str) and "detection" in data:
            # Several authors use this field for human-readable research notes.
            data.pop("correlation")
        if isinstance(data.get("references"), str):
            data["references"] = [data["references"]]
        if isinstance(data.get("description"), list) and all(
            isinstance(part, str) for part in data["description"]
        ):
            data["description"] = "\n".join(data["description"])
        if data.get("description") is None:
            data["description"] = ""
        if isinstance(data.get("tags"), list):
            data["tags"] = normalize_tags(data["tags"])
        status = data.get("status")
        if isinstance(status, str):
            status = status.lower()
            data["status"] = {
                "experimental|": "experimental",
                "production": "stable",
                "experimental (depending how many more emojis are out there)": "experimental",
            }.get(status, status)
        logsource = data.get("logsource", {})
        product = logsource.get("product")
        def normalize_product(value):
            if isinstance(value, str) and value.lower() in ("windows", "linux"):
                return value.lower()
            return value
        if product is not None:
            logsource["product"] = ([normalize_product(value) for value in product]
                                    if isinstance(product, list) else normalize_product(product))
        if logsource.get("category") == "file_creation":
            logsource["category"] = "file_event"
        if logsource.get("category") in ("security", "bitlocker") and not logsource.get("service"):
            logsource["service"] = logsource.pop("category")
        if logsource.get("service") == "bits":
            logsource["service"] = "bits-client"
        if logsource.get("service") == "security, system":
            logsource["service"] = ["security", "system"]

    identity = str(data.get("id", ""))
    try:
        uuid.UUID(identity)
    except (ValueError, TypeError):
        identity = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"https://github.com/{spec['repository']}#"
            f"{identity or document.path + ':' + document.document}",
        ))
        data["id"] = identity
    if not data.get("level"):
        data["level"] = "informational"

    logsource = data.get("logsource", {})
    lists = {key: value for key, value in logsource.items() if isinstance(value, list)}
    if lists and spec["adapter"] != "community":
        raise ValueError("List-valued official logsource needs upstream correction")
    if any(not values or not all(isinstance(v, str) for v in values) for values in lists.values()):
        raise ValueError("Logsource alternatives must be non-empty lists of strings")
    result = []
    for alternatives in itertools.product(*lists.values()):
        variant = deepcopy(data)
        suffix = ""
        if lists:
            selected = dict(zip(lists, alternatives, strict=True))
            variant["logsource"].update(selected)
            suffix = ":" + json.dumps(selected, sort_keys=True, separators=(",", ":"))
            variant["id"] = str(uuid.uuid5(uuid.UUID(identity), suffix))
            # A named definition with alternatives is ambiguous to correlations.
            # Keep its original name here so dependency validation rejects duplicates.
        changes = {
            key: {"original": original.get(key), "adapted": variant.get(key)}
            for key in original.keys() | variant.keys()
            if original.get(key) != variant.get(key)
        }
        result.append(Document(document.path, document.sha256,
                               document.document + suffix, variant, changes))
    return result


def template_reason(document, spec):
    """Do not ship organization-specific exclusions as literal SQL comparisons."""
    if spec["repository"].startswith("mdecrevoisier/"):
        # These templates use lower-case %name% tokens; Windows %COMSPEC% is literal.
        detection = json.dumps(document.data.get("detection", {}))
        placeholders = sorted(set(re.findall(r"%[a-z][a-z_]*%", detection)))
        if placeholders:
            return "requires organization values: " + ", ".join(placeholders)
    return None
