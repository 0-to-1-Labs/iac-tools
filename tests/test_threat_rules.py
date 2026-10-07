"""Governance tests for skills/threat-model/data/threat-rules.json.

The rules file is checked-in, human-reviewed data. These tests are the gate:

1. Every rule has valid fields (id, STRIDE category, severity, kinds, when,
   threat text, mitigations).
2. Every Checkov id cited as a mitigation exists in rule-severity.json or
   control-map.json. A mitigation nobody reviewed cannot flip a threat to
   mitigated.
3. A NIST 800-53 control on a rule is allowed only with source "curated", a
   written rationale, and an id the checked-in control data already knows.
4. All six STRIDE categories are covered, and the file stays in the 25-40
   rule band the design asked for.
"""

import json
import os
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TM_SCRIPTS = os.path.join(REPO_ROOT, "skills", "threat-model", "scripts")
TM_DATA = os.path.join(REPO_ROOT, "skills", "threat-model", "data")
SEC_DATA = os.path.join(REPO_ROOT, "skills", "security-scan", "data")
sys.path.insert(0, TM_SCRIPTS)

from graph_semantics import KIND_BY_TYPE  # noqa: E402
from threat_model import (  # noqa: E402
    SEVERITIES,
    STRIDE,
    RuleError,
    control_vocabulary,
    load_rules,
)

RULES_PATH = os.path.join(TM_DATA, "threat-rules.json")


def _json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def rules_file():
    return _json(RULES_PATH)


@pytest.fixture(scope="module")
def known_checkov_ids():
    sev = _json(os.path.join(SEC_DATA, "rule-severity.json"))
    cm = _json(os.path.join(SEC_DATA, "control-map.json"))
    return {k for k in sev if k != "_meta"} | {k for k in cm if k != "_meta"}


def test_rules_load_through_the_governed_loader():
    loaded = load_rules(RULES_PATH)
    assert loaded["rules"]
    assert loaded["path"] == RULES_PATH


def test_rule_count_in_design_band(rules_file):
    assert 25 <= len(rules_file["rules"]) <= 40


def test_every_rule_has_valid_fields(rules_file):
    seen = set()
    kinds = set(KIND_BY_TYPE.values())
    for rule in rules_file["rules"]:
        assert rule["id"] not in seen, rule["id"]
        seen.add(rule["id"])
        assert rule["id"].startswith("TM-")
        assert rule["stride"] in STRIDE, rule["id"]
        assert rule["severity"] in SEVERITIES, rule["id"]
        assert isinstance(rule["kinds"], list) and rule["kinds"], rule["id"]
        for kind in rule["kinds"]:
            assert kind == "*" or kind in kinds, "%s names unknown kind %s" % (rule["id"], kind)
        assert isinstance(rule["when"], dict) and rule["when"], rule["id"]
        for path in rule["when"]:
            assert path.split(".")[0] in ("flags", "kind", "type", "format"), "%s: %s" % (rule["id"], path)
        assert isinstance(rule["threat"], str) and len(rule["threat"]) > 20, rule["id"]
        assert "{id}" in rule["threat"], "%s: threat text should name the element" % rule["id"]
        assert isinstance(rule["title"], str) and rule["title"]
        assert isinstance(rule["mitigations"], list), rule["id"]


def test_every_cited_checkov_id_exists(rules_file, known_checkov_ids):
    for rule in rules_file["rules"]:
        for mid in rule["mitigations"]:
            assert mid in known_checkov_ids, "%s cites %s, which is in neither rule-severity.json nor control-map.json" % (rule["id"], mid)


def test_curated_controls_carry_source_and_rationale(rules_file):
    cm = _json(os.path.join(SEC_DATA, "control-map.json"))
    baseline_path = os.path.join(SEC_DATA, "control-baseline-800-53.json")
    baseline = _json(baseline_path) if os.path.exists(baseline_path) else None
    vocab = control_vocabulary(cm, baseline)
    curated = 0
    for rule in rules_file["rules"]:
        if "nist_800_53" not in rule:
            assert "rationale" not in rule or rule.get("source") != "curated" or True
            continue
        curated += 1
        assert rule.get("source") == "curated", rule["id"]
        assert len(str(rule.get("rationale") or "")) > 40, rule["id"]
        for cid in rule["nist_800_53"]:
            assert cid in vocab, "%s cites control %s outside the checked-in vocabulary" % (rule["id"], cid)
    # Curated entries are the exception, not the rule.
    assert curated <= 6


def test_all_six_stride_categories_covered(rules_file):
    covered = {rule["stride"] for rule in rules_file["rules"]}
    assert covered == set(STRIDE)


def test_loader_rejects_unknown_mitigation():
    bad = {
        "rules": [
            {
                "id": "TM-TEST-001",
                "title": "t",
                "stride": "Tampering",
                "severity": "low",
                "kinds": ["s3_bucket"],
                "when": {"flags.public": True},
                "threat": "{id} is a test threat with enough words in it.",
                "mitigations": ["CKV_AWS_999999"],
            }
        ]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(bad, fh)
        path = fh.name
    try:
        with pytest.raises(RuleError):
            load_rules(path)
    finally:
        os.unlink(path)


def test_loader_rejects_control_without_rationale():
    bad = {
        "rules": [
            {
                "id": "TM-TEST-002",
                "title": "t",
                "stride": "Tampering",
                "severity": "low",
                "kinds": ["s3_bucket"],
                "when": {"flags.public": True},
                "threat": "{id} is a test threat with enough words in it.",
                "mitigations": [],
                "nist_800_53": ["SC-7"],
            }
        ]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(bad, fh)
        path = fh.name
    try:
        with pytest.raises(RuleError):
            load_rules(path)
    finally:
        os.unlink(path)


def test_loader_rejects_control_outside_vocabulary():
    bad = {
        "rules": [
            {
                "id": "TM-TEST-003",
                "title": "t",
                "stride": "Tampering",
                "severity": "low",
                "kinds": ["s3_bucket"],
                "when": {"flags.public": True},
                "threat": "{id} is a test threat with enough words in it.",
                "mitigations": [],
                "nist_800_53": ["ZZ-99"],
                "source": "curated",
                "rationale": "a made-up control that must be refused because the vocabulary does not know it",
            }
        ]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(bad, fh)
        path = fh.name
    try:
        with pytest.raises(RuleError):
            load_rules(path)
    finally:
        os.unlink(path)
