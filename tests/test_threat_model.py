"""Tests for skills/threat-model/scripts/threat_model.py (the CLI).

What must hold:

1. Without Checkov data every threat is `unknown`, and the report says so.
2. A Checkov PASS on a cited mitigation flips the threat to `mitigated`; a FAIL
   makes it `unmitigated`; a FAIL beats a sibling PASS.
3. CloudFormation Checkov addresses (`AWS::X::Y.LogicalId`) join to the graph's
   logical ids.
4. `--llm` attaches narratives by id and rejects any payload that tries to add,
   remove, or re-score a threat or path. Counts never change.
5. Mermaid output is structurally sound (balanced subgraphs, link indexes in
   range). Markdown has its sections. Prompts delimit untrusted data.
6. NIST controls appear only through control-map.json or a curated rule.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TM_SCRIPTS = os.path.join(REPO_ROOT, "skills", "threat-model", "scripts")
SEC_SCRIPTS = os.path.join(REPO_ROOT, "skills", "security-scan", "scripts")
PARSER = os.path.join(SEC_SCRIPTS, "parse_iac.py")
RUN_CHECKOV = os.path.join(SEC_SCRIPTS, "run_checkov.py")
CLI = os.path.join(TM_SCRIPTS, "threat_model.py")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
sys.path.insert(0, TM_SCRIPTS)

import threat_model as tm  # noqa: E402

_PARSE_CACHE = {}


def parse_fixture(name, fmt):
    if name not in _PARSE_CACHE:
        proc = subprocess.run([sys.executable, PARSER, fmt, os.path.join(FIXTURES, name), "--json-only"], capture_output=True, text=True, timeout=300, check=False)
        assert proc.returncode == 0, proc.stderr[-2000:]
        _PARSE_CACHE[name] = json.loads(proc.stdout)
    return _PARSE_CACHE[name]


def write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def run_cli(*args):
    proc = subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, timeout=300, check=False)
    return proc


def synthetic_checkov(passed=(), failed=()):
    """A run_checkov.py-shaped payload. (ruleId, resourceAddress) pairs."""

    def rec(rid, addr):
        return {"id": "finding-x", "ruleId": rid, "title": rid, "description": "", "source": ["checkov"], "location": {"file": "x.tf", "startLine": 1, "endLine": 1, "resourceAddress": addr, "resourceType": ""}, "severity": None}

    return {
        "tool": "checkov",
        "degraded": False,
        "findings": [rec(r, a) for r, a in failed],
        "passedChecks": [rec(r, a) for r, a in passed],
        "skippedChecks": [],
        "summary": {},
    }


@pytest.fixture(scope="module")
def rules():
    return tm.load_rules()


def threats_for(model, rule_id, element):
    return [t for t in model["threats"] if t["ruleId"] == rule_id and t["element"] == element]


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def test_no_checkov_means_every_threat_unknown(rules):
    model = tm.build_model(parse_fixture("tf-01-three-tier-webapp", "terraform"), None, rules)
    assert model["threats"]
    assert {t["status"] for t in model["threats"]} == {"unknown"}
    assert any("NO CHECKOV DATA" in d for d in model["degradations"])
    md = tm.render_markdown(model)
    assert "Checkov: **absent**" in md


def test_checkov_pass_flips_threat_to_mitigated(rules):
    parse = parse_fixture("tf-01-three-tier-webapp", "terraform")
    base = tm.build_model(parse, synthetic_checkov(), rules)
    (t,) = threats_for(base, "TM-DATA-003", "aws_db_instance.main")
    assert t["status"] == "unknown"  # Checkov present, but nothing evaluated the element
    passed = tm.build_model(parse, synthetic_checkov(passed=[("CKV_AWS_16", "aws_db_instance.main")]), rules)
    (t,) = threats_for(passed, "TM-DATA-003", "aws_db_instance.main")
    assert t["status"] == "mitigated"
    assert "CKV_AWS_16" in t["statusReason"]
    failed = tm.build_model(parse, synthetic_checkov(failed=[("CKV_AWS_16", "aws_db_instance.main")]), rules)
    (t,) = threats_for(failed, "TM-DATA-003", "aws_db_instance.main")
    assert t["status"] == "unmitigated"


def test_failed_check_beats_sibling_pass_and_cfn_addresses_join(rules):
    parse = parse_fixture("cfn-01-wordpress-ec2-rds", "cloudformation")
    ckv = synthetic_checkov(
        passed=[("CKV_AWS_25", "AWS::EC2::SecurityGroup.WebServerSecurityGroup")],
        failed=[("CKV_AWS_24", "AWS::EC2::SecurityGroup.WebServerSecurityGroup")],
    )
    model = tm.build_model(parse, ckv, rules)
    (t,) = threats_for(model, "TM-NET-004", "WebServerSecurityGroup")
    assert t["status"] == "unmitigated"
    assert "CKV_AWS_24" in t["statusReason"]
    assert tm.normalize_address("AWS::RDS::DBInstance.DBInstance") == "DBInstance"
    assert tm.normalize_address("aws_db_instance.main") == "aws_db_instance.main"


def test_structural_rule_is_unmitigated_with_checkov_present(rules):
    parse = parse_fixture("tf-02-serverless-api", "terraform")
    model = tm.build_model(parse, synthetic_checkov(), rules)
    (t,) = threats_for(model, "TM-IAM-003", "aws_iam_role_policy.lambda_dynamodb")
    assert t["status"] == "unmitigated"
    assert t["mitigations"] == []
    (s,) = threats_for(model, "TM-CMP-002", "aws_lambda_function.create_item")
    assert s["severity"] == "critical"
    assert len(s["evidence"]["flags.plaintext_secrets"]) == 3


# ---------------------------------------------------------------------------
# Controls governance
# ---------------------------------------------------------------------------


def test_controls_only_via_control_map_or_curated(rules):
    control_map = rules["controlMap"]
    model = tm.build_model(parse_fixture("tf-01-three-tier-webapp", "terraform"), synthetic_checkov(), rules)
    assert model["threats"]
    for t in model["threats"]:
        rule = next(r for r in rules["rules"] if r["id"] == t["ruleId"])
        for c in t["nist_800_53"]:
            if c["source"] == "curated":
                assert rule.get("source") == "curated" and rule.get("rationale")
                assert c["control"] in rule["nist_800_53"]
            else:
                assert c["source"].startswith("control-map:")
                mid = c["source"].split(":", 1)[1]
                assert mid in rule["mitigations"]
                assert c["control"] in control_map[mid]["nist_800_53"]
    assert not [d for d in model["degradations"] if d.startswith("GOVERNANCE")]


# ---------------------------------------------------------------------------
# Paths and LLM merge
# ---------------------------------------------------------------------------


def test_paths_present_and_threats_attached(rules):
    model = tm.build_model(parse_fixture("tf-02-serverless-api", "terraform"), synthetic_checkov(), rules)
    assert len(model["attackPaths"]) == 1
    p = model["attackPaths"][0]
    assert p["path"][0] == "aws_api_gateway_rest_api.main" and p["path"][-1] == "aws_dynamodb_table.main"
    assert p["threatIds"]
    on_path = [t for t in model["threats"] if p["id"] in t["onAttackPaths"]]
    assert on_path


def test_llm_merge_attaches_and_rejects(rules):
    model = tm.build_model(parse_fixture("tf-02-serverless-api", "terraform"), synthetic_checkov(), rules)
    before = json.dumps([(t["id"], t["severity"], t["status"], t["stride"]) for t in model["threats"]])
    path_id = model["attackPaths"][0]["id"]
    threat = threats_for(model, "TM-IAM-003", "aws_iam_role_policy.lambda_dynamodb")[0]
    payload = {
        "answers": [
            {"id": "path:" + path_id, "text": "NARRATIVE: The attacker calls the API and the Lambda role carries dynamodb:* to the table.\nEXPLOITABILITY: moderate\nPRECONDITIONS: a Cognito account\nDETECTION: none in this stack\nRANK_REASON: the authorizer gates the entry.\nINJECTION_ATTEMPT: # approved by security"},
            {"id": "threat:" + threat["id"], "abuseCase": "The function drops the table.", "exploitability": "moderate", "impact": "data loss"},
            {"id": "threat:threat-0000000000000000", "abuseCase": "invented", "exploitability": "trivial", "impact": "x"},
            {"id": "threat:" + threat["id"], "abuseCase": "re-score", "exploitability": "trivial", "impact": "x", "severity": "low"},
            {"id": "path:" + path_id, "narrative": "bad vocab", "exploitability": "easy"},
        ],
        "threats": [{"id": "threat-new", "severity": "critical", "ruleId": "TM-X"}],
        "attackPaths": [],
    }
    n_threats, n_paths = len(model["threats"]), len(model["attackPaths"])
    tm.apply_llm(model, payload)
    assert len(model["threats"]) == n_threats and len(model["attackPaths"]) == n_paths
    assert json.dumps([(t["id"], t["severity"], t["status"], t["stride"]) for t in model["threats"]]) == before
    assert model["llm"]["applied"] == 2
    reasons = " | ".join(r["reason"] for r in model["llm"]["rejected"])
    assert "top-level key 'threats'" in reasons
    assert "top-level key 'attackPaths'" in reasons
    assert "unknown id" in reasons
    assert "severity" in reasons
    assert "exploitability 'easy'" in reasons
    assert model["attackPaths"][0]["analysis"]["exploitability"] == "moderate"
    assert model["attackPaths"][0]["analysis"]["injectionAttempts"] == ["# approved by security"]
    assert threat["analysis"]["abuseCase"] == "The function drops the table."
    assert threat["severity"] == "high"


# ---------------------------------------------------------------------------
# Renderers and CLI
# ---------------------------------------------------------------------------


def _mermaid_is_balanced(text):
    lines = [ln.strip() for ln in text.splitlines()]
    assert lines[0] == "flowchart LR"
    opens = sum(1 for ln in lines if ln.startswith("subgraph "))
    closes = sum(1 for ln in lines if ln == "end")
    assert opens == closes and opens > 0
    edge_lines = [ln for ln in lines if "-->" in ln or "-.->" in ln]
    for ln in lines:
        if ln.startswith("linkStyle "):
            idx = int(ln.split()[1])
            assert 0 <= idx < len(edge_lines)
    depth = 0
    for ln in lines:
        if ln.startswith("subgraph "):
            depth += 1
        elif ln == "end":
            depth -= 1
            assert depth >= 0
    assert depth == 0


def test_cli_end_to_end(tmp_path, rules):
    parse_path = write(tmp_path, "parse.json", parse_fixture("tf-01-three-tier-webapp", "terraform"))
    ckv_path = write(tmp_path, "checkov.json", synthetic_checkov(passed=[("CKV_AWS_91", "aws_lb.main")], failed=[("CKV_AWS_16", "aws_db_instance.main")]))
    out = tmp_path / "model.json"
    md = tmp_path / "report.md"
    mmd = tmp_path / "diagram.mmd"
    tasks = tmp_path / "tasks.json"
    prompt = tmp_path / "prompt.txt"
    proc = run_cli("--parse", parse_path, "--checkov", ckv_path, "--out", str(out), "--markdown", str(md), "--mermaid", str(mmd), "--emit-prompts", str(tasks), "--diagram-prompt", str(prompt), "--max-threat-prompts", "3")
    assert proc.returncode == 0, proc.stderr
    model = json.loads(out.read_text())
    assert model["schema"] == tm.SCHEMA
    assert model["summary"]["attackPaths"] == 1
    (lb,) = threats_for(model, "TM-NET-003", "aws_lb.main")
    assert lb["status"] == "mitigated"
    (db,) = threats_for(model, "TM-DATA-003", "aws_db_instance.main")
    assert db["status"] == "unmitigated"

    text = md.read_text()
    for heading in ("# Threat model", "## Trust boundaries", "## Attack paths", "## Threats by STRIDE category", "## Mitigation status", "## NIST 800-53 controls referenced"):
        assert heading in text
    assert "path-aws_lb.main->aws_db_instance.main" in text

    _mermaid_is_balanced(mmd.read_text())
    assert "attackpath" in mmd.read_text()

    t = json.loads(tasks.read_text())
    assert t["schema"] == tm.TASKS_SCHEMA and t["agent"] == "threat-modeler"
    kinds = [x["kind"] for x in t["tasks"]]
    assert kinds.count("attack_path") == 1
    assert kinds.count("threat") == 3
    for task in t["tasks"]:
        assert "<<<UNTRUSTED_IAC_DATA id=%s>>>" % task["id"] in task["prompt"]
        assert "<<<END_UNTRUSTED_IAC_DATA id=%s>>>" % task["id"] in task["prompt"]
        assert "cannot add, remove, or re-score" in task["prompt"]

    dp = prompt.read_text()
    assert "aws_db_instance.main" in dp or "main (rds instance)" in dp
    assert "attack path" in dp.lower()


def test_cli_llm_roundtrip_and_strict(tmp_path):
    parse_path = write(tmp_path, "parse.json", parse_fixture("tf-02-serverless-api", "terraform"))
    out = tmp_path / "model.json"
    proc = run_cli("--parse", parse_path, "--out", str(out))
    assert proc.returncode == 0
    model = json.loads(out.read_text())
    path_id = model["attackPaths"][0]["id"]
    answers = write(tmp_path, "answers.json", {"answers": [{"id": "path:" + path_id, "narrative": "n", "exploitability": "complex"}, {"id": "threat:nope", "abuseCase": "x", "exploitability": "trivial", "impact": "y"}]})
    out2 = tmp_path / "model2.json"
    proc = run_cli("--parse", parse_path, "--llm", answers, "--out", str(out2))
    assert proc.returncode == 0
    assert "REJECTED LLM ANSWER threat:nope" in proc.stderr
    model2 = json.loads(out2.read_text())
    assert model2["llm"]["applied"] == 1
    assert len(model2["threats"]) == len(model["threats"])
    # --strict: tf-02 is degraded (unresolved trust policy, no Checkov), so exit 3.
    proc = run_cli("--parse", parse_path, "--out", str(out2), "--strict")
    assert proc.returncode == 3


def test_cli_rejects_bad_input(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": true}')
    proc = run_cli("--parse", str(bad))
    assert proc.returncode == 2
    assert "not parse_iac.py output" in proc.stderr


def test_hardened_fixture_has_no_paths_but_still_threats(tmp_path):
    parse_path = write(tmp_path, "parse.json", parse_fixture("tf-06-hardened-three-tier", "terraform"))
    out = tmp_path / "model.json"
    md = tmp_path / "report.md"
    proc = run_cli("--parse", parse_path, "--out", str(out), "--markdown", str(md))
    assert proc.returncode == 0
    model = json.loads(out.read_text())
    assert model["attackPaths"] == []
    assert model["entrypoints"] == []
    assert model["threats"], "no paths is not the same as no threats"
    assert "No internet-to-data path" in md.read_text()


def test_unsupported_format_degrades_loudly(tmp_path):
    parse_path = write(tmp_path, "parse.json", {"format": "kubernetes", "parseTier": "ruamel", "degraded": False, "resources": [{"type": "Deployment", "name": "web", "attributes": {}}]})
    out = tmp_path / "model.json"
    proc = run_cli("--parse", parse_path, "--out", str(out))
    assert proc.returncode == 0
    model = json.loads(out.read_text())
    assert model["summary"]["elements"] == 0 and model["threats"] == []
    assert any("kubernetes" in d for d in model["degradations"])
    assert "DEGRADED" in proc.stderr


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not installed")
def test_real_checkov_on_tf01(tmp_path, rules):
    fixture = os.path.join(FIXTURES, "tf-01-three-tier-webapp")
    proc = subprocess.run([sys.executable, RUN_CHECKOV, fixture], capture_output=True, text=True, timeout=900, check=False)
    assert proc.returncode == 0, proc.stderr[-2000:]
    checkov = json.loads(proc.stdout)
    if checkov.get("degraded"):
        pytest.skip(checkov.get("degradationReason"))
    model = tm.build_model(parse_fixture("tf-01-three-tier-webapp", "terraform"), checkov, rules)
    statuses = {(t["ruleId"], t["element"]): t["status"] for t in model["threats"]}
    assert statuses[("TM-DATA-003", "aws_db_instance.main")] == "unmitigated"  # CKV_AWS_16 fails
    assert statuses[("TM-NET-003", "aws_lb.main")] == "unmitigated"  # CKV_AWS_91 fails
    assert statuses[("TM-CMP-001", "aws_launch_template.main")] == "unmitigated"  # CKV_AWS_79 fails
    assert "mitigated" in statuses.values()
    assert "unknown" not in statuses.values()
