"""Tests for the Checkov adapter (WS-2).

Two things are load-bearing here and both get explicit coverage:

1. **Path normalization.** Checkov says "/athena.tf"; the WS-1 parser says
   "athena.tf". The downstream join key is (rule, file, resourceAddress). If
   these two do not normalize to the same string, EVERY join silently produces
   zero matches and the scan looks healthy while finding nothing.

2. **The degraded path.** Checkov missing must be loud: degraded=true, an
   install hint, and zero findings that are clearly labeled as "we didn't run
   the rule engine" rather than "your code is clean".

Graded against checkov 3.3.25 (re-graded 2026-10-06 from 3.2.500). requirements.txt
is a FLOOR (checkov>=3.3.25): the adapter records the version it ran and lists any
firing rule with no severity seed as ``unseededRules`` -- a warning, never a crash.
"""

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_ROOT, "skills", "security-scan", "scripts")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
SCRIPT = os.path.join(SCRIPTS, "run_checkov.py")

sys.path.insert(0, SCRIPTS)

import run_checkov  # noqa: E402

# Graded expectations (plan risk #10: an unnoticed checkov upgrade reads as a
# regression in our code). Measured against checkov 3.3.25. 3.3.x adds
# CKV_AWS_394 (aws_availability_zones pinning), which fires once on tf-01/main.tf:
# tf-01 23 -> 24, corpus 162 -> 163, distinct rules 58 -> 59. CKV_AWS_393 (GitHub
# OIDC trust on aws_iam_role) is also new and passes on every role in the corpus.
#
# Counts are for the DEFAULT framework set (terraform + secrets). The `secrets`
# framework is not cosmetic: tf-02's lambda.tf carries three plaintext production
# credentials (a DB password, an `sk-prod-` API key, an encryption key) that a
# terraform-only scan reports ZERO of -- CKV_SECRET_* lives in the secrets
# framework. Those 3 (tf-02) + 1 (tf-05) are the delta from the terraform-only
# baseline of 158. Being structurally blind to hardcoded secrets is not a posture
# a security scanner gets to keep, so they are in the default counts.
GRADED_CHECKOV_VERSION = "3.3.25"
EXPECTED_FAILED = {
    "tf-01-three-tier-webapp": 24,  # 23 + CKV_AWS_394 on main.tf (new in 3.3.x)
    "tf-02-serverless-api": 58,  # 55 terraform + 3 hardcoded secrets
    "tf-03-data-lake": 26,
    "tf-04-container-platform": 35,
    "tf-05-cicd-pipeline": 20,  # 19 terraform + 1 hardcoded secret
}
EXPECTED_CORPUS_TOTAL = 163  # 159 terraform + 4 secrets
EXPECTED_DISTINCT_RULES = 59  # 57 terraform + CKV_SECRET_4 + CKV_SECRET_6


def _version_tuple(text):
    return tuple(int(p) for p in text.strip().split("."))


def checkov_installed():
    return run_checkov.find_checkov() is not None


requires_checkov = pytest.mark.skipif(
    not checkov_installed(), reason="checkov not installed"
)


# ---------------------------------------------------------------------------
# Path normalization — the silent-join-breaker
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/athena.tf", "athena.tf"),  # the exact shape Checkov emits
        ("/modules/vpc/main.tf", "modules/vpc/main.tf"),
        ("athena.tf", "athena.tf"),  # the exact shape tfparse emits
        ("./athena.tf", "athena.tf"),
        ("/./athena.tf", "athena.tf"),
        ("//athena.tf", "athena.tf"),
        ("  /athena.tf  ", "athena.tf"),
        ("", ""),
        (None, ""),
    ],
)
def test_normalize_path(raw, expected):
    assert run_checkov.normalize_path(raw) == expected


def test_checkov_and_parser_paths_converge():
    """The whole point: both sides of the join land on the same string."""
    checkov_side = run_checkov.normalize_path("/athena.tf")  # checkov file_path
    parser_side = run_checkov.normalize_path("athena.tf")  # tfparse __tfmeta.filename
    assert checkov_side == parser_side == "athena.tf"


def test_normalized_path_never_leads_with_slash():
    for raw in ("/a.tf", "/deep/nested/b.tf", "///c.tf"):
        assert not run_checkov.normalize_path(raw).startswith("/")


# ---------------------------------------------------------------------------
# Resource address / type / service
# ---------------------------------------------------------------------------


def test_resource_address_joins_natively():
    """Pre-flight verified: checkov.resource == tfparse __tfmeta.path, verbatim."""
    address, rtype = run_checkov.split_resource_address("aws_athena_workgroup.main")
    assert address == "aws_athena_workgroup.main"
    assert rtype == "aws_athena_workgroup"


def test_module_resource_address():
    address, rtype = run_checkov.split_resource_address("module.vpc.aws_s3_bucket.logs")
    assert address == "module.vpc.aws_s3_bucket.logs"
    assert rtype == "aws_s3_bucket"


@pytest.mark.parametrize(
    "rtype,service",
    [
        ("aws_s3_bucket", "s3"),
        ("aws_cloudwatch_log_group", "cloudwatch"),
        ("aws_athena_workgroup", "athena"),
        ("", ""),
    ],
)
def test_service_from_resource_type(rtype, service):
    assert run_checkov.service_from_resource_type(rtype) == service


def test_finding_id_is_stable_and_spec_shaped():
    a = run_checkov.finding_id("CKV_AWS_18", "athena.tf", "aws_s3_bucket.x")
    b = run_checkov.finding_id("CKV_AWS_18", "athena.tf", "aws_s3_bucket.x")
    assert a == b
    assert a.startswith("finding-")
    assert len(a) == len("finding-") + 16
    assert a != run_checkov.finding_id("CKV_AWS_18", "s3.tf", "aws_s3_bucket.x")


# ---------------------------------------------------------------------------
# Normalization of a synthetic Checkov payload (no Checkov needed)
# ---------------------------------------------------------------------------

SAMPLE_CHECK = {
    "check_id": "CKV_AWS_159",
    "check_name": "Ensure that Athena Workgroup is encrypted",
    "check_result": {"result": "FAILED"},
    "file_path": "/athena.tf",
    "file_abs_path": "/anywhere/athena.tf",
    "file_line_range": [2, 26],
    "resource": "aws_athena_workgroup.main",
    "severity": None,
    "guideline": "https://example.invalid/g",
}


def test_normalize_check_emits_spec_shape():
    f = run_checkov.normalize_check(SAMPLE_CHECK)
    assert f["ruleId"] == "CKV_AWS_159"
    assert f["title"] == "Ensure that Athena Workgroup is encrypted"
    assert f["source"] == ["checkov"]
    assert f["location"] == {
        "file": "athena.tf",  # leading slash gone
        "startLine": 2,
        "endLine": 26,
        "resourceAddress": "aws_athena_workgroup.main",
        "resourceType": "aws_athena_workgroup",
        "service": "athena",
    }


def test_severity_is_null_never_fabricated():
    """Checkov CE emits no severity. We must not invent one or default to medium."""
    f = run_checkov.normalize_check(SAMPLE_CHECK)
    assert f["severity"] is None


def test_no_checkov_native_field_leaks_into_the_schema():
    """Risk §14.1: swapping in tfsec/Trivy must stay a one-file change."""
    f = run_checkov.normalize_check(SAMPLE_CHECK)
    leaked = {
        "check_id",
        "check_name",
        "check_result",
        "file_path",
        "file_abs_path",
        "file_line_range",
        "resource",
        "bc_check_id",
        "check_class",
        "repo_file_path",
    }
    assert not (leaked & set(f)), "Checkov field leaked into core schema"
    assert not (leaked & set(f["location"]))


def test_normalize_results_handles_list_and_dict_payloads():
    block = {
        "results": {"failed_checks": [SAMPLE_CHECK], "passed_checks": [SAMPLE_CHECK]},
        "summary": {"failed": 1, "passed": 1, "skipped": 0, "resource_count": 1},
    }
    as_dict = run_checkov.normalize_results(block)
    as_list = run_checkov.normalize_results([block])
    assert len(as_dict["failed"]) == len(as_list["failed"]) == 1
    assert len(as_dict["passed"]) == len(as_list["passed"]) == 1


# ---------------------------------------------------------------------------
# Degraded path — Checkov absent
# ---------------------------------------------------------------------------


def test_degraded_when_checkov_missing(monkeypatch, capsys, tmp_path):
    """Simulate an uninstalled Checkov. Must degrade LOUDLY, never silently."""
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: None)

    result = run_checkov.run_checkov(str(tmp_path))

    assert result["degraded"] is True
    assert result["findings"] == []
    assert result["passedChecks"] == []
    assert result["toolVersion"] is None
    assert result["checkovVersion"] is None
    assert result["gradedVersion"] == GRADED_CHECKOV_VERSION
    assert result["unseededRules"] == []
    assert 'pip install "checkov>=%s"' % GRADED_CHECKOV_VERSION in result["installHint"]
    assert "not installed" in result["degradationReason"]

    # Loud: the install line and a DEGRADED banner go to stderr, so it survives
    # stdout being piped into a JSON consumer.
    err = capsys.readouterr().err
    assert "DEGRADED" in err
    assert run_checkov.INSTALL_HINT in err  # pip install "checkov>=<graded>"


def test_degraded_result_is_not_confusable_with_a_clean_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: None)
    result = run_checkov.run_checkov(str(tmp_path))
    # Zero findings AND degraded=true. A consumer that reads `degraded` cannot
    # mistake "the tool never ran" for "the code is clean".
    assert result["summary"]["failed"] == 0
    assert result["degraded"] is True
    assert result["degradationReason"]


def test_degraded_when_checkov_binary_unexecutable(monkeypatch, tmp_path):
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: "/nonexistent/checkov")

    def boom(*_a, **_k):
        raise OSError("No such file or directory")

    monkeypatch.setattr(run_checkov.subprocess, "run", boom)
    result = run_checkov.run_checkov(str(tmp_path))
    assert result["degraded"] is True
    assert run_checkov.INSTALL_HINT in result["degradationReason"]


def test_degraded_on_unparseable_output(monkeypatch, tmp_path):
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: "checkov")

    class Proc:
        returncode = 0
        stdout = "not json at all"
        stderr = ""

    monkeypatch.setattr(run_checkov.subprocess, "run", lambda *a, **k: Proc())
    result = run_checkov.run_checkov(str(tmp_path))
    assert result["degraded"] is True
    assert "not valid JSON" in result["degradationReason"]


# ---------------------------------------------------------------------------
# Live Checkov against the fixture corpus
# ---------------------------------------------------------------------------


@requires_checkov
def test_quiet_flag_is_not_used():
    """--quiet silently drops passed_checks, which §7.2's compliance report needs."""
    src = open(SCRIPT).read()
    assert '"--quiet"' not in src


def test_graded_version_matches_the_adapter_constant():
    """The tests and the adapter must agree on what 'graded' means."""
    assert run_checkov.GRADED_CHECKOV_VERSION == GRADED_CHECKOV_VERSION
    assert run_checkov.EXPECTED_CHECKOV_VERSION == GRADED_CHECKOV_VERSION  # alias


def test_version_helpers():
    assert run_checkov.parse_version("3.3.25") == (3, 3, 25)
    assert run_checkov.parse_version("") is None
    assert run_checkov.parse_version("garbage") is None
    assert run_checkov.version_matches_graded(GRADED_CHECKOV_VERSION) is True
    assert run_checkov.version_matches_graded("3.3.26") is False
    assert run_checkov.version_matches_graded(None) is None


def test_unseeded_rules_are_reported_not_dropped(monkeypatch, capsys, tmp_path):
    """A rule with no severity seed must surface as a visible `unseededRules`
    entry and a stderr WARNING. Never a crash, never silently dropped."""
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: "checkov")
    monkeypatch.setattr(run_checkov, "checkov_version", lambda _b: "9.9.9")
    novel = dict(SAMPLE_CHECK, check_id="CKV_AWS_999999", resource="aws_s3_bucket.x")
    payload = {
        "check_type": "terraform",
        "results": {"failed_checks": [SAMPLE_CHECK, novel], "passed_checks": []},
        "summary": {"failed": 2, "passed": 0, "skipped": 0, "resource_count": 2},
    }

    class Proc:
        returncode = 1
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(run_checkov.subprocess, "run", lambda *a, **k: Proc())
    result = run_checkov.run_checkov(str(tmp_path))
    assert result["degraded"] is False
    assert result["checkovVersion"] == "9.9.9"
    assert result["versionMatchesGraded"] is False
    # CKV_AWS_159 is seeded; the novel rule is not.
    assert result["unseededRules"] == ["CKV_AWS_999999"]
    assert len(result["findings"]) == 2, "unseeded findings are still findings"
    err = capsys.readouterr().err
    assert "WARNING" in err and "CKV_AWS_999999" in err


def test_unseeded_rules_empty_when_every_rule_is_seeded(monkeypatch, tmp_path):
    monkeypatch.setattr(run_checkov, "find_checkov", lambda: "checkov")
    monkeypatch.setattr(run_checkov, "checkov_version", lambda _b: GRADED_CHECKOV_VERSION)
    payload = {
        "results": {"failed_checks": [SAMPLE_CHECK], "passed_checks": []},
        "summary": {"failed": 1, "passed": 0, "skipped": 0, "resource_count": 1},
    }

    class Proc:
        returncode = 1
        stdout = json.dumps(payload)
        stderr = ""

    monkeypatch.setattr(run_checkov.subprocess, "run", lambda *a, **k: Proc())
    result = run_checkov.run_checkov(str(tmp_path))
    assert result["unseededRules"] == []
    assert result["versionMatchesGraded"] is True


def test_missing_seed_file_degrades_the_warning_not_the_scan(monkeypatch):
    """If the seed map cannot be read, unseeded_rules yields [] and nothing raises."""
    assert run_checkov.unseeded_rules([{"ruleId": "CKV_AWS_1"}], None) == []
    monkeypatch.setattr(run_checkov, "SEVERITY_SEED_PATH", "/nonexistent/seeds.json")
    # SeverityMap import still works here, so the real map loads; the raw-file
    # fallback path is exercised by forcing the import to fail.
    import builtins

    real_import = builtins.__import__

    def no_findings(name, *a, **k):
        if name == "findings":
            raise ImportError("simulated")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_findings)
    assert run_checkov.load_seeded_rule_ids() is None


@requires_checkov
def test_tf03_data_lake_returns_26_findings():
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-03-data-lake"))
    assert result["degraded"] is False
    # Floor, not pin: the version that ran is recorded and must be >= graded.
    assert result["toolVersion"] == result["checkovVersion"]
    assert _version_tuple(result["checkovVersion"]) >= _version_tuple(GRADED_CHECKOV_VERSION)
    assert result["gradedVersion"] == GRADED_CHECKOV_VERSION
    assert isinstance(result["unseededRules"], list)
    assert len(result["findings"]) == 26


@requires_checkov
def test_passed_checks_are_captured():
    """Phase 2's 'controls SATISFIED by the current IaC' is derived from these."""
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-03-data-lake"))
    assert len(result["passedChecks"]) > 0
    assert result["summary"]["passed"] == len(result["passedChecks"])
    passing = result["passedChecks"][0]
    assert passing["ruleId"].startswith("CKV")
    assert passing["location"]["file"]
    assert passing["severity"] is None


@requires_checkov
@pytest.mark.parametrize("fixture,expected", sorted(EXPECTED_FAILED.items()))
def test_per_fixture_finding_counts(fixture, expected):
    result = run_checkov.run_checkov(os.path.join(FIXTURES, fixture))
    assert len(result["findings"]) == expected


@requires_checkov
def test_corpus_totals():
    total, rules = 0, set()
    for fixture in EXPECTED_FAILED:
        result = run_checkov.run_checkov(os.path.join(FIXTURES, fixture))
        total += len(result["findings"])
        rules.update(f["ruleId"] for f in result["findings"])
    assert total == EXPECTED_CORPUS_TOTAL
    assert len(rules) == EXPECTED_DISTINCT_RULES


@requires_checkov
def test_hardcoded_secrets_are_found_by_default():
    """tf-02's lambda.tf carries three plaintext production credentials. They live
    in Checkov's `secrets` framework, which `--framework terraform` never runs. A
    security scanner blind to hardcoded secrets is not one worth shipping, so the
    secrets framework is in the DEFAULT set -- proven here, not just configured.

    Guards against a silent revert to terraform-only, which would make the three
    prod secrets in the corpus invisible again with every other test still green.
    """
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-02-serverless-api"))
    secrets = [f for f in result["findings"] if f["ruleId"].startswith("CKV_SECRET")]
    assert len(secrets) == 3, "the three plaintext secrets in lambda.tf must be found"
    for f in secrets:
        assert f["location"]["file"] == "lambda.tf"
        assert f["location"]["startLine"], "a secret finding must carry a real line"


@requires_checkov
def test_the_default_framework_set_includes_secrets():
    assert "terraform" in run_checkov.DEFAULT_FRAMEWORKS
    assert "secrets" in run_checkov.DEFAULT_FRAMEWORKS


@requires_checkov
def test_every_real_finding_has_a_clean_repo_relative_path():
    """The join-key guarantee, asserted against real Checkov output."""
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-03-data-lake"))
    for f in result["findings"] + result["passedChecks"]:
        path = f["location"]["file"]
        assert path, "empty file path in %s" % f["ruleId"]
        assert not path.startswith("/"), path
        assert not path.startswith("./"), path
        # And it actually exists relative to the scan root.
        assert os.path.isfile(os.path.join(result["scanRoot"], path)), path


@requires_checkov
def test_no_finding_carries_a_fabricated_severity():
    result = run_checkov.run_checkov(os.path.join(FIXTURES, "tf-02-serverless-api"))
    assert all(f["severity"] is None for f in result["findings"])


@requires_checkov
def test_cli_emits_json_on_stdout_and_exits_zero():
    proc = subprocess.run(
        [sys.executable, SCRIPT, os.path.join(FIXTURES, "tf-03-data-lake")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert len(payload["findings"]) == 26
    assert payload["degraded"] is False


def test_cli_exits_2_on_bad_path():
    proc = subprocess.run(
        [sys.executable, SCRIPT, "/nonexistent/path/xyz"], capture_output=True, text=True
    )
    assert proc.returncode == 2
