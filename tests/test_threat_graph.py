"""Tests for skills/threat-model/scripts/graph_semantics.py.

What must hold:

1. Attack paths on the fixture corpus match tests/data/threat-answer-key.json:
   tf-01 ALB -> app tier -> RDS; tf-02 API Gateway -> Lambda -> role -> DynamoDB;
   cfn-01 the WordPress stack; tf-06 (hardened) none at all.
2. Terraform and CloudFormation produce the same semantic node kinds for the
   equivalent fixture pair (tf-01 / cfn-01).
3. Every node has a trust boundary.
4. A mention is not an edge: tf-02's Lambda names the table in an env var and
   there is still no lambda -> table edge; the path goes through the role.
5. The type tables are imported from merge_findings, not copied.
"""

import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TM_SCRIPTS = os.path.join(REPO_ROOT, "skills", "threat-model", "scripts")
PARSER = os.path.join(REPO_ROOT, "skills", "security-scan", "scripts", "parse_iac.py")
FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
ANSWER_KEY = os.path.join(REPO_ROOT, "tests", "data", "threat-answer-key.json")
sys.path.insert(0, TM_SCRIPTS)

import graph_semantics as gs  # noqa: E402

_PARSE_CACHE = {}


def parse_fixture(name, fmt):
    if name in _PARSE_CACHE:
        return _PARSE_CACHE[name]
    proc = subprocess.run(
        [sys.executable, PARSER, fmt, os.path.join(FIXTURES, name), "--json-only"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    data = json.loads(proc.stdout)
    _PARSE_CACHE[name] = data
    return data


@pytest.fixture(scope="module")
def answer_key():
    with open(ANSWER_KEY, encoding="utf-8") as fh:
        return json.load(fh)


def graph_for(name, fmt):
    graph = gs.build_graph(parse_fixture(name, fmt))
    graph["attackPaths"] = gs.find_attack_paths(graph)
    return graph


def _path_matches(path, expected):
    if path[0] != expected["entry"] or path[-1] != expected["terminus"]:
        return False
    cursor = 1
    for group in expected.get("through") or []:
        hit = None
        for i in range(cursor, len(path) - 1):
            if path[i] in group:
                hit = i
                break
        if hit is None:
            return False
        cursor = hit + 1
    return True


@pytest.mark.parametrize("fixture", ["tf-01-three-tier-webapp", "tf-02-serverless-api", "cfn-01-wordpress-ec2-rds", "tf-06-hardened-three-tier"])
def test_attack_paths_match_answer_key(fixture, answer_key):
    expected = answer_key["fixtures"][fixture]
    graph = graph_for(fixture, expected["format"])
    paths = [p["path"] for p in graph["attackPaths"]]
    if expected.get("exactlyZero"):
        assert paths == [], "hardened fixture must yield no path, got %s" % paths
        assert graph["entrypoints"] == []
        return
    for exp in expected["expectedPaths"]:
        assert any(_path_matches(p, exp) for p in paths), "no path for %s -> %s in %s" % (exp["entry"], exp["terminus"], paths)
    assert sorted(e["id"] for e in graph["entrypoints"]) == sorted(expected["entrypoints"])


def test_tf02_path_goes_through_the_role_not_a_mention():
    graph = graph_for("tf-02-serverless-api", "terraform")
    direct = [e for e in graph["edges"] if e["source"].startswith("aws_lambda_function.") and e["target"] == "aws_dynamodb_table.main"]
    assert direct == [], "a Lambda env var naming the table must not be an edge"
    for p in graph["attackPaths"]:
        if p["path"][-1] == "aws_dynamodb_table.main":
            assert "aws_iam_role.lambda_exec" in p["path"]
            perm = [e for e in p["edges"] if e["kind"] == "permission"]
            assert perm and "dynamodb:*" in (perm[0]["actions"] or [])


def test_tf01_path_is_network_mediated_with_ports():
    graph = graph_for("tf-01-three-tier-webapp", "terraform")
    path = next(p for p in graph["attackPaths"] if p["path"][-1] == "aws_db_instance.main")
    kinds = [e["kind"] for e in path["edges"]]
    assert "network" in kinds and "attach" in kinds
    last_network = [e for e in path["edges"] if e["kind"] == "network"][-1]
    assert last_network["ports"]["from"] == 3306
    assert path["severity"] == "critical"  # RDS storage_encrypted = false
    assert path["boundariesCrossed"][0].endswith(":public")


def test_every_node_has_a_boundary():
    for fixture, fmt in (("tf-01-three-tier-webapp", "terraform"), ("cfn-01-wordpress-ec2-rds", "cloudformation")):
        graph = graph_for(fixture, fmt)
        for node in graph["nodes"]:
            b = node["boundary"]
            assert b, node["id"]
            assert b.split(":")[0] in ("internet", "vpc", "subnet", "account", "principal"), b
            if b.startswith("subnet:"):
                assert b.endswith(":public") or b.endswith(":private")


def test_cfn_and_tf_produce_the_same_kinds_for_the_equivalent_pair():
    tf = graph_for("tf-01-three-tier-webapp", "terraform")
    cfn = graph_for("cfn-01-wordpress-ec2-rds", "cloudformation")
    tf_kinds = {n["kind"] for n in tf["nodes"]}
    cfn_kinds = {n["kind"] for n in cfn["nodes"]}
    required = {
        "load_balancer",
        "listener",
        "target_group",
        "autoscaling_group",
        "launch_template",
        "security_group",
        "rds_instance",
        "db_subnet_group",
        "iam_role",
        "instance_profile",
        "subnet",
        "vpc",
        "internet_gateway",
        "nat_gateway",
        "route_table",
        "route",
        "route_table_association",
        "internet",
    }
    assert required <= tf_kinds, required - tf_kinds
    assert required <= cfn_kinds, required - cfn_kinds
    # Same path shape too: entry kind, terminus kind, and the compute hop.
    tf_path = next(p for p in tf["attackPaths"] if p["path"][-1] == "aws_db_instance.main")
    cfn_path = next(p for p in cfn["attackPaths"] if p["path"][-1] == "DBInstance")
    assert tf_path["nodeKinds"] == cfn_path["nodeKinds"]


def test_type_map_rows_are_well_formed():
    for kind, tf_types, cfn_types in gs.TYPE_MAP:
        assert kind == kind.lower() and " " not in kind
        for t in tf_types:
            assert t.startswith("aws_"), t
            assert gs.KIND_BY_TYPE[t] == kind
        for t in cfn_types:
            assert t.startswith("AWS::"), t
            assert gs.KIND_BY_TYPE[t] == kind
    # Every type that merge_findings treats as data or compute has a kind here.
    for t in gs.DATA_TYPES | gs.COMPUTE_TYPES:
        assert t in gs.KIND_BY_TYPE, t


def test_type_tables_are_imported_from_merge_findings():
    import merge_findings  # noqa: F401  (security-scan/scripts is on sys.path via graph_semantics)

    assert gs.DATA_TYPES is merge_findings.DATA_TYPES
    assert gs.COMPUTE_TYPES is merge_findings.COMPUTE_TYPES
    assert gs.TRANSIT_HUB_TYPES is merge_findings.TRANSIT_HUB_TYPES
    assert gs.CONNECTOR_TYPES is merge_findings.CONNECTOR_TYPES
    assert gs.MAX_PATH_SUBSTANTIVE == merge_findings.MAX_CHAIN_DEPTH


def test_security_group_flags_and_sources():
    cfn = graph_for("cfn-01-wordpress-ec2-rds", "cloudformation")
    nodes = {n["id"]: n for n in cfn["nodes"]}
    web = nodes["WebServerSecurityGroup"]
    assert web["flags"]["open_admin_ports"] == ["ssh/22"]
    assert web["flags"]["open_nonweb_ingress"] == ["tcp/22"]
    assert web["flags"]["open_all_ports"] is False
    # The ALB (attached to ALBSecurityGroup) is the source of the web SG's 80/443 edges.
    sources = {(e["source"], e["label"]) for e in cfn["edges"] if e["target"] == "WebServerSecurityGroup" and e["kind"] == "network"}
    assert ("ApplicationLoadBalancer", "tcp/80") in sources
    assert ("internet", "tcp/22") in sources
    # Publicly accessible RDS behind a closed SG is NOT an entrypoint, but is flagged.
    db = nodes["DBInstance"]
    assert db["flags"]["public"] is True
    assert db["flags"].get("public_but_closed") is True
    assert "DBInstance" not in {e["id"] for e in cfn["entrypoints"]}


def test_identity_flags():
    tf = graph_for("tf-02-serverless-api", "terraform")
    nodes = {n["id"]: n for n in tf["nodes"]}
    policy = nodes["aws_iam_role_policy.lambda_dynamodb"]
    assert policy["flags"]["service_wildcard_actions"] == ["dynamodb:*"]
    assert policy["flags"]["wildcard_actions"] is False
    role = nodes["aws_iam_role.lambda_exec"]
    assert role["flags"]["trust_unknown"] is True  # data source document: degrade, never guess
    assert any("trust policy" in d for d in tf["degradations"])
    tf1 = graph_for("tf-01-three-tier-webapp", "terraform")
    n1 = {n["id"]: n for n in tf1["nodes"]}
    assert n1["aws_iam_role.ec2"]["flags"]["trust_services"] == ["ec2.amazonaws.com"]
    assert any(e["kind"] == "trust" and e["target"] == "aws_iam_role.ec2" for e in tf1["edges"])


def test_imdsv2_flag_reads_http_tokens():
    tf1 = graph_for("tf-01-three-tier-webapp", "terraform")
    tf6 = graph_for("tf-06-hardened-three-tier", "terraform")
    lt1 = next(n for n in tf1["nodes"] if n["id"] == "aws_launch_template.main")
    lt6 = next(n for n in tf6["nodes"] if n["id"] == "aws_launch_template.main")
    assert lt1["flags"]["imdsv2"] is False  # no metadata_options block at all
    assert lt6["flags"]["imdsv2"] is True  # http_tokens = "required" (the parser keeps setting keys)
    assert not any("IMDSv2" in d for d in tf6["degradations"])


def test_redacted_imds_is_unknown_not_false():
    # Defensive path: an older parser output with http_tokens redacted must read
    # as unknown, never as "IMDSv2 off".
    parsed = {
        "format": "terraform",
        "resources": [{
            "type": "aws_launch_template", "name": "lt", "full_name": "aws_launch_template.lt",
            "attributes": {"metadata_options": [{"http_tokens": "[REDACTED]"}]},
            "location": {"resourceType": "aws_launch_template", "resourceAddress": "aws_launch_template.lt"},
        }],
        "dependencies": {},
    }
    graph = gs.build_graph(parsed)
    lt = next(n for n in graph["nodes"] if n["id"] == "aws_launch_template.lt")
    assert lt["flags"]["imdsv2"] is None
    assert any("IMDSv2" in d for d in graph["degradations"])


def test_plaintext_secret_detection():
    tf2 = graph_for("tf-02-serverless-api", "terraform")
    fn = next(n for n in tf2["nodes"] if n["id"] == "aws_lambda_function.create_item")
    paths = sorted(s["path"] for s in fn["flags"]["plaintext_secrets"])
    assert paths == ["environment.variables.API_KEY", "environment.variables.DB_PASSWORD", "environment.variables.ENCRYPTION_SECRET"]
    clean = next(n for n in tf2["nodes"] if n["id"] == "aws_lambda_function.get_item")
    assert clean["flags"]["plaintext_secrets"] == []
    cfn = graph_for("cfn-01-wordpress-ec2-rds", "cloudformation")
    db = next(n for n in cfn["nodes"] if n["id"] == "DBInstance")
    assert db["flags"]["plaintext_secrets"][0]["path"] == "MasterUserPassword"


def test_unsupported_format_degrades_loudly():
    graph = gs.build_graph({"format": "kubernetes", "resources": [{"type": "Deployment", "name": "x"}]})
    assert graph["nodes"] == []
    assert graph["degraded"] is True
    assert any("kubernetes" in d for d in graph["degradations"])
