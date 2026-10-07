#!/usr/bin/env python3
"""
graph_semantics.py -- a DIRECTED semantic graph from the IaC parser output.

The security-scan parser (`parse_iac.py`) emits resources and a flat reference
graph: "resource A mentions resource B". That is enough to find exposure chains,
but it has no direction and no meaning. This module turns it into a graph an
analyst can reason about:

  * nodes carry a semantic KIND (`load_balancer`, `security_group`, `iam_role`,
    `rds_instance`, ...) that is the same for Terraform and CloudFormation;
  * edges are typed and directed in the direction an attacker moves:
      network     source (internet, CIDR, or a resource behind a source SG) -> SG
      attach      SG -> the resource it protects
      forward     load balancer -> listener -> target group -> target
      invoke      API Gateway -> Lambda
      assumes     compute -> instance profile -> role
      trust       principal -> role (who may assume it)
      permission  role -> resource (what it may do there), with actions
      grants      policy -> role (provenance; never traversed)
      serves      EFS mount target -> file system
      launches    autoscaling group -> launch template
  * every node gets a TRUST BOUNDARY: `internet`, `vpc:<id>`,
    `subnet:<id>:public|private`, `account`, or `principal`.

The type tables (DATA_TYPES, COMPUTE_TYPES, TRANSIT_HUB_TYPES, CONNECTOR_TYPES,
OBSERVER_TYPES, INTERNET_EXPOSED_TYPES) and the hop budget are IMPORTED from
security-scan's merge_findings.py, not copied. One source of truth.

Scope (v1): AWS resources in Terraform and CloudFormation. Anything else is
reported in `graph["degradations"]` -- loudly, never silently.

What is deliberately NOT an edge:
  * a compute resource that merely mentions a data resource's name or endpoint
    (a Lambda env var `TABLE_NAME`, a user_data template with the DB endpoint).
    A name is not access. Access is an IAM permission or a network rule, and
    only those become edges. This is why the serverless path reads
    `api -> lambda -> role -> table` and not `api -> lambda -> table`.
  * VPC, route table, subnet, IGW and NAT nodes as intermediate hops. They are
    placement, not reachability (the hub argument from merge_findings).
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

_LIB = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "lib")
)
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)
from iac_tools import paths  # noqa: E402

_SEC_SCRIPTS = paths.skill_scripts("security-scan")
if _SEC_SCRIPTS not in sys.path:
    sys.path.insert(0, _SEC_SCRIPTS)

from merge_findings import (  # noqa: E402
    COMPUTE_TYPES,
    CONNECTOR_TYPES,
    DATA_TYPES,
    EXCLUDED_FROM_TRAVERSAL,
    INTERNET_EXPOSED_TYPES,
    MAX_CHAIN_DEPTH,
    MAX_CHAIN_NODES,
    OBSERVER_TYPES,
    OPEN_CIDRS,
    TRANSIT_HUB_TYPES,
    _drop_subsumed_chains,
)

SCHEMA = "iac-tools/threat-model/graph/v1"

# ---------------------------------------------------------------------------
# Type mapping: Terraform type <-> CloudFormation type -> semantic kind
# ---------------------------------------------------------------------------

#: (kind, terraform types, cloudformation types). Both formats land on the same
#: kind, which is what lets one rules file and one answer key serve both.
TYPE_MAP: List[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = [
    ("vpc", ("aws_vpc", "aws_default_vpc"), ("AWS::EC2::VPC",)),
    ("subnet", ("aws_subnet",), ("AWS::EC2::Subnet",)),
    ("internet_gateway", ("aws_internet_gateway",), ("AWS::EC2::InternetGateway",)),
    ("nat_gateway", ("aws_nat_gateway",), ("AWS::EC2::NatGateway",)),
    ("route_table", ("aws_route_table", "aws_default_route_table"), ("AWS::EC2::RouteTable",)),
    ("route", ("aws_route",), ("AWS::EC2::Route",)),
    ("route_table_association", ("aws_route_table_association",), ("AWS::EC2::SubnetRouteTableAssociation",)),
    ("security_group", ("aws_security_group", "aws_default_security_group"), ("AWS::EC2::SecurityGroup",)),
    (
        "security_group_rule",
        ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"),
        ("AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"),
    ),
    ("network_acl", ("aws_network_acl",), ("AWS::EC2::NetworkAcl",)),
    ("elastic_ip", ("aws_eip",), ("AWS::EC2::EIP",)),
    ("eip_association", ("aws_eip_association",), ("AWS::EC2::EIPAssociation",)),
    ("flow_log", ("aws_flow_log",), ("AWS::EC2::FlowLog",)),
    ("load_balancer", ("aws_lb", "aws_alb", "aws_elb"), ("AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancing::LoadBalancer")),
    ("listener", ("aws_lb_listener", "aws_alb_listener"), ("AWS::ElasticLoadBalancingV2::Listener",)),
    ("listener_rule", ("aws_lb_listener_rule", "aws_alb_listener_rule"), ("AWS::ElasticLoadBalancingV2::ListenerRule",)),
    ("target_group", ("aws_lb_target_group", "aws_alb_target_group"), ("AWS::ElasticLoadBalancingV2::TargetGroup",)),
    ("target_group_attachment", ("aws_lb_target_group_attachment", "aws_alb_target_group_attachment"), ()),
    ("instance", ("aws_instance",), ("AWS::EC2::Instance",)),
    ("launch_template", ("aws_launch_template",), ("AWS::EC2::LaunchTemplate",)),
    ("launch_configuration", ("aws_launch_configuration",), ("AWS::AutoScaling::LaunchConfiguration",)),
    ("autoscaling_group", ("aws_autoscaling_group",), ("AWS::AutoScaling::AutoScalingGroup",)),
    ("lambda_function", ("aws_lambda_function",), ("AWS::Lambda::Function",)),
    ("lambda_url", ("aws_lambda_function_url",), ("AWS::Lambda::Url",)),
    ("lambda_permission", ("aws_lambda_permission",), ("AWS::Lambda::Permission",)),
    ("ecs_cluster", ("aws_ecs_cluster",), ("AWS::ECS::Cluster",)),
    ("ecs_service", ("aws_ecs_service",), ("AWS::ECS::Service",)),
    ("ecs_task_definition", ("aws_ecs_task_definition",), ("AWS::ECS::TaskDefinition",)),
    ("eks_cluster", ("aws_eks_cluster",), ("AWS::EKS::Cluster",)),
    ("batch_job_definition", ("aws_batch_job_definition",), ("AWS::Batch::JobDefinition",)),
    ("api_gateway", ("aws_api_gateway_rest_api", "aws_apigatewayv2_api"), ("AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api")),
    ("api_stage", ("aws_api_gateway_stage", "aws_apigatewayv2_stage"), ("AWS::ApiGateway::Stage", "AWS::ApiGatewayV2::Stage")),
    ("api_resource", ("aws_api_gateway_resource",), ("AWS::ApiGateway::Resource",)),
    ("api_method", ("aws_api_gateway_method",), ("AWS::ApiGateway::Method",)),
    ("api_route", ("aws_apigatewayv2_route",), ("AWS::ApiGatewayV2::Route",)),
    ("api_integration", ("aws_api_gateway_integration", "aws_apigatewayv2_integration"), ("AWS::ApiGatewayV2::Integration",)),
    ("api_deployment", ("aws_api_gateway_deployment", "aws_apigatewayv2_deployment"), ("AWS::ApiGateway::Deployment", "AWS::ApiGatewayV2::Deployment")),
    ("api_authorizer", ("aws_api_gateway_authorizer", "aws_apigatewayv2_authorizer"), ("AWS::ApiGateway::Authorizer", "AWS::ApiGatewayV2::Authorizer")),
    ("api_method_settings", ("aws_api_gateway_method_settings",), ()),
    ("cloudfront_distribution", ("aws_cloudfront_distribution",), ("AWS::CloudFront::Distribution",)),
    ("dns_record", ("aws_route53_record",), ("AWS::Route53::RecordSet",)),
    ("waf_web_acl", ("aws_wafv2_web_acl", "aws_waf_web_acl", "aws_wafregional_web_acl"), ("AWS::WAFv2::WebACL",)),
    ("waf_association", ("aws_wafv2_web_acl_association", "aws_wafregional_web_acl_association"), ("AWS::WAFv2::WebACLAssociation",)),
    ("s3_bucket", ("aws_s3_bucket",), ("AWS::S3::Bucket",)),
    ("s3_public_access_block", ("aws_s3_bucket_public_access_block",), ()),
    ("s3_bucket_policy", ("aws_s3_bucket_policy",), ("AWS::S3::BucketPolicy",)),
    ("s3_encryption", ("aws_s3_bucket_server_side_encryption_configuration",), ()),
    ("s3_versioning", ("aws_s3_bucket_versioning",), ()),
    ("s3_logging", ("aws_s3_bucket_logging",), ()),
    ("s3_acl", ("aws_s3_bucket_acl",), ()),
    ("rds_instance", ("aws_db_instance",), ("AWS::RDS::DBInstance",)),
    ("rds_cluster", ("aws_rds_cluster",), ("AWS::RDS::DBCluster",)),
    ("db_subnet_group", ("aws_db_subnet_group",), ("AWS::RDS::DBSubnetGroup",)),
    ("db_snapshot", ("aws_db_snapshot", "aws_db_cluster_snapshot"), ()),
    ("ami_launch_permission", ("aws_ami_launch_permission",), ()),
    ("dynamodb_table", ("aws_dynamodb_table",), ("AWS::DynamoDB::Table",)),
    ("efs_file_system", ("aws_efs_file_system",), ("AWS::EFS::FileSystem",)),
    ("efs_mount_target", ("aws_efs_mount_target",), ("AWS::EFS::MountTarget",)),
    ("elasticache_cluster", ("aws_elasticache_cluster", "aws_elasticache_replication_group"), ("AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ReplicationGroup")),
    ("redshift_cluster", ("aws_redshift_cluster",), ("AWS::Redshift::Cluster",)),
    ("secret", ("aws_secretsmanager_secret",), ("AWS::SecretsManager::Secret",)),
    ("secret_rotation", ("aws_secretsmanager_secret_rotation",), ("AWS::SecretsManager::RotationSchedule",)),
    ("ssm_parameter", ("aws_ssm_parameter",), ("AWS::SSM::Parameter",)),
    ("kms_key", ("aws_kms_key",), ("AWS::KMS::Key",)),
    ("glue_database", ("aws_glue_catalog_database",), ("AWS::Glue::Database",)),
    ("athena_workgroup", ("aws_athena_workgroup",), ("AWS::Athena::WorkGroup",)),
    ("ecr_repository", ("aws_ecr_repository",), ("AWS::ECR::Repository",)),
    ("backup_vault", ("aws_backup_vault",), ("AWS::Backup::BackupVault",)),
    ("sqs_queue", ("aws_sqs_queue",), ("AWS::SQS::Queue",)),
    ("sns_topic", ("aws_sns_topic",), ("AWS::SNS::Topic",)),
    ("sns_subscription", ("aws_sns_topic_subscription",), ("AWS::SNS::Subscription",)),
    ("iam_role", ("aws_iam_role",), ("AWS::IAM::Role",)),
    ("iam_user", ("aws_iam_user",), ("AWS::IAM::User",)),
    ("iam_group", ("aws_iam_group",), ("AWS::IAM::Group",)),
    ("iam_policy", ("aws_iam_policy",), ("AWS::IAM::ManagedPolicy",)),
    ("iam_inline_policy", ("aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"), ("AWS::IAM::Policy",)),
    (
        "iam_policy_attachment",
        ("aws_iam_role_policy_attachment", "aws_iam_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment"),
        (),
    ),
    ("instance_profile", ("aws_iam_instance_profile",), ("AWS::IAM::InstanceProfile",)),
    ("log_group", ("aws_cloudwatch_log_group",), ("AWS::Logs::LogGroup",)),
    ("cloudtrail", ("aws_cloudtrail",), ("AWS::CloudTrail::Trail",)),
    ("cloudwatch_alarm", ("aws_cloudwatch_metric_alarm", "aws_cloudwatch_composite_alarm"), ("AWS::CloudWatch::Alarm", "AWS::CloudWatch::CompositeAlarm")),
    ("cloudwatch_dashboard", ("aws_cloudwatch_dashboard",), ("AWS::CloudWatch::Dashboard",)),
    ("log_metric_filter", ("aws_cloudwatch_log_metric_filter",), ("AWS::Logs::MetricFilter",)),
    ("cognito_user_pool", ("aws_cognito_user_pool",), ("AWS::Cognito::UserPool",)),
]

KIND_BY_TYPE: Dict[str, str] = {}
TF_TYPES_BY_KIND: Dict[str, Tuple[str, ...]] = {}
CFN_TYPES_BY_KIND: Dict[str, Tuple[str, ...]] = {}
for _kind, _tf, _cfn in TYPE_MAP:
    TF_TYPES_BY_KIND[_kind] = _tf
    CFN_TYPES_BY_KIND[_kind] = _cfn
    for _t in _tf + _cfn:
        KIND_BY_TYPE[_t] = _kind


def kinds_for(types: Iterable[str]) -> frozenset:
    return frozenset(KIND_BY_TYPE[t] for t in types if t in KIND_BY_TYPE)


#: Derived from the imported tables, so the two engines never disagree.
DATA_KINDS = kinds_for(DATA_TYPES)
COMPUTE_KINDS = kinds_for(COMPUTE_TYPES)
HUB_KINDS = kinds_for(TRANSIT_HUB_TYPES) | frozenset(
    {"subnet", "internet_gateway", "nat_gateway", "route", "db_subnet_group", "elastic_ip", "eip_association", "flow_log"}
)
OBSERVER_KINDS = kinds_for(OBSERVER_TYPES)
EXCLUDED_KINDS = HUB_KINDS | OBSERVER_KINDS | frozenset({"other", "cidr", "principal", "managed_policy", "external_resource"})
#: Free hops: wiring between components. IAM and API Gateway plumbing come from
#: CONNECTOR_TYPES; the network wiring that this graph makes explicit (security
#: groups, listeners, target groups) is added here for the same reason.
CONNECTOR_KINDS = kinds_for(CONNECTOR_TYPES) | frozenset(
    {
        "security_group",
        "listener",
        "listener_rule",
        "target_group",
        "target_group_attachment",
        "lambda_url",
        "efs_mount_target",
        "waf_association",
        "api_stage",
        "iam_user",
        "iam_group",
    }
)
#: The chain budget, as in merge_findings: MAX_CHAIN_DEPTH substantive hops.
#: The raw node cap grows by one tier of wiring (SG + listener + target group +
#: template = 4) because this graph makes those hops explicit free nodes that
#: the reference graph folds into edges.
MAX_PATH_SUBSTANTIVE = MAX_CHAIN_DEPTH
MAX_PATH_NODES = MAX_CHAIN_NODES + 4

#: Kinds whose public exposure is governed by a security group.
SG_GOVERNED_KINDS = frozenset(
    {
        "load_balancer",
        "instance",
        "launch_template",
        "launch_configuration",
        "rds_instance",
        "rds_cluster",
        "redshift_cluster",
        "elasticache_cluster",
        "ecs_service",
        "efs_mount_target",
        "eks_cluster",
    }
)

INTERNET = "internet"
ANY_RESOURCE = "resource:*"
ANY_PRINCIPAL = "principal:*"

ADMIN_PORTS = {22: "ssh", 3389: "rdp", 5985: "winrm", 5986: "winrm"}
DB_PORTS = {
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    2049: "nfs",
    5439: "redshift",
}

#: Services where a wildcard resource is a data or identity exposure, not noise.
DATA_SERVICES = frozenset(
    {
        "s3",
        "dynamodb",
        "rds",
        "rds-db",
        "secretsmanager",
        "ssm",
        "kms",
        "elasticfilesystem",
        "elasticache",
        "redshift",
        "glue",
        "athena",
        "ecr",
        "backup",
        "sqs",
        "sns",
        "iam",
        "sts",
        "lambda",
    }
)

PRIVESC_ACTIONS = frozenset(
    {
        "iam:*",
        "iam:passrole",
        "iam:createpolicyversion",
        "iam:setdefaultpolicyversion",
        "iam:attachrolepolicy",
        "iam:attachuserpolicy",
        "iam:attachgrouppolicy",
        "iam:putrolepolicy",
        "iam:putuserpolicy",
        "iam:putgrouppolicy",
        "iam:createaccesskey",
        "iam:createloginprofile",
        "iam:updateloginprofile",
        "iam:updateassumerolepolicy",
        "iam:addusertogroup",
        "sts:assumerole",
        "lambda:updatefunctioncode",
        "lambda:createfunction",
    }
)

#: The shared parser replaces scalars under secret-looking keys with this marker
#: (lib/iac_tools/parse_iac.py: redact_secrets). A marker proves a literal was
#: there; it hides what the literal said.
REDACTED = "[REDACTED]"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TF_ADDR_RE = re.compile(r"(aws_[a-z0-9_]+)\.([A-Za-z0-9_\-]+(?:\[[0-9]+\])?)")
_CFN_SUB_RE = re.compile(r"\$\{([A-Za-z0-9]+)(?:\.[A-Za-z0-9.]+)?\}")
_ACCOUNT_RE = re.compile(r"^\d{12}$")

SECRET_KEY_RE = re.compile(r"(?i)(passw(or)?d|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)")
SECRET_SKIP_RE = re.compile(
    r"(?i)(arn|_id$|^id$|kms|key_?name|hash_key|range_key|sort_key|partition|^key$|http_?tokens|key_schema|"
    r"key_spec|key_usage|rotation|policy|_name$|description|version|_count$|length|enabled|type$|source_code_hash|"
    r"secret_recovery|recovery_window|token_validity|tokens_valid|token_expiration|generate_secret|^tags?$)"
)
USER_DATA_SECRET_RE = re.compile(r"(?i)(passw(or)?d|secret|api[_-]?key|token)\s*[=:]\s*['\"]?([^\s'\"$]{6,})")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _blocks(value: Any) -> List[Dict[str, Any]]:
    """tfparse emits a nested block as a dict, repeated blocks as a list."""
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _get(attrs: Dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(attrs, dict) and name in attrs and attrs[name] is not None:
            return attrs[name]
    return default


def _truthy(value: Any) -> Optional[bool]:
    """Bool from a Terraform/CFN scalar. None when unknown (a reference)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "1", "enabled", "required"):
            return True
        if low in ("false", "no", "0", "disabled", "optional"):
            return False
    return None


def _is_open_cidr(cidr: Any) -> bool:
    return isinstance(cidr, str) and cidr.strip() in OPEN_CIDRS


def _ports(from_port: Any, to_port: Any, protocol: Any) -> Dict[str, Any]:
    proto = str(protocol).lower() if protocol is not None else "tcp"
    if proto in ("-1", "all"):
        return {"from": 0, "to": 65535, "protocol": "all"}
    try:
        f = int(from_port) if from_port is not None else 0
    except (TypeError, ValueError):
        f = 0
    try:
        t = int(to_port) if to_port is not None else f
    except (TypeError, ValueError):
        t = f
    if f == 0 and t == 0 and proto in ("tcp", "udp", "6", "17"):
        # Terraform's "all ports" for a single protocol.
        t = 65535
    return {"from": f, "to": t, "protocol": proto}


def _port_label(p: Dict[str, Any]) -> str:
    if p["protocol"] == "all":
        return "all ports"
    if p["from"] == p["to"]:
        return "%s/%s" % (p["protocol"], p["from"])
    return "%s/%s-%s" % (p["protocol"], p["from"], p["to"])


def _covers(p: Dict[str, Any], port: int) -> bool:
    return p["protocol"] in ("all", "tcp", "6") and p["from"] <= port <= p["to"]


def _parse_json_doc(value: Any) -> Optional[Dict[str, Any]]:
    """A policy document: a dict (CFN) or a JSON string (Terraform jsonencode)."""
    if isinstance(value, dict) and ("Statement" in value or "statement" in value):
        if value.get("Statement", value.get("statement")) is None:
            return None  # tfparse could not evaluate the document
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{"):
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                return None
            if not isinstance(doc, dict) or doc.get("Statement", doc.get("statement")) is None:
                return None
            return doc
    return None


def _statements(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    stmts = doc.get("Statement", doc.get("statement"))
    if isinstance(stmts, dict):
        return [stmts]
    return [s for s in _as_list(stmts) if isinstance(s, dict)]


def _safe_name(value: Any, limit: int = 60) -> str:
    """Names are untrusted repo content: keep them printable and short."""
    text = str(value if value is not None else "")
    text = re.sub(r"[^\w .\-\[\]:/]", "", text)
    return text[:limit]


# ---------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------


class SemanticGraph:
    def __init__(self, parse: Dict[str, Any]):
        self.parse = parse
        self.format = (parse.get("format") or "").lower()
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._edge_keys: Set[Tuple[str, str, str, str]] = set()
        self.by_uuid: Dict[str, str] = {}
        self.resources: Dict[str, Dict[str, Any]] = {}
        self.dependencies: Dict[str, List[str]] = parse.get("dependencies") or {}
        self.parameters: Dict[str, Any] = parse.get("parameters") or {}
        self.degradations: List[str] = []
        self.unmapped_types: Dict[str, int] = {}
        self.entrypoints: List[Dict[str, Any]] = []

    # -- resource access ---------------------------------------------------

    @staticmethod
    def address_of(res: Dict[str, Any]) -> str:
        loc = res.get("location") or {}
        return loc.get("resourceAddress") or res.get("full_name") or res.get("logical_id") or res.get("name") or ""

    @staticmethod
    def attrs(res: Dict[str, Any]) -> Dict[str, Any]:
        a = res.get("attributes")
        if a is None:
            a = res.get("properties")
        return a if isinstance(a, dict) else {}

    def node(self, nid: str) -> Optional[Dict[str, Any]]:
        return self.nodes.get(nid)

    def kind(self, nid: str) -> str:
        n = self.nodes.get(nid)
        return n["kind"] if n else ""

    def nodes_of_kind(self, *kinds: str) -> List[Dict[str, Any]]:
        return [n for n in self.nodes.values() if n["kind"] in kinds]

    def add_edge(self, source: str, target: str, kind: str, **extra: Any) -> Optional[Dict[str, Any]]:
        if not source or not target or source == target:
            return None
        if source not in self.nodes or target not in self.nodes:
            return None
        label = extra.get("label") or ""
        key = (source, target, kind, label)
        if key in self._edge_keys:
            # Merge provenance for a duplicate edge instead of repeating it.
            for e in self.edges:
                if (e["source"], e["target"], e["kind"], e.get("label") or "") == key:
                    for v in _as_list(extra.get("via")):
                        if v not in e["via"]:
                            e["via"].append(v)
                    return e
            return None
        self._edge_keys.add(key)
        edge = {
            "source": source,
            "target": target,
            "kind": kind,
            "label": label,
            "ports": extra.get("ports"),
            "protocol": extra.get("protocol"),
            "actions": extra.get("actions"),
            "via": list(_as_list(extra.get("via"))),
            "flags": extra.get("flags") or {},
        }
        self.edges.append(edge)
        return edge

    def _synthetic(self, nid: str, kind: str, boundary: str, name: str, **flags: Any) -> Dict[str, Any]:
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id": nid,
                "kind": kind,
                "type": None,
                "format": None,
                "name": name,
                "boundary": boundary,
                "vpc": None,
                "subnets": [],
                "flags": dict(flags),
                "location": None,
                "synthetic": True,
            }
        return self.nodes[nid]

    # -- reference resolution ---------------------------------------------

    def resolve(self, value: Any, kinds: Optional[Iterable[str]] = None) -> List[str]:
        """Node ids referenced by `value`, in order, without duplicates.

        Handles tfparse's resolved UUIDs, `{"__attribute__": "aws_x.y.attr"}`,
        raw `aws_x.y.attr` strings (lower parser tiers), `${...}` interpolation,
        and CloudFormation `Ref` / `Fn::GetAtt` / `Fn::Sub`.
        """
        out: List[str] = []
        want = set(kinds) if kinds else None

        def add(nid: str) -> None:
            if nid in self.nodes and nid not in out and (want is None or self.nodes[nid]["kind"] in want):
                out.append(nid)

        def walk(v: Any) -> None:
            if isinstance(v, str):
                s = v.strip()
                m = _UUID_RE.match(s)
                if m and m.group(0) in self.by_uuid:
                    add(self.by_uuid[m.group(0)])
                    return
                for tm in _TF_ADDR_RE.finditer(s):
                    add("%s.%s" % (tm.group(1), tm.group(2)))
                if self.format == "cloudformation":
                    for cm in _CFN_SUB_RE.finditer(s):
                        add(cm.group(1))
                    if s in self.nodes:
                        add(s)
            elif isinstance(v, dict):
                if "__attribute__" in v:
                    walk(v["__attribute__"])
                    return
                meta = v.get("__tfmeta")
                if isinstance(meta, dict):
                    # tfparse records the referenced resource on the block.
                    for ref in meta.get("references") or []:
                        if isinstance(ref, dict) and ref.get("name"):
                            add("%s.%s" % (ref.get("label"), ref["name"]))
                if "Ref" in v and isinstance(v["Ref"], str):
                    add(v["Ref"])
                    return
                if "Fn::GetAtt" in v:
                    ga = v["Fn::GetAtt"]
                    if isinstance(ga, list) and ga:
                        add(str(ga[0]))
                    elif isinstance(ga, str):
                        add(ga.split(".")[0])
                    return
                if "Fn::Sub" in v:
                    sub = v["Fn::Sub"]
                    if isinstance(sub, list):
                        for item in sub:
                            walk(item)
                    else:
                        walk(sub)
                    return
                for k, item in v.items():
                    if k == "__tfmeta":
                        continue
                    walk(item)
            elif isinstance(v, list):
                for item in v:
                    walk(item)

        walk(value)
        return out

    def refs_of(self, res: Dict[str, Any], kinds: Iterable[str]) -> List[str]:
        """Fallback: the parser's own reference list, filtered by kind.

        Used when an attribute was resolved by tfparse to a plain name (an
        instance profile's `role = "my-role"`) and so cannot be traced by value.
        """
        want = set(kinds)
        out: List[str] = []
        for ref in res.get("references") or []:
            label = ref.get("label") or ""
            name = ref.get("name") or ""
            if not name:
                continue
            nid = "%s.%s" % (label, name)
            if nid in self.nodes and self.nodes[nid]["kind"] in want and nid not in out:
                out.append(nid)
        address = self.address_of(res)
        for dep in self.dependencies.get(address) or []:
            if dep in self.nodes and self.nodes[dep]["kind"] in want and dep not in out:
                out.append(dep)
        return out

    def link(self, res: Dict[str, Any], value: Any, kinds: Iterable[str], fallback: bool = True) -> List[str]:
        found = self.resolve(value, kinds)
        if found or not fallback:
            return found
        return self.refs_of(res, kinds)

    def scan_keys(self, value: Any, keys: Set[str], kinds: Iterable[str], path: str = "") -> List[str]:
        """Resolve every attribute whose key is in `keys`, at any nesting depth."""
        out: List[str] = []
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "__tfmeta":
                    continue
                if k in keys:
                    for nid in self.resolve(v, kinds):
                        if nid not in out:
                            out.append(nid)
                else:
                    for nid in self.scan_keys(v, keys, kinds, path + "." + k):
                        if nid not in out:
                            out.append(nid)
        elif isinstance(value, list):
            for item in value:
                for nid in self.scan_keys(item, keys, kinds, path):
                    if nid not in out:
                        out.append(nid)
        return out

    # -- build --------------------------------------------------------------

    def build(self) -> Dict[str, Any]:
        if self.format not in ("terraform", "cloudformation"):
            self.degradations.append(
                "threat-model v1 covers Terraform and CloudFormation. Format %r is not modelled; "
                "no graph was built." % (self.format or "unknown")
            )
            return self.to_dict()
        if self.parse.get("degraded"):
            self.degradations.append(
                "DEGRADED PARSE (tier %s): %s. Attribute values may be unresolved; edges and flags "
                "that depend on them are missing, not merely uncertain."
                % (self.parse.get("parseTier"), self.parse.get("degradationReason") or "no line provenance")
            )
        self._make_nodes()
        self._synthetic(INTERNET, "internet", "internet", "Internet", public=True)
        self._network()
        self._placement()
        self._public_flags()
        self._forwarding()
        self._identity()
        self._data_flags()
        self._secrets()
        self._boundaries()
        self._entrypoints()
        self._report_unmapped()
        return self.to_dict()

    def _make_nodes(self) -> None:
        non_aws = 0
        for res in self.parse.get("resources") or []:
            address = self.address_of(res)
            rtype = res.get("type") or (res.get("location") or {}).get("resourceType") or ""
            if not address or not rtype:
                continue
            is_aws = rtype.startswith("aws_") or rtype.startswith("AWS::")
            if not is_aws:
                non_aws += 1
                continue
            kind = KIND_BY_TYPE.get(rtype, "other")
            if kind == "other":
                self.unmapped_types[rtype] = self.unmapped_types.get(rtype, 0) + 1
            attrs = self.attrs(res)
            uid = attrs.get("id")
            if isinstance(uid, str) and _UUID_RE.match(uid):
                self.by_uuid[uid] = address
            self.resources[address] = res
            self.nodes[address] = {
                "id": address,
                "kind": kind,
                "type": rtype,
                "format": self.format,
                "name": _safe_name(res.get("name") or res.get("logical_id") or address),
                "boundary": None,
                "vpc": None,
                "subnets": [],
                "flags": {},
                "location": res.get("location"),
                "synthetic": False,
            }
        if non_aws:
            self.degradations.append(
                "%d non-AWS resources were ignored. threat-model v1 models AWS only." % non_aws
            )

    # -- network ------------------------------------------------------------

    SG_KEYS = {
        "vpc_security_group_ids",
        "security_groups",
        "security_group_ids",
        "SecurityGroups",
        "SecurityGroupIds",
        "VPCSecurityGroups",
        "VpcSecurityGroupIds",
        "Groups",
        "GroupSet",
    }

    def _ingress_rules(self) -> List[Dict[str, Any]]:
        rules: List[Dict[str, Any]] = []

        def add(sg: str, via: str, spec: Dict[str, Any], tf_inline: bool) -> None:
            if tf_inline:
                ports = _ports(spec.get("from_port"), spec.get("to_port"), spec.get("protocol"))
                cidrs = _as_list(spec.get("cidr_blocks")) + _as_list(spec.get("ipv6_cidr_blocks"))
                src_sgs = self.resolve(spec.get("security_groups"), ["security_group"])
                self_ref = _truthy(spec.get("self")) or False
            else:
                ports = _ports(
                    _get(spec, "from_port", "FromPort"),
                    _get(spec, "to_port", "ToPort"),
                    _get(spec, "ip_protocol", "protocol", "IpProtocol"),
                )
                cidrs = []
                for key in ("cidr_ipv4", "cidr_ipv6", "CidrIp", "CidrIpv6"):
                    cidrs += _as_list(spec.get(key))
                cidrs += _as_list(spec.get("cidr_blocks")) + _as_list(spec.get("ipv6_cidr_blocks"))
                src_sgs = self.resolve(
                    [spec.get("referenced_security_group_id"), spec.get("source_security_group_id"), spec.get("SourceSecurityGroupId")],
                    ["security_group"],
                )
                self_ref = _truthy(spec.get("self")) or False
            if self_ref and sg not in src_sgs:
                src_sgs.append(sg)
            rules.append(
                {
                    "sg": sg,
                    "via": via,
                    "ports": ports,
                    "cidrs": [c for c in cidrs if isinstance(c, str)],
                    "source_sgs": src_sgs,
                    "description": _safe_name(_get(spec, "description", "Description", default="")),
                }
            )

        for sg in self.nodes_of_kind("security_group"):
            res = self.resources.get(sg["id"])
            if not res:
                continue
            a = self.attrs(res)
            for spec in _blocks(a.get("ingress")):
                add(sg["id"], sg["id"], spec, tf_inline=True)
            for spec in _blocks(a.get("SecurityGroupIngress")):
                add(sg["id"], sg["id"], spec, tf_inline=False)
        for rule in self.nodes_of_kind("security_group_rule"):
            res = self.resources.get(rule["id"])
            if not res:
                continue
            a = self.attrs(res)
            rtype = rule["type"]
            if rtype in ("aws_vpc_security_group_egress_rule", "AWS::EC2::SecurityGroupEgress"):
                continue
            if rtype == "aws_security_group_rule" and str(a.get("type", "ingress")).lower() != "ingress":
                continue
            targets = self.link(res, [a.get("security_group_id"), a.get("GroupId")], ["security_group"], fallback=False)
            if not targets and rtype != "aws_security_group_rule":
                targets = self.refs_of(res, ["security_group"])[:1]
            if not targets and rtype == "aws_security_group_rule":
                # The rule names the target first and the source second; the
                # reference list cannot tell them apart, so take the first.
                targets = self.refs_of(res, ["security_group"])[:1]
            for sg in targets:
                add(sg, rule["id"], a, tf_inline=False)
        return rules

    def _network(self) -> None:
        # Attachment: SG -> protected resource.
        attached_by_sg: Dict[str, List[str]] = {}
        for nid, node in list(self.nodes.items()):
            if node["kind"] in ("security_group", "security_group_rule") or node.get("synthetic"):
                continue
            res = self.resources.get(nid)
            if not res:
                continue
            sgs = self.scan_keys(self.attrs(res), self.SG_KEYS, ["security_group"])
            if sgs or node["kind"] in SG_GOVERNED_KINDS:
                node["flags"]["security_groups"] = sgs
            for sg in sgs:
                self.add_edge(sg, nid, "attach", label="protects")
                attached_by_sg.setdefault(sg, []).append(nid)
        self.attached_by_sg = attached_by_sg

        for sg in self.nodes_of_kind("security_group"):
            sg["flags"].setdefault("open_ingress", [])
            sg["flags"].setdefault("open_admin_ports", [])
            sg["flags"].setdefault("open_db_ports", [])
            sg["flags"].setdefault("open_all_ports", False)
            sg["flags"].setdefault("open_nonweb_ingress", [])
            sg["flags"].setdefault("ingress_rule_count", 0)
            sg["flags"]["attached"] = list(attached_by_sg.get(sg["id"], []))

        for rule in self._ingress_rules():
            sg = self.nodes[rule["sg"]]
            sg["flags"]["ingress_rule_count"] += 1
            label = _port_label(rule["ports"])
            for cidr in rule["cidrs"]:
                if _is_open_cidr(cidr):
                    source = INTERNET
                    sg["flags"]["open_ingress"].append(
                        {"ports": label, "cidr": cidr, "via": rule["via"], "description": rule["description"]}
                    )
                    if rule["ports"]["protocol"] == "all" or (rule["ports"]["from"] == 0 and rule["ports"]["to"] == 65535):
                        sg["flags"]["open_all_ports"] = True
                    web_only = rule["ports"]["from"] == rule["ports"]["to"] and rule["ports"]["from"] in (80, 443)
                    if not web_only and label not in sg["flags"]["open_nonweb_ingress"]:
                        sg["flags"]["open_nonweb_ingress"].append(label)
                    for port, name in ADMIN_PORTS.items():
                        if _covers(rule["ports"], port):
                            entry = "%s/%d" % (name, port)
                            if entry not in sg["flags"]["open_admin_ports"]:
                                sg["flags"]["open_admin_ports"].append(entry)
                    for port, name in DB_PORTS.items():
                        if _covers(rule["ports"], port):
                            entry = "%s/%d" % (name, port)
                            if entry not in sg["flags"]["open_db_ports"]:
                                sg["flags"]["open_db_ports"].append(entry)
                else:
                    source = "cidr:%s" % cidr
                    self._synthetic(source, "cidr", "internet", cidr, public=False, cidr=cidr)
                self.add_edge(source, sg["id"], "network", label=label, ports=rule["ports"], protocol=rule["ports"]["protocol"], via=rule["via"])
            for src_sg in rule["source_sgs"]:
                members = attached_by_sg.get(src_sg, [])
                if members:
                    for member in members:
                        self.add_edge(member, sg["id"], "network", label=label, ports=rule["ports"], protocol=rule["ports"]["protocol"], via=rule["via"], flags={"sourceSecurityGroup": src_sg})
                else:
                    self.add_edge(src_sg, sg["id"], "network", label=label, ports=rule["ports"], protocol=rule["ports"]["protocol"], via=rule["via"])

    # -- placement: subnets, VPCs, public subnets -----------------------------

    SUBNET_KEYS = {"subnet_id", "subnet_ids", "subnets", "vpc_zone_identifier", "SubnetId", "SubnetIds", "Subnets", "VPCZoneIdentifier"}
    VPC_KEYS = {"vpc_id", "VpcId"}

    def _placement(self) -> None:
        # Public subnets: an IGW route on an associated route table, or auto public IP.
        igw_tables: Set[str] = set()
        for rt in self.nodes_of_kind("route_table"):
            res = self.resources.get(rt["id"])
            if not res:
                continue
            for route in _blocks(self.attrs(res).get("route")):
                if self.resolve(route.get("gateway_id"), ["internet_gateway"]):
                    igw_tables.add(rt["id"])
        for route in self.nodes_of_kind("route"):
            res = self.resources.get(route["id"])
            if not res:
                continue
            a = self.attrs(res)
            if self.link(res, [a.get("gateway_id"), a.get("GatewayId")], ["internet_gateway"]):
                for rt in self.link(res, [a.get("route_table_id"), a.get("RouteTableId")], ["route_table"]):
                    igw_tables.add(rt)
        public_subnets: Set[str] = set()
        for assoc in self.nodes_of_kind("route_table_association"):
            res = self.resources.get(assoc["id"])
            if not res:
                continue
            a = self.attrs(res)
            rts = self.link(res, [a.get("route_table_id"), a.get("RouteTableId")], ["route_table"])
            subnets = self.link(res, [a.get("subnet_id"), a.get("SubnetId")], ["subnet"])
            if any(rt in igw_tables for rt in rts):
                public_subnets.update(subnets)
                for rt in rts:
                    for igw in self.nodes_of_kind("internet_gateway"):
                        for s in subnets:
                            self.add_edge(igw["id"], s, "route", label="0.0.0.0/0")
        for subnet in self.nodes_of_kind("subnet"):
            res = self.resources.get(subnet["id"])
            a = self.attrs(res) if res else {}
            auto_ip = _truthy(_get(a, "map_public_ip_on_launch", "MapPublicIpOnLaunch")) or False
            subnet["flags"]["public_ip_on_launch"] = auto_ip
            subnet["flags"]["igw_route"] = subnet["id"] in public_subnets
            subnet["flags"]["public"] = auto_ip or subnet["id"] in public_subnets
            subnet["vpc"] = (self.link(res, a.get("vpc_id") or a.get("VpcId"), ["vpc"]) or [None])[0] if res else None

        # Resource placement.
        for nid, node in self.nodes.items():
            if node.get("synthetic") or node["kind"] in ("subnet", "vpc"):
                continue
            res = self.resources.get(nid)
            if not res:
                continue
            a = self.attrs(res)
            subnets = self.scan_keys(a, self.SUBNET_KEYS, ["subnet"])
            if not subnets and node["kind"] in ("rds_instance", "rds_cluster"):
                for group in self.link(res, _get(a, "db_subnet_group_name", "DBSubnetGroupName"), ["db_subnet_group"]):
                    gres = self.resources.get(group)
                    if gres:
                        subnets = self.scan_keys(self.attrs(gres), self.SUBNET_KEYS, ["subnet"])
            vpcs = self.scan_keys(a, self.VPC_KEYS, ["vpc"]) if node["kind"] != "security_group_rule" else []
            if not vpcs and node["kind"] == "security_group":
                vpcs = self.link(res, a.get("vpc_id") or a.get("VpcId"), ["vpc"])
            node["subnets"] = subnets
            node["vpc"] = vpcs[0] if vpcs else (self.nodes[subnets[0]]["vpc"] if subnets else None)

        # A launch template inherits the subnets of the ASG that launches it.
        for asg in self.nodes_of_kind("autoscaling_group"):
            res = self.resources.get(asg["id"])
            if not res:
                continue
            a = self.attrs(res)
            templates = self.link(res, [a.get("launch_template"), a.get("LaunchTemplate"), a.get("mixed_instances_policy"), a.get("MixedInstancesPolicy")], ["launch_template"])
            configs = self.link(res, [a.get("launch_configuration"), a.get("LaunchConfigurationName")], ["launch_configuration"])
            for t in templates + configs:
                self.add_edge(asg["id"], t, "launches", label="launches")
                tnode = self.nodes[t]
                if not tnode["subnets"]:
                    tnode["subnets"] = list(asg["subnets"])
                if not tnode["vpc"]:
                    tnode["vpc"] = asg["vpc"]
        # Resources protected by a security group inherit its VPC when they have none.
        for nid, node in self.nodes.items():
            if node["vpc"] is None and node["flags"].get("security_groups"):
                for sg in node["flags"]["security_groups"]:
                    if self.nodes[sg]["vpc"]:
                        node["vpc"] = self.nodes[sg]["vpc"]
                        break

    # -- public flags ---------------------------------------------------------

    def _public_flags(self) -> None:
        eip_targets: Set[str] = set()
        for eip in self.nodes_of_kind("elastic_ip", "eip_association"):
            res = self.resources.get(eip["id"])
            if res:
                a = self.attrs(res)
                eip_targets.update(self.resolve([a.get("instance"), a.get("instance_id"), a.get("InstanceId")], ["instance"]))

        for nid, node in self.nodes.items():
            res = self.resources.get(nid)
            if not res:
                continue
            a = self.attrs(res)
            f = node["flags"]
            k = node["kind"]
            if k == "load_balancer":
                if node["type"] in ("aws_lb", "aws_alb", "aws_elb"):
                    internal = _truthy(a.get("internal"))
                    f["public"] = not internal if internal is not None else True
                else:
                    scheme = str(a.get("Scheme") or "internet-facing").lower()
                    f["public"] = scheme != "internal"
                f["access_logging"] = self._lb_access_logging(a)
                f["deletion_protection"] = _truthy(a.get("enable_deletion_protection")) or self._lb_attr(a, "deletion_protection.enabled") or False
                f["drop_invalid_headers"] = _truthy(a.get("drop_invalid_header_fields")) or self._lb_attr(a, "routing.http.drop_invalid_header_fields.enabled") or False
                f["waf"] = False
                f["http_listener"] = False
            elif k in ("rds_instance", "rds_cluster", "redshift_cluster"):
                f["public"] = _truthy(_get(a, "publicly_accessible", "PubliclyAccessible")) or False
            elif k in ("instance", "launch_template", "launch_configuration"):
                data = a.get("LaunchTemplateData") if isinstance(a.get("LaunchTemplateData"), dict) else a
                public_ip = _truthy(_get(data, "associate_public_ip_address", "AssociatePublicIpAddress"))
                for ni in _blocks(_get(data, "network_interfaces", "NetworkInterfaces")):
                    v = _truthy(_get(ni, "associate_public_ip_address", "AssociatePublicIpAddress"))
                    if v is not None:
                        public_ip = public_ip or v
                in_public_subnet = any(self.nodes[s]["flags"].get("public_ip_on_launch") for s in node["subnets"])
                f["public_ip"] = bool(public_ip) or nid in eip_targets or (public_ip is None and in_public_subnet)
                f["public"] = f["public_ip"]
                f["public_ip_reason"] = (
                    "associate_public_ip_address" if public_ip else "elastic ip" if nid in eip_targets else "subnet assigns public IPs" if (public_ip is None and in_public_subnet) else None
                )
            elif k == "api_gateway":
                types = []
                ec = _get(a, "endpoint_configuration", "EndpointConfiguration")
                for block in _blocks(ec):
                    types += [str(t).upper() for t in _as_list(_get(block, "types", "Types"))]
                f["public"] = "PRIVATE" not in types
                f["endpoint_types"] = types or ["EDGE"]
                f["waf"] = False
                f["access_logging"] = None
                f["unauthenticated_methods"] = []
            elif k == "cloudfront_distribution":
                f["public"] = True
                cfg = a.get("DistributionConfig") if isinstance(a.get("DistributionConfig"), dict) else a
                dcb = _blocks(_get(cfg, "default_cache_behavior", "DefaultCacheBehavior"))
                vpp = str(_get(dcb[0], "viewer_protocol_policy", "ViewerProtocolPolicy", default="")).lower() if dcb else ""
                f["http_allowed"] = vpp == "allow-all"
                f["waf"] = bool(_get(cfg, "web_acl_id", "WebACLId"))
                f["logging"] = bool(_get(cfg, "logging_config", "Logging"))
            elif k == "ecs_service":
                nc = _blocks(_get(a, "network_configuration", "NetworkConfiguration"))
                public = False
                for block in nc:
                    inner = block.get("AwsvpcConfiguration") if isinstance(block.get("AwsvpcConfiguration"), dict) else block
                    v = _get(inner, "assign_public_ip", "AssignPublicIp")
                    public = public or (_truthy(v) or False) or (isinstance(v, str) and v.upper() == "ENABLED")
                f["public"] = public
            elif k == "eks_cluster":
                vc = _blocks(_get(a, "vpc_config", "ResourcesVpcConfig"))
                public = True
                cidrs: List[str] = []
                for block in vc:
                    v = _truthy(_get(block, "endpoint_public_access", "EndpointPublicAccess"))
                    if v is not None:
                        public = v
                    cidrs += [str(c) for c in _as_list(_get(block, "public_access_cidrs", "PublicAccessCidrs"))]
                f["public"] = public and (not cidrs or any(_is_open_cidr(c) for c in cidrs))
            elif k == "s3_bucket":
                f["public"] = False  # refined in _data_flags
            elif k == "lambda_function":
                f["public"] = False  # refined via URL / permission
            else:
                f.setdefault("public", False)

        # Lambda URLs and permissions.
        for url in self.nodes_of_kind("lambda_url"):
            res = self.resources.get(url["id"])
            if not res:
                continue
            a = self.attrs(res)
            auth = str(_get(a, "authorization_type", "AuthType", default="NONE")).upper()
            url["flags"]["auth"] = auth
            url["flags"]["public"] = auth == "NONE"
            for fn in self.link(res, _get(a, "function_name", "TargetFunctionArn"), ["lambda_function"]):
                self.add_edge(url["id"], fn, "invoke", label="function url")
                if auth == "NONE":
                    self.nodes[fn]["flags"]["public"] = True
                    self.nodes[fn]["flags"]["public_url"] = url["id"]
                    self.add_edge(INTERNET, url["id"], "network", label="https/443 (no auth)")
        for perm in self.nodes_of_kind("lambda_permission"):
            res = self.resources.get(perm["id"])
            if not res:
                continue
            a = self.attrs(res)
            principal = str(_get(a, "principal", "Principal", default=""))
            fns = self.link(res, _get(a, "function_name", "FunctionName"), ["lambda_function"])
            source = _get(a, "source_arn", "SourceArn")
            if principal == "*" and not source:
                for fn in fns:
                    self.nodes[fn]["flags"]["public"] = True
                    self.nodes[fn]["flags"]["public_permission"] = perm["id"]
                    self.add_edge(INTERNET, fn, "invoke", label="lambda:InvokeFunction (principal *)", via=perm["id"])
            if principal.startswith("apigateway"):
                apis = self.resolve(source, ["api_gateway"]) or self.refs_of(res, ["api_gateway"])
                for api in apis:
                    for fn in fns:
                        self.add_edge(api, fn, "invoke", label="invoke", via=perm["id"])

    @staticmethod
    def _lb_attr(a: Dict[str, Any], key: str) -> Optional[bool]:
        for attr in _blocks(a.get("LoadBalancerAttributes")):
            if attr.get("Key") == key:
                return _truthy(attr.get("Value"))
        return None

    def _lb_access_logging(self, a: Dict[str, Any]) -> bool:
        for block in _blocks(a.get("access_logs")):
            if _truthy(block.get("enabled")) is not False and block.get("bucket"):
                return True
        if self._lb_attr(a, "access_logs.s3.enabled"):
            return True
        return False

    # -- forwarding: LB -> listener -> target group -> target; API -> Lambda ---

    def _forwarding(self) -> None:
        for listener in self.nodes_of_kind("listener"):
            res = self.resources.get(listener["id"])
            if not res:
                continue
            a = self.attrs(res)
            proto = str(_get(a, "protocol", "Protocol", default="")).upper()
            listener["flags"]["protocol"] = proto
            listener["flags"]["port"] = _get(a, "port", "Port")
            actions = _blocks(_get(a, "default_action", "DefaultActions"))
            redirect = any(str(_get(act, "type", "Type", default="")).lower() == "redirect" for act in actions)
            listener["flags"]["redirect"] = redirect
            for lb in self.link(res, _get(a, "load_balancer_arn", "LoadBalancerArn"), ["load_balancer"]):
                self.add_edge(lb, listener["id"], "forward", label="%s/%s" % (proto.lower() or "tcp", listener["flags"]["port"]))
                if proto == "HTTP" and not redirect:
                    self.nodes[lb]["flags"]["http_listener"] = True
                    self.nodes[lb]["flags"].setdefault("http_listeners", []).append(listener["id"])
            for tg in self.resolve(actions, ["target_group"]):
                self.add_edge(listener["id"], tg, "forward", label="forward")
        for rule in self.nodes_of_kind("listener_rule"):
            res = self.resources.get(rule["id"])
            if not res:
                continue
            a = self.attrs(res)
            for listener in self.link(res, _get(a, "listener_arn", "ListenerArn"), ["listener"]):
                for tg in self.resolve(_get(a, "action", "Actions"), ["target_group"]):
                    self.add_edge(listener, tg, "forward", label="forward", via=rule["id"])
        for asg in self.nodes_of_kind("autoscaling_group"):
            res = self.resources.get(asg["id"])
            if not res:
                continue
            a = self.attrs(res)
            for tg in self.link(res, _get(a, "target_group_arns", "TargetGroupARNs"), ["target_group"]):
                self.add_edge(tg, asg["id"], "forward", label="targets")
        for att in self.nodes_of_kind("target_group_attachment"):
            res = self.resources.get(att["id"])
            if not res:
                continue
            a = self.attrs(res)
            for tg in self.link(res, a.get("target_group_arn"), ["target_group"]):
                for target in self.resolve(a.get("target_id")) or self.refs_of(res, ["instance", "lambda_function", "load_balancer"]):
                    if target != tg:
                        self.add_edge(tg, target, "forward", label="targets", via=att["id"])
        for svc in self.nodes_of_kind("ecs_service"):
            res = self.resources.get(svc["id"])
            if not res:
                continue
            a = self.attrs(res)
            for tg in self.resolve(_get(a, "load_balancer", "LoadBalancers"), ["target_group"]):
                self.add_edge(tg, svc["id"], "forward", label="targets")
            for td in self.link(res, _get(a, "task_definition", "TaskDefinition"), ["ecs_task_definition"]):
                self.add_edge(svc["id"], td, "runs", label="runs")
        # API Gateway wiring.
        for integ in self.nodes_of_kind("api_integration"):
            res = self.resources.get(integ["id"])
            if not res:
                continue
            a = self.attrs(res)
            apis = self.link(res, _get(a, "rest_api_id", "api_id", "ApiId"), ["api_gateway"])
            fns = self.resolve(_get(a, "uri", "integration_uri", "IntegrationUri"), ["lambda_function"]) or self.refs_of(res, ["lambda_function"])
            for api in apis:
                self.add_edge(api, integ["id"], "forward", label="route")
            for fn in fns:
                self.add_edge(integ["id"], fn, "invoke", label="invoke")
        for method in self.nodes_of_kind("api_method", "api_route"):
            res = self.resources.get(method["id"])
            if not res:
                continue
            a = self.attrs(res)
            auth = str(_get(a, "authorization", "authorization_type", "AuthorizationType", default="NONE")).upper()
            http = str(_get(a, "http_method", "HttpMethod", "route_key", "RouteKey", default="")).upper()
            method["flags"]["authorization"] = auth
            method["flags"]["http_method"] = http
            for api in self.link(res, _get(a, "rest_api_id", "api_id", "RestApiId", "ApiId"), ["api_gateway"]):
                if auth == "NONE" and "OPTIONS" not in http:
                    self.nodes[api]["flags"].setdefault("unauthenticated_methods", []).append(method["id"])
                # CloudFormation folds the integration into the method.
                integ = a.get("Integration")
                if isinstance(integ, dict):
                    for fn in self.resolve(integ.get("Uri"), ["lambda_function"]):
                        self.add_edge(api, fn, "invoke", label="invoke", via=method["id"])
        for stage in self.nodes_of_kind("api_stage"):
            res = self.resources.get(stage["id"])
            if not res:
                continue
            a = self.attrs(res)
            logging = bool(_get(a, "access_log_settings", "AccessLogSettings", "AccessLogSetting"))
            stage["flags"]["access_logging"] = logging
            stage["flags"]["waf"] = False
            for api in self.link(res, _get(a, "rest_api_id", "api_id", "RestApiId", "ApiId"), ["api_gateway"]):
                self.add_edge(api, stage["id"], "deploys", label="stage")
                stage["flags"]["api"] = api
                node = self.nodes[api]
                node["flags"]["access_logging"] = bool(node["flags"].get("access_logging")) or logging
                node["flags"].setdefault("stages", []).append(stage["id"])
        for api in self.nodes_of_kind("api_gateway"):
            if api["flags"].get("access_logging") is None:
                api["flags"]["access_logging"] = False
        # WAF associations.
        for assoc in self.nodes_of_kind("waf_association"):
            res = self.resources.get(assoc["id"])
            if not res:
                continue
            a = self.attrs(res)
            for target in self.link(res, _get(a, "resource_arn", "ResourceArn"), ["load_balancer", "api_stage", "api_gateway"]):
                self.nodes[target]["flags"]["waf"] = True
                api = self.nodes[target]["flags"].get("api")
                if api:
                    self.nodes[api]["flags"]["waf"] = True
        for cf in self.nodes_of_kind("cloudfront_distribution"):
            res = self.resources.get(cf["id"])
            if not res:
                continue
            a = self.attrs(res)
            cfg = a.get("DistributionConfig") if isinstance(a.get("DistributionConfig"), dict) else a
            for origin in self.resolve(_get(cfg, "origin", "Origins"), ["s3_bucket", "load_balancer", "api_gateway", "lambda_url"]):
                self.add_edge(cf["id"], origin, "forward", label="origin")
        for mt in self.nodes_of_kind("efs_mount_target"):
            res = self.resources.get(mt["id"])
            if not res:
                continue
            a = self.attrs(res)
            for fs in self.link(res, _get(a, "file_system_id", "FileSystemId"), ["efs_file_system"]):
                self.add_edge(mt["id"], fs, "serves", label="nfs/2049")

    # -- identity -------------------------------------------------------------

    def _principal_node(self, ptype: str, value: str) -> str:
        value = str(value)
        if value == "*" or (ptype == "AWS" and value == "*"):
            nid = ANY_PRINCIPAL
            self._synthetic(nid, "principal", "internet", "Anyone (*)", public=True, principalType="*")
            return nid
        nid = "principal:%s:%s" % (ptype.lower(), _safe_name(value, 120))
        self._synthetic(nid, "principal", "principal", _safe_name(value, 80), public=False, principalType=ptype)
        return nid

    def _trust(self, role: Dict[str, Any], res: Dict[str, Any]) -> None:
        a = self.attrs(res)
        raw = _get(a, "assume_role_policy", "AssumeRolePolicyDocument")
        doc = _parse_json_doc(raw)
        f = role["flags"]
        f.update({"trust_wildcard": False, "trust_external_account": [], "trust_federated": [], "trust_services": [], "trust_unknown": False, "trust_conditioned": True})
        if doc is None:
            f["trust_unknown"] = True
            return
        any_unconditioned = False
        for stmt in _statements(doc):
            if str(stmt.get("Effect", "Allow")).lower() != "allow":
                continue
            conditioned = bool(stmt.get("Condition"))
            principal = stmt.get("Principal")
            entries: List[Tuple[str, str]] = []
            if principal == "*" or principal == {"AWS": "*"}:
                entries.append(("AWS", "*"))
            elif isinstance(principal, dict):
                for ptype, vals in principal.items():
                    for v in _as_list(vals):
                        entries.append((str(ptype), str(v)))
            for ptype, value in entries:
                nid = self._principal_node(ptype, value)
                self.add_edge(nid, role["id"], "trust", label="sts:AssumeRole" + (" (conditioned)" if conditioned else ""), flags={"conditioned": conditioned})
                if value == "*":
                    f["trust_wildcard"] = True
                    if not conditioned:
                        any_unconditioned = True
                elif ptype == "Service":
                    f["trust_services"].append(value)
                elif ptype == "Federated":
                    f["trust_federated"].append(value)
                    if not conditioned:
                        any_unconditioned = True
                elif ptype == "AWS":
                    # Another account or a foreign ARN. We cannot know our own
                    # account id from IaC, so every literal is flagged for review.
                    if _ACCOUNT_RE.match(value) or (value.startswith("arn:") and "${" not in value):
                        f["trust_external_account"].append(value)
                        if not conditioned:
                            any_unconditioned = True
        f["trust_conditioned"] = not any_unconditioned

    def _policy_flags(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        flags = {"wildcard_actions": False, "service_wildcard_actions": [], "wildcard_resource": False, "wildcard_resource_actions": [], "admin": False, "privesc_actions": [], "statements": 0}
        for stmt in _statements(doc):
            if str(stmt.get("Effect", "Allow")).lower() != "allow":
                continue
            flags["statements"] += 1
            actions = [str(x) for x in _as_list(stmt.get("Action"))]
            resources = _as_list(stmt.get("Resource"))
            # A Condition scopes the statement; "*" with a namespace or tag
            # condition is not the same exposure as a bare "*".
            res_wild = any(r == "*" for r in resources if isinstance(r, str)) and not stmt.get("Condition")
            for act in actions:
                low = act.lower()
                if act == "*":
                    flags["wildcard_actions"] = True
                    if res_wild:
                        flags["admin"] = True
                elif low.endswith(":*"):
                    if act not in flags["service_wildcard_actions"]:
                        flags["service_wildcard_actions"].append(act)
                if low in PRIVESC_ACTIONS or (low.endswith(":*") and low.split(":")[0] in ("iam", "sts")):
                    if act not in flags["privesc_actions"]:
                        flags["privesc_actions"].append(act)
            if res_wild and actions:
                flags["wildcard_resource"] = True
                for act in actions:
                    if act not in flags["wildcard_resource_actions"]:
                        flags["wildcard_resource_actions"].append(act)
        return flags

    def _grant(self, principal: str, doc: Dict[str, Any], via: List[str]) -> None:
        """Permission edges principal -> resource for one policy document."""
        for stmt in _statements(doc):
            if str(stmt.get("Effect", "Allow")).lower() != "allow":
                continue
            actions = [str(x) for x in _as_list(stmt.get("Action"))]
            if not actions:
                continue
            wildcard = any(a == "*" for a in actions)
            svc_wild = [a for a in actions if a.lower().endswith(":*")]
            privesc = [a for a in actions if a.lower() in PRIVESC_ACTIONS]
            flags = {"wildcardActions": wildcard, "serviceWildcardActions": svc_wild, "privescActions": privesc, "conditioned": bool(stmt.get("Condition"))}
            targets: List[str] = []
            any_resource = False
            externals: List[str] = []
            for r in _as_list(stmt.get("Resource")):
                if isinstance(r, str) and r.strip() == "*":
                    any_resource = True
                    continue
                found = self.resolve(r)
                if found:
                    targets += [t for t in found if t not in targets]
                elif isinstance(r, str) and r.startswith("arn:") and "${" not in r:
                    externals.append(r)
            label = ", ".join(actions[:3]) + (" +%d" % (len(actions) - 3) if len(actions) > 3 else "")
            for t in targets:
                self.add_edge(principal, t, "permission", label=label, actions=actions, via=via, flags=flags)
            for arn in externals[:10]:
                nid = "ext:%s" % _safe_name(arn, 160)
                self._synthetic(nid, "external_resource", "account", _safe_name(arn.split(":")[-1] or arn, 60), public=False, arn=arn)
                self.add_edge(principal, nid, "permission", label=label, actions=actions, via=via, flags=flags)
            if any_resource:
                relevant = wildcard or any(a.split(":")[0].lower() in DATA_SERVICES for a in actions)
                if relevant:
                    self._synthetic(ANY_RESOURCE, "any_resource", "account", "Any resource (*)", public=False)
                    self.add_edge(principal, ANY_RESOURCE, "permission", label=label, actions=actions, via=via, flags=dict(flags, wildcardResource=True))

    def _identity(self) -> None:
        for role in self.nodes_of_kind("iam_role"):
            res = self.resources.get(role["id"])
            if not res:
                continue
            self._trust(role, res)
            a = self.attrs(res)
            role["flags"].update({"wildcard_actions": False, "service_wildcard_actions": [], "wildcard_resource": False, "admin": False, "privesc_actions": [], "managed_policies": [], "policy_unknown": False})
            # Inline policies declared on the role itself (CloudFormation, and
            # Terraform's deprecated inline_policy block).
            for block in _blocks(_get(a, "Policies", "inline_policy")):
                doc = _parse_json_doc(_get(block, "PolicyDocument", "policy"))
                if doc:
                    self._apply_policy(role["id"], doc, [role["id"]])
                else:
                    role["flags"]["policy_unknown"] = True
            for arn in _as_list(_get(a, "ManagedPolicyArns", "managed_policy_arns")):
                self._managed_policy(role["id"], arn, [role["id"]])

        for policy in self.nodes_of_kind("iam_inline_policy", "iam_policy"):
            res = self.resources.get(policy["id"])
            if not res:
                continue
            a = self.attrs(res)
            doc = _parse_json_doc(_get(a, "policy", "PolicyDocument"))
            if doc is None:
                policy["flags"]["policy_unknown"] = True
                self.degradations.append(
                    "%s: policy document is not a literal JSON object (a data source or file). Its permissions are NOT in the graph." % policy["id"]
                )
                continue
            policy["flags"].update(self._policy_flags(doc))
            policy["flags"]["document"] = doc
            principals: List[str] = []
            if policy["kind"] == "iam_inline_policy":
                principals = self.link(res, [a.get("role"), a.get("user"), a.get("group"), a.get("Roles"), a.get("Users"), a.get("Groups")], ["iam_role", "iam_user", "iam_group"])
            else:
                principals = self.resolve([a.get("Roles"), a.get("Users"), a.get("Groups")], ["iam_role", "iam_user", "iam_group"])
            for p in principals:
                self.add_edge(policy["id"], p, "grants", label="grants")
                self._apply_policy(p, doc, [policy["id"]])
        for att in self.nodes_of_kind("iam_policy_attachment"):
            res = self.resources.get(att["id"])
            if not res:
                continue
            a = self.attrs(res)
            principals = self.link(res, [a.get("role"), a.get("roles"), a.get("user"), a.get("users"), a.get("group"), a.get("groups")], ["iam_role", "iam_user", "iam_group"])
            policies = self.link(res, a.get("policy_arn"), ["iam_policy"], fallback=False)
            if not policies:
                policies = self.refs_of(res, ["iam_policy"])
            for p in principals:
                for pol in policies:
                    self.add_edge(pol, p, "grants", label="grants", via=att["id"])
                    doc = self.nodes[pol]["flags"].get("document")
                    if doc:
                        self._apply_policy(p, doc, [pol, att["id"]])
                arn = a.get("policy_arn")
                if not policies and isinstance(arn, str) and arn.startswith("arn:"):
                    self._managed_policy(p, arn, [att["id"]])
        # Compute -> instance profile -> role.
        for profile in self.nodes_of_kind("instance_profile"):
            res = self.resources.get(profile["id"])
            if not res:
                continue
            a = self.attrs(res)
            for role in self.link(res, [a.get("role"), a.get("Roles")], ["iam_role"]):
                self.add_edge(profile["id"], role, "assumes", label="role")
        for node in list(self.nodes.values()):
            if node["kind"] not in COMPUTE_KINDS and node["kind"] not in ("instance", "ecs_service"):
                continue
            res = self.resources.get(node["id"])
            if not res:
                continue
            a = self.attrs(res)
            data = a.get("LaunchTemplateData") if isinstance(a.get("LaunchTemplateData"), dict) else a
            profiles = self.link(res, _get(data, "iam_instance_profile", "IamInstanceProfile"), ["instance_profile"], fallback=node["kind"] in ("instance", "launch_template", "launch_configuration"))
            for p in profiles:
                self.add_edge(node["id"], p, "assumes", label="instance profile")
            roles = self.resolve([_get(data, "role", "Role"), _get(a, "task_role_arn", "TaskRoleArn"), _get(a, "execution_role_arn", "ExecutionRoleArn"), _get(a, "role_arn", "RoleArn")], ["iam_role"])
            if not roles and node["kind"] in ("lambda_function", "ecs_task_definition", "eks_cluster"):
                roles = self.refs_of(res, ["iam_role"])
            for r in roles:
                self.add_edge(node["id"], r, "assumes", label="execution role")

    def _apply_policy(self, principal: str, doc: Dict[str, Any], via: List[str]) -> None:
        pf = self._policy_flags(doc)
        node = self.nodes.get(principal)
        if node is not None:
            f = node["flags"]
            f["wildcard_actions"] = f.get("wildcard_actions") or pf["wildcard_actions"]
            f["wildcard_resource"] = f.get("wildcard_resource") or pf["wildcard_resource"]
            f["admin"] = f.get("admin") or pf["admin"]
            f.setdefault("service_wildcard_actions", [])
            f.setdefault("privesc_actions", [])
            for x in pf["service_wildcard_actions"]:
                if x not in f["service_wildcard_actions"]:
                    f["service_wildcard_actions"].append(x)
            for x in pf["privesc_actions"]:
                if x not in f["privesc_actions"]:
                    f["privesc_actions"].append(x)
        self._grant(principal, doc, via)

    def _managed_policy(self, principal: str, arn: Any, via: List[str]) -> None:
        if not isinstance(arn, str) or not arn.startswith("arn:"):
            for pol in self.resolve(arn, ["iam_policy"]):
                self.add_edge(pol, principal, "grants", label="grants", via=via)
                doc = self.nodes[pol]["flags"].get("document")
                if doc:
                    self._apply_policy(principal, doc, via + [pol])
            return
        name = arn.split("/")[-1]
        nid = "policy:%s" % _safe_name(arn, 160)
        self._synthetic(nid, "managed_policy", "account", _safe_name(name), public=False, arn=arn)
        self.add_edge(nid, principal, "grants", label="managed policy", via=via)
        node = self.nodes.get(principal)
        if node is not None:
            node["flags"].setdefault("managed_policies", []).append(name)
            if name in ("AdministratorAccess", "PowerUserAccess"):
                node["flags"]["admin"] = True
                node["flags"]["wildcard_actions"] = True
                node["flags"]["wildcard_resource"] = True
                self._synthetic(ANY_RESOURCE, "any_resource", "account", "Any resource (*)", public=False)
                self.add_edge(principal, ANY_RESOURCE, "permission", label="* (via %s)" % name, actions=["*"], via=via, flags={"wildcardActions": True, "wildcardResource": True})

    # -- data flags -----------------------------------------------------------

    def _data_flags(self) -> None:
        # Side resources that modify an S3 bucket (Terraform's split resources).
        bucket_side: Dict[str, Dict[str, Any]] = {}
        for side in self.nodes_of_kind("s3_public_access_block", "s3_bucket_policy", "s3_encryption", "s3_versioning", "s3_logging", "s3_acl"):
            res = self.resources.get(side["id"])
            if not res:
                continue
            a = self.attrs(res)
            for bucket in self.link(res, _get(a, "bucket", "Bucket"), ["s3_bucket"]):
                bucket_side.setdefault(bucket, {})[side["kind"]] = a
        flow_log_vpcs: Set[str] = set()
        for fl in self.nodes_of_kind("flow_log"):
            res = self.resources.get(fl["id"])
            if res:
                a = self.attrs(res)
                flow_log_vpcs.update(self.link(res, [a.get("vpc_id"), a.get("ResourceId")], ["vpc"]))
        rotated: Set[str] = set()
        for rot in self.nodes_of_kind("secret_rotation"):
            res = self.resources.get(rot["id"])
            if res:
                rotated.update(self.link(res, _get(self.attrs(res), "secret_id", "SecretId"), ["secret"]))

        for nid, node in self.nodes.items():
            res = self.resources.get(nid)
            if not res:
                continue
            a = self.attrs(res)
            f = node["flags"]
            k = node["kind"]
            if k == "vpc":
                f["flow_logs"] = nid in flow_log_vpcs
            elif k == "rds_instance":
                f["encrypted"] = _truthy(_get(a, "storage_encrypted", "StorageEncrypted")) or False
                f["deletion_protection"] = _truthy(_get(a, "deletion_protection", "DeletionProtection")) or False
                f["iam_auth"] = _truthy(_get(a, "iam_database_authentication_enabled", "EnableIAMDatabaseAuthentication")) or False
                f["logging"] = bool(_as_list(_get(a, "enabled_cloudwatch_logs_exports", "EnableCloudwatchLogsExports")))
                f["multi_az"] = _truthy(_get(a, "multi_az", "MultiAZ")) or False
                f["engine"] = str(_get(a, "engine", "Engine", default="")).lower()
            elif k == "rds_cluster":
                f["encrypted"] = _truthy(_get(a, "storage_encrypted", "StorageEncrypted")) or False
                f["deletion_protection"] = _truthy(_get(a, "deletion_protection", "DeletionProtection")) or False
                f["iam_auth"] = _truthy(_get(a, "iam_database_authentication_enabled", "EnableIAMDatabaseAuthentication")) or False
                f["logging"] = bool(_as_list(_get(a, "enabled_cloudwatch_logs_exports", "EnableCloudwatchLogsExports")))
            elif k == "redshift_cluster":
                f["encrypted"] = _truthy(_get(a, "encrypted", "Encrypted")) or False
                f["logging"] = bool(_get(a, "logging", "LoggingProperties"))
            elif k == "dynamodb_table":
                sse = _blocks(_get(a, "server_side_encryption", "SSESpecification"))
                enabled = any(_truthy(_get(b, "enabled", "SSEEnabled")) for b in sse)
                cmk = any(_get(b, "kms_key_arn", "KMSMasterKeyId") for b in sse)
                f["encrypted_cmk"] = bool(enabled and cmk)
                pitr = _blocks(_get(a, "point_in_time_recovery", "PointInTimeRecoverySpecification"))
                f["pitr"] = any(_truthy(_get(b, "enabled", "PointInTimeRecoveryEnabled")) for b in pitr)
            elif k == "s3_bucket":
                side = bucket_side.get(nid, {})
                acl = str(_get(a, "acl", "AccessControl", default="") or side.get("s3_acl", {}).get("acl") or "").lower().replace("-", "")
                public_acl = acl in ("publicread", "publicreadwrite", "authenticatedread")
                policy_doc = _parse_json_doc(_get(a, "policy", "PolicyDocument")) or _parse_json_doc(_get(side.get("s3_bucket_policy", {}), "policy", "PolicyDocument"))
                public_policy = False
                if policy_doc:
                    for stmt in _statements(policy_doc):
                        p = stmt.get("Principal")
                        if str(stmt.get("Effect", "")).lower() == "allow" and (p == "*" or p == {"AWS": "*"}) and not stmt.get("Condition"):
                            public_policy = True
                block = _get(a, "PublicAccessBlockConfiguration") or side.get("s3_public_access_block")
                blocked = False
                if isinstance(block, dict):
                    blocked = all(
                        _truthy(_get(block, tf, cfn)) for tf, cfn in (
                            ("block_public_acls", "BlockPublicAcls"),
                            ("block_public_policy", "BlockPublicPolicy"),
                            ("ignore_public_acls", "IgnorePublicAcls"),
                            ("restrict_public_buckets", "RestrictPublicBuckets"),
                        )
                    )
                f["public_access_block"] = blocked
                f["public_acl"] = public_acl
                f["public_policy"] = public_policy
                f["public"] = (public_acl or public_policy) and not blocked
                if f["public"]:
                    self.add_edge(INTERNET, nid, "network", label="public %s" % ("policy" if public_policy else "ACL"))
                f["encrypted"] = bool(_get(a, "server_side_encryption_configuration", "BucketEncryption")) or "s3_encryption" in side
                vers = _blocks(_get(a, "versioning", "VersioningConfiguration"))
                f["versioning"] = any(_truthy(_get(b, "enabled")) or str(b.get("Status", "")).lower() == "enabled" for b in vers) or any(
                    str(_get(c, "status", default="")).lower() == "enabled" for c in _blocks(side.get("s3_versioning", {}).get("versioning_configuration"))
                )
                f["logging"] = bool(_get(a, "logging", "LoggingConfiguration")) or "s3_logging" in side
            elif k == "efs_file_system":
                f["encrypted"] = _truthy(_get(a, "encrypted", "Encrypted")) or False
            elif k == "elasticache_cluster":
                f["at_rest_encryption"] = _truthy(_get(a, "at_rest_encryption_enabled", "AtRestEncryptionEnabled"))
                f["transit_encryption"] = _truthy(_get(a, "transit_encryption_enabled", "TransitEncryptionEnabled")) or False
            elif k == "secret":
                f["encrypted_cmk"] = bool(_get(a, "kms_key_id", "KmsKeyId"))
                f["rotation"] = nid in rotated
            elif k == "ssm_parameter":
                f["secure_string"] = str(_get(a, "type", "Type", default="")).lower() == "securestring"
            elif k == "kms_key":
                f["rotation"] = _truthy(_get(a, "enable_key_rotation", "EnableKeyRotation")) or False
                doc = _parse_json_doc(_get(a, "policy", "KeyPolicy"))
                f["wildcard_principal"] = False
                if doc:
                    for stmt in _statements(doc):
                        if stmt.get("Principal") in ("*", {"AWS": "*"}) and not stmt.get("Condition"):
                            f["wildcard_principal"] = True
            elif k == "ecr_repository":
                scan = _blocks(_get(a, "image_scanning_configuration", "ImageScanningConfiguration"))
                f["scan_on_push"] = any(_truthy(_get(b, "scan_on_push", "ScanOnPush")) for b in scan)
                f["tag_immutable"] = str(_get(a, "image_tag_mutability", "ImageTagMutability", default="MUTABLE")).upper() == "IMMUTABLE"
            elif k == "sqs_queue":
                f["encrypted"] = bool(_get(a, "kms_master_key_id", "KmsMasterKeyId")) or (_truthy(_get(a, "sqs_managed_sse_enabled", "SqsManagedSseEnabled")) or False)
            elif k == "sns_topic":
                f["encrypted"] = bool(_get(a, "kms_master_key_id", "KmsMasterKeyId"))
            elif k == "log_group":
                try:
                    f["retention_days"] = int(_get(a, "retention_in_days", "RetentionInDays", default=0) or 0)
                except (TypeError, ValueError):
                    f["retention_days"] = 0
                f["encrypted_cmk"] = bool(_get(a, "kms_key_id", "KmsKeyId"))
                # 0 means "never expire", which satisfies a one-year floor.
                f["retention_ok"] = f["retention_days"] == 0 or f["retention_days"] >= 365
            elif k == "db_snapshot":
                f["public"] = any(str(x).lower() == "all" for x in _as_list(a.get("shared_accounts")))
            elif k == "ami_launch_permission":
                f["public"] = str(a.get("group", "")).lower() == "all"
            elif k == "lambda_function":
                vpc = _blocks(_get(a, "vpc_config", "VpcConfig"))
                f["in_vpc"] = any(_as_list(_get(b, "subnet_ids", "SubnetIds")) for b in vpc)
                f["env_kms"] = bool(_get(a, "kms_key_arn", "KmsKeyArn"))
                env = _blocks(_get(a, "environment", "Environment"))
                variables = {}
                for b in env:
                    v = _get(b, "variables", "Variables")
                    if isinstance(v, dict):
                        variables.update({kk: vv for kk, vv in v.items() if kk != "__tfmeta"})
                f["env_var_count"] = len(variables)
                f["dlq"] = bool(_get(a, "dead_letter_config", "DeadLetterConfig"))
                tracing = _blocks(_get(a, "tracing_config", "TracingConfig"))
                f["tracing"] = any(str(_get(b, "mode", "Mode", default="")).lower() == "active" for b in tracing)
            elif k in ("instance", "launch_template", "launch_configuration"):
                data = a.get("LaunchTemplateData") if isinstance(a.get("LaunchTemplateData"), dict) else a
                mo = _blocks(_get(data, "metadata_options", "MetadataOptions"))
                tokens = [str(_get(b, "http_tokens", "HttpTokens", default="optional")) for b in mo]
                endpoint_off = any(str(_get(b, "http_endpoint", "HttpEndpoint", default="enabled")).lower() == "disabled" for b in mo)
                if any(t == REDACTED for t in tokens) and not endpoint_off:
                    # The parser redacts `http_tokens` (it matches its secret-key
                    # pattern), so required-vs-optional is not visible here.
                    f["imdsv2"] = None
                    f["imdsv2_unknown"] = True
                else:
                    f["imdsv2"] = bool(tokens) and all(t.lower() == "required" for t in tokens) or endpoint_off
                encrypted_flags: List[Optional[bool]] = []
                for bdm in _blocks(_get(data, "block_device_mappings", "BlockDeviceMappings", "ebs_block_device")):
                    ebs = _blocks(_get(bdm, "ebs", "Ebs")) or [bdm]
                    for e in ebs:
                        encrypted_flags.append(_truthy(_get(e, "encrypted", "Encrypted")))
                for rbd in _blocks(data.get("root_block_device")):
                    encrypted_flags.append(_truthy(rbd.get("encrypted")))
                known = [x for x in encrypted_flags if x is not None]
                f["ebs_encrypted"] = all(known) if known else None
                f["ebs_unencrypted_explicit"] = any(x is False for x in encrypted_flags)
                f["monitoring"] = bool(_get(data, "monitoring", "Monitoring"))
            elif k == "ecs_task_definition":
                defs = _get(a, "container_definitions", "ContainerDefinitions")
                containers: List[Dict[str, Any]] = []
                if isinstance(defs, str):
                    try:
                        parsed = json.loads(defs)
                        containers = [c for c in parsed if isinstance(c, dict)] if isinstance(parsed, list) else []
                    except json.JSONDecodeError:
                        containers = []
                else:
                    containers = _blocks(defs)
                f["privileged"] = any(_truthy(_get(c, "privileged", "Privileged")) for c in containers)
                f["container_count"] = len(containers)
                f["env_secret_names"] = []
                for c in containers:
                    for env in _blocks(_get(c, "environment", "Environment")):
                        name = str(_get(env, "name", "Name", default=""))
                        value = _get(env, "value", "Value")
                        if SECRET_KEY_RE.search(name) and not SECRET_SKIP_RE.search(name) and self._literal_secret(value):
                            f["env_secret_names"].append(name)
            elif k == "eks_cluster":
                enc = _blocks(_get(a, "encryption_config", "EncryptionConfig"))
                f["secrets_encrypted"] = bool(enc)

    # -- secrets in plain attributes -----------------------------------------

    def _literal_secret(self, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        s = value.strip()
        if len(s) < 6 or len(s) > 512:
            return False
        if _UUID_RE.match(s) or "${" in s or s.startswith(("arn:", "aws_", "var.", "local.", "data.", "module.")):
            return False
        if s.lower() in ("true", "false", "null", "none", "changeme", "example", "required", "optional", "enabled", "disabled"):
            return False
        if s.lower().startswith(("alias/", "/aws/", "arn:")):
            return False
        if s.isalpha() and len(s) < 16:
            return False  # "minutes", "required": a unit or an enum, not a credential
        return True

    def _secrets(self) -> None:
        for nid, node in self.nodes.items():
            res = self.resources.get(nid)
            if not res:
                continue
            found: List[Dict[str, str]] = []

            def walk(v: Any, path: str) -> None:
                if isinstance(v, dict):
                    if "__attribute__" in v:
                        return
                    if "Ref" in v and isinstance(v.get("Ref"), str) and len(v) == 1:
                        # A CFN parameter with a baked-in default is a secret in the template.
                        param = self.parameters.get(v["Ref"])
                        if isinstance(param, dict) and param.get("default") not in (None, ""):
                            key = path.rsplit(".", 1)[-1]
                            if (SECRET_KEY_RE.search(key) or SECRET_KEY_RE.search(v["Ref"])) and not SECRET_SKIP_RE.search(key) and self._literal_secret(str(param.get("default"))):
                                found.append({"path": path, "hint": "parameter %s has a default value" % v["Ref"]})
                        return
                    for k, item in v.items():
                        if k == "__tfmeta":
                            continue
                        child = "%s.%s" % (path, k) if path else k
                        if isinstance(item, str) and SECRET_KEY_RE.search(k) and not SECRET_SKIP_RE.search(k) and self._literal_secret(item):
                            found.append({"path": child, "hint": "literal value (redacted by the parser)" if item == REDACTED else "literal value"})
                        elif k in ("user_data", "UserData", "user_data_base64") and isinstance(item, str):
                            text = item
                            try:
                                text = base64.b64decode(item, validate=True).decode("utf-8", "ignore")
                            except Exception:  # noqa: BLE001 - not base64; scan as-is
                                pass
                            if USER_DATA_SECRET_RE.search(text):
                                found.append({"path": child, "hint": "credential assignment in user data"})
                        else:
                            walk(item, child)
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        walk(item, "%s[%d]" % (path, i))

            walk(self.attrs(res), "")
            for name in node["flags"].get("env_secret_names") or []:
                found.append({"path": "container_definitions[].environment.%s" % name, "hint": "literal value"})
            node["flags"]["plaintext_secrets"] = found

    # -- boundaries -------------------------------------------------------------

    def _boundaries(self) -> None:
        for nid, node in self.nodes.items():
            if node.get("synthetic"):
                continue
            k = node["kind"]
            if k == "vpc":
                node["boundary"] = "vpc:%s" % nid
                continue
            if k == "subnet":
                node["boundary"] = "subnet:%s:%s" % (nid, "public" if node["flags"].get("public") else "private")
                continue
            if k in ("iam_role", "iam_user", "iam_group", "iam_policy", "iam_inline_policy", "iam_policy_attachment", "instance_profile"):
                node["boundary"] = "principal"
                continue
            if node["subnets"]:
                # If any subnet is public the resource is reachable from the
                # public side; name that subnet.
                public = [s for s in node["subnets"] if self.nodes[s]["flags"].get("public")]
                chosen = sorted(public)[0] if public else sorted(node["subnets"])[0]
                node["boundary"] = "subnet:%s:%s" % (chosen, "public" if public else "private")
            elif node["vpc"]:
                node["boundary"] = "vpc:%s" % node["vpc"]
            else:
                node["boundary"] = "account"

    # -- entrypoints --------------------------------------------------------------

    def _entrypoints(self) -> None:
        for nid, node in self.nodes.items():
            f = node["flags"]
            if nid == ANY_PRINCIPAL:
                self.entrypoints.append({"id": nid, "reason": "any principal may assume a role", "via": []})
                continue
            if node.get("synthetic") or not f.get("public"):
                continue
            if node["kind"] in HUB_KINDS or node["kind"] in OBSERVER_KINDS:
                continue  # a public subnet is placement, not a front door
            if node["kind"] in SG_GOVERNED_KINDS:
                sgs = f.get("security_groups") or []
                open_rules = []
                for sg in sgs:
                    open_rules += self.nodes[sg]["flags"].get("open_ingress", [])
                if sgs and not open_rules:
                    f["public_but_closed"] = True
                    continue
                reason = "public endpoint with open security group" if sgs else "public endpoint; no security group resolved"
                self.entrypoints.append({"id": nid, "reason": reason, "via": open_rules})
                self.add_edge(INTERNET, nid, "network", label="public" if not sgs else "public (via SG)")
            else:
                via = []
                if f.get("public_url"):
                    via.append({"via": f["public_url"], "ports": "https/443"})
                if f.get("public_permission"):
                    via.append({"via": f["public_permission"], "ports": "invoke"})
                self.entrypoints.append({"id": nid, "reason": "public %s" % node["kind"].replace("_", " "), "via": via})
                self.add_edge(INTERNET, nid, "network", label="public")
            f["entrypoint"] = True

    def _report_unmapped(self) -> None:
        if self.unmapped_types:
            total = sum(self.unmapped_types.values())
            sample = ", ".join(sorted(self.unmapped_types)[:8])
            self.degradations.append(
                "%d resources across %d types have no semantic mapping (%s%s). They appear as kind 'other', carry no rules, and are never on a path."
                % (total, len(self.unmapped_types), sample, ", ..." if len(self.unmapped_types) > 8 else "")
            )
        imds_unknown = [n["id"] for n in self.nodes.values() if n["flags"].get("imdsv2_unknown")]
        if imds_unknown:
            self.degradations.append(
                "%d compute resources declare metadata_options, but the parser redacts http_tokens, so IMDSv2 enforcement is UNKNOWN for them (%s). TM-CMP-001 is not evaluated there."
                % (len(imds_unknown), ", ".join(imds_unknown[:5]))
            )
        unknown_trust = [n["id"] for n in self.nodes_of_kind("iam_role") if n["flags"].get("trust_unknown")]
        if unknown_trust:
            self.degradations.append(
                "%d IAM roles have a trust policy that is not a literal document (%s). Who may assume them is UNKNOWN; no trust edges were drawn."
                % (len(unknown_trust), ", ".join(unknown_trust[:5]))
            )

    # -- output ---------------------------------------------------------------------

    def boundaries(self) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}
        for node in self.nodes.values():
            b = node.get("boundary") or "account"
            counts[b] = counts.get(b, 0) + 1
        out = []
        for b in sorted(counts):
            parent = None
            label = b
            kind = b.split(":")[0]
            if kind == "subnet":
                _, sid, vis = b.split(":", 2)
                parent = "vpc:%s" % self.nodes[sid]["vpc"] if sid in self.nodes and self.nodes[sid]["vpc"] else "account"
                label = "%s subnet %s" % (vis, self.nodes[sid]["name"] if sid in self.nodes else sid)
            elif kind == "vpc":
                parent = "account"
                vid = b.split(":", 1)[1]
                label = "VPC %s" % (self.nodes[vid]["name"] if vid in self.nodes else vid)
            elif kind == "principal":
                parent = "account"
                label = "Identity (IAM)"
            elif kind == "internet":
                label = "Internet"
            elif kind == "account":
                label = "AWS account"
            out.append({"id": b, "kind": kind, "label": label, "parent": parent, "nodeCount": counts[b]})
        if "account" not in counts:
            out.append({"id": "account", "kind": "account", "label": "AWS account", "parent": None, "nodeCount": 0})
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "format": self.format,
            "parseTier": self.parse.get("parseTier"),
            "degraded": bool(self.parse.get("degraded")) or bool(self.degradations),
            "degradations": list(self.degradations),
            "nodes": [self.nodes[k] for k in sorted(self.nodes)],
            "edges": list(self.edges),
            "boundaries": self.boundaries(),
            "entrypoints": list(self.entrypoints),
            "budget": {"substantiveHops": MAX_PATH_SUBSTANTIVE, "maxNodes": MAX_PATH_NODES},
        }


def build_graph(parse: Dict[str, Any]) -> Dict[str, Any]:
    return SemanticGraph(parse).build()


# ---------------------------------------------------------------------------
# Attack paths: directed, bounded BFS from every entrypoint to every data node
# ---------------------------------------------------------------------------


def _index(graph: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    nodes = {n["id"]: n for n in graph["nodes"]}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for e in graph["edges"]:
        if e["kind"] in ("grants", "route", "deploys"):
            continue  # provenance and placement; never a step an attacker takes
        out.setdefault(e["source"], []).append(e)
    return nodes, out


def is_terminus(node: Dict[str, Any]) -> bool:
    return node["kind"] in DATA_KINDS or node["kind"] == "any_resource"


def path_severity(nodes: Dict[str, Dict[str, Any]], path: List[str], edges: List[Dict[str, Any]]) -> str:
    terminus = nodes[path[-1]]
    f = terminus["flags"]
    if terminus["kind"] == "any_resource":
        return "critical"
    if f.get("public") or f.get("encrypted") is False:
        return "critical"
    if any((e.get("flags") or {}).get("wildcardActions") or (e.get("flags") or {}).get("serviceWildcardActions") for e in edges):
        return "critical"
    return "high"


def find_attack_paths(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One shortest path per (entrypoint, data terminus).

    Not gated on findings: a reachable data store is a path whether or not
    Checkov has an opinion about any hop. Hubs are excluded, connector kinds
    are free, and the budget is MAX_CHAIN_DEPTH substantive hops.
    """
    nodes, out = _index(graph)
    paths: List[Dict[str, Any]] = []
    seen_pairs: Set[Tuple[str, str]] = set()
    for entry in sorted(e["id"] for e in graph.get("entrypoints", [])):
        if entry not in nodes:
            continue
        if is_terminus(nodes[entry]):
            pair = (entry, entry)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                paths.append(_describe_path(nodes, [entry], [], graph, direct=True))
        queue: List[Tuple[List[str], List[Dict[str, Any]], int]] = [([entry], [], 0)]
        while queue:
            path, edges, cost = queue.pop(0)
            node = path[-1]
            if len(path) > 1 and is_terminus(nodes[node]):
                pair = (entry, node)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    paths.append(_describe_path(nodes, path, edges, graph))
                continue
            if cost >= MAX_PATH_SUBSTANTIVE or len(path) >= MAX_PATH_NODES:
                continue
            for edge in sorted(out.get(node, []), key=lambda e: e["target"]):
                nxt = edge["target"]
                if nxt in path:
                    continue
                target = nodes.get(nxt)
                if target is None:
                    continue
                if target["kind"] in EXCLUDED_KINDS and target["kind"] != "any_resource":
                    continue
                if (target.get("type") or "") in EXCLUDED_FROM_TRAVERSAL:
                    continue
                step = 0 if target["kind"] in CONNECTOR_KINDS else 1
                queue.append((path + [nxt], edges + [edge], cost + step))
    return _drop_subsumed_chains(paths)


def _describe_path(nodes: Dict[str, Dict[str, Any]], path: List[str], edges: List[Dict[str, Any]], graph: Dict[str, Any], direct: bool = False) -> Dict[str, Any]:
    boundaries: List[str] = []
    for nid in path:
        b = nodes[nid].get("boundary") or "account"
        if not boundaries or boundaries[-1] != b:
            boundaries.append(b)
    entry = nodes[path[0]]
    terminus = nodes[path[-1]]
    entry_meta = next((e for e in graph.get("entrypoints", []) if e["id"] == path[0]), {})
    hop_edges = [
        {
            "source": e["source"],
            "target": e["target"],
            "kind": e["kind"],
            "label": e.get("label"),
            "ports": e.get("ports"),
            "actions": e.get("actions"),
            "via": e.get("via") or [],
            "flags": e.get("flags") or {},
        }
        for e in edges
    ]
    substantive = sum(1 for nid in path[1:] if nodes[nid]["kind"] not in CONNECTOR_KINDS)
    if direct:
        summary = "%s is a data store that is itself reachable from the internet." % path[0]
    else:
        summary = "%s is reachable from the internet and is wired, via %s, to %s, a data store (%s)." % (
            path[0],
            " -> ".join(path[1:-1]) or "a direct edge",
            path[-1],
            terminus["kind"].replace("_", " "),
        )
    return {
        "id": "path-%s->%s" % (path[0], path[-1]),
        "source": {"id": path[0], "kind": entry["kind"], "boundary": entry.get("boundary"), "reason": entry_meta.get("reason"), "via": entry_meta.get("via", [])},
        "target": {"id": path[-1], "kind": terminus["kind"], "boundary": terminus.get("boundary"), "flags": {k: v for k, v in terminus["flags"].items() if k in ("public", "encrypted", "encrypted_cmk", "deletion_protection", "logging")}},
        "path": list(path),
        "nodeKinds": [nodes[n]["kind"] for n in path],
        "edges": hop_edges,
        "boundariesCrossed": boundaries,
        "substantiveHops": substantive,
        "direct": direct,
        "severity": path_severity(nodes, path, edges),
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# CLI (debugging aid; threat_model.py is the real entry point)
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Build the semantic graph from parse_iac.py output.")
    ap.add_argument("parse", help="parse.json from parse_iac.py --json-only")
    ap.add_argument("--out", help="write graph JSON here (default stdout)")
    ap.add_argument("--paths", action="store_true", help="also compute attack paths")
    args = ap.parse_args(argv)
    with open(args.parse, encoding="utf-8") as fh:
        parse = json.load(fh)
    graph = build_graph(parse)
    if args.paths:
        graph["attackPaths"] = find_attack_paths(graph)
    text = json.dumps(graph, indent=2, default=str)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")
    for d in graph["degradations"]:
        print("DEGRADED: %s" % d, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
