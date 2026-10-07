#!/usr/bin/env python3
"""
IaC Parser (shared by the security-scan and diagram-generator skills).

Parses Infrastructure as Code files and extracts resource information.
Supports: Terraform, CloudFormation, Kubernetes, Docker Compose.
Accepts: local paths or GitHub repository URLs.

This module merges two forks of ``parse_iac.py``. The security-scan fork owns
the public output contract (``location`` objects, ``parseTier``, ``degraded``,
line provenance). The diagram-generator fork owns the robustness fixes
(IDG-01..IDG-22). The output here is a strict superset of both: every
security-scan field keeps its shape and meaning; the diagram fields are added.

Feature matrix
==============

feature                          | scan                        | diagram                      | merged behaviour
---------------------------------|-----------------------------|------------------------------|------------------------------------------------
``location`` object              | yes (file/startLine/endLine/| no                           | scan shape, on every resource of every format
                                 | resourceAddress/resourceType|                              |
                                 | /service)                   |                              |
``parseTier`` / ``degraded`` /   | yes                         | no                           | scan (every tier reports them)
``degradationReason`` /          |                             |                              |
``lineProvenance`` /             |                             |                              |
``resources_with_line_provenance``|                            |                              |
Terraform tier order             | tfparse -> hcl2 -> regex,   | tfparse only with .terraform/| scan: tfparse unconditional; FORCE_TIER env kept
                                 | tfparse unconditional       |                              |
tfparse count/for_each           | one resource per instance   | collapsed, ``instances`` n   | scan: one per instance; additive ``instances``
                                 | (address keeps the index)   |                              | (siblings sharing the base address)
tfparse data sources             | ``data_sources`` with       | ``data_sources`` with        | both: address + location + full_name + module
                                 | address/location            | full_name/module/file        | + file
tfparse edges                    | regex over attribute values | ``__tfmeta.references``      | union, resolved to known resources/data sources
                                 |                             |                              | (keyed by the scan address)
``references`` (raw __tfmeta)    | yes                         | no                           | scan (kept raw)
hcl2 8.x shapes                  | tolerated list/dict only    | ``hcl2_clean`` strips quotes,| diagram, plus ``hcl2_unwrap_bc`` for the
                                 |                             | ``__is_block__``/comments    | bc-python-hcl2 fork Checkov installs (every
                                 |                             |                              | value list-wrapped, ``__start_line__`` tags)
hcl2/regex data sources          | no                          | yes, ``data.`` references    | diagram, plus location (no lines)
hcl2/regex dependencies          | known-resource regex /      | real references in bodies,   | diagram (``dependencies_source: "references"``)
                                 | type-pair guessing          | comments stripped            |
hcl2 all-files-failed            | empty result                | error -> regex tier          | diagram
CloudFormation decode            | cfn_yaml/cfn_json + marks   | ``decode()`` + ``plain_data``| scan marks for lines; diagram ``plain_data`` for
                                 |                             |                              | the JSON payload
CloudFormation directory         | merged ``templates`` +      | merged ``files`` + per-item  | both keys; ``file`` on every CFN resource
                                 | relative ``location.file``  | ``file``                     |
CloudFormation short tags (yaml  | ``{"GetAtt": "A.B"}``       | ``{"Fn::GetAtt": ["A","B"]}``| diagram
tier)                            |                             |                              |
CloudFormation yaml tier on a    | zero resources              | error                        | diagram
non-template                     |                             |                              |
Parameter ``NoEcho`` / defaults  | raw                         | redacted                     | diagram
Kubernetes line provenance       | ruamel per document         | no                           | scan, extended to items inside ``kind: List``
Kubernetes ``kind: List``        | not expanded                | expanded                     | diagram
Kubernetes non-objects           | kind ``Unknown``            | skipped (+ Kustomization),   | diagram; ``skipped_documents``/``unreadable_files``
                                 |                             | error when nothing is left   | added
Kubernetes REFERENCE edges       | Ingress, RBAC               | + envFrom, secretKeyRef,     | diagram
                                 |                             | configMapKeyRef,             |
                                 |                             | serviceAccountName,          |
                                 |                             | initContainers, ReplicaSet   |
Kubernetes ``dependencies``      | duplicates kept             | deduplicated                 | diagram
Compose input                    | one file                    | file or directory, merged    | both (directory merge keeps provenance fields)
Secret redaction                 | no                          | ``redact_secrets`` by key    | diagram, applied to attributes/properties/spec/
                                 |                             |                              | environment/variables/outputs/locals
GitHub URLs                      | ``/tree/<ref>/<path>``      | ref + subpath, ``..``        | diagram
                                 | without ref                 | rejection, clone-escape      |
                                 |                             | check, GIT_TERMINAL_PROMPT=0 |
CLI                              | ``<format> <path>           | argparse, ``--data-dir``,    | one argparse CLI with all flags; the venv
                                 | [--json-only]``, degraded   | ``--install-optional``, venv | bootstrap stays in the diagram shim
                                 | banner                      | re-exec, zero-resource       |
                                 |                             | warning                      |

Terraform tiers are not equal tiers:
  1. tfparse     -- ALWAYS tried first. No ``terraform init`` required. The
                    ONLY tier that yields line provenance.           [FULL]
  2. python-hcl2 -- resources, NO line numbers.                      [DEGRADED]
  3. regex       -- best effort, NO line numbers.                    [DEGRADED]
A fallback is a degraded scan: without line numbers there is no SARIF and no
patching. Callers must surface ``degraded: true`` loudly.
"""

import argparse
import glob as file_glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

# PyYAML is required. The check is deferred to first use (not import time) so a
# shim can parse its arguments and re-exec into its managed venv first.
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    yaml = None
    YAML_AVAILABLE = False

YAML_INSTALL_HINT = (
    "ERROR: PyYAML is not installed.\n"
    f"  Interpreter: {sys.executable}\n"
    "  Install it with: pip install pyyaml"
)


def _require_yaml():
    """Exit with the install hint when PyYAML is missing. Called at first use."""
    if yaml is None:
        print(YAML_INSTALL_HINT)
        sys.exit(1)

# tfparse: accurate Terraform parsing with line provenance.
# NOTE: it does NOT require `terraform init`. Always try it first.
try:
    from tfparse import load_from_path as tfparse_load
    TFPARSE_AVAILABLE = True
except ImportError:
    TFPARSE_AVAILABLE = False

# Optional: python-hcl2 for HCL2 parsing without terraform init
try:
    import hcl2
    HCL2_AVAILABLE = True
except ImportError:
    HCL2_AVAILABLE = False

# Optional: cfn-lint for accurate CloudFormation parsing (with line marks)
try:
    from cfnlint.decode import cfn_json, cfn_yaml
    CFNLINT_AVAILABLE = True
except ImportError:
    CFNLINT_AVAILABLE = False

# Optional: ruamel.yaml for line-preserving YAML parsing (Kubernetes / Compose).
# This is to the YAML formats what tfparse is to Terraform: the ONLY tier that
# yields per-resource line provenance. Absent it, the YAML formats fall back to
# PyYAML, which has no line numbers -> a DEGRADED scan, reported as one.
try:
    from ruamel.yaml import YAML as _RuamelYAML
    RUAMEL_AVAILABLE = True
except ImportError:
    RUAMEL_AVAILABLE = False

# Test/debug escape hatch: force a specific parser tier.
#   IAC_PARSER_FORCE_TIER=hcl2|regex
FORCE_TIER_ENV = "IAC_PARSER_FORCE_TIER"

SUPPORTED_FORMATS = ("terraform", "cloudformation", "kubernetes", "docker-compose")

# Terraform block types that are not resources.
TF_NON_RESOURCE_BLOCKS = (
    'variable', 'output', 'locals', 'terraform', 'provider', 'module', 'data',
)
# tfparse top-level keys that never hold resources or data sources.
TF_TFPARSE_SKIP_BLOCKS = (
    'variable', 'output', 'locals', 'terraform', 'provider', 'moved', 'check', 'import',
)

# Services whose Terraform type prefix spans more than one underscore token.
SERVICE_ALIASES = {
    'api_gateway': 'apigateway',
    'apigatewayv2': 'apigatewayv2',
    'elasticache': 'elasticache',
    'load_balancer': 'elb',
}


# ===========================================================================
# Secret redaction
# ===========================================================================

# Keys whose values are redacted from parser output (IaC often carries secrets,
# and the JSON goes into the model context).
SECRET_KEY_PATTERN = re.compile(
    r'(?i)(password|passwd|pwd|secret|token|credential|connection[_-]?string|\w[_-]?key$)'
)
# Keys that name or point at a secret rather than hold one (secretName,
# secretKeyRef, KeyName, kms_key_id, data_keys, ...) stay visible.
NOT_SECRET_SUFFIX = re.compile(r'(?i)(name|ref|id|ids|arn|keys|type|version|length|policy|enabled)$')
# Keys that match the pattern but hold a setting, not a secret. EC2 metadata
# options are the common case: `http_tokens = "required"` is the IMDSv2 switch
# the threat model and the scanner both need to read.
SETTING_KEYS = frozenset({
    "http_tokens", "HttpTokens", "token_ttl", "TokenTtl",
    "secret_string_wo_version", "rotation_rules",
})
REDACTED = "[REDACTED]"


def is_secret_key(key):
    if not isinstance(key, str) or key in SETTING_KEYS:
        return False
    return bool(SECRET_KEY_PATTERN.search(key)) and not NOT_SECRET_SUFFIX.search(key)


def redact_secrets(obj, key=None):
    """
    Return a copy of `obj` with values under secret-looking keys replaced.

    `key` is the name the value sits under (a scalar under a secret-looking
    key is redacted; dicts and lists under it are walked so names and
    references stay visible). Also handles Compose-style "KEY=value" strings
    and Kubernetes / ECS {"name": "DB_PASSWORD", "value": "..."} pairs.
    """
    if isinstance(obj, dict):
        out = {}
        env_name = obj.get('name') if 'value' in obj else None
        for k, v in obj.items():
            if k == 'value' and is_secret_key(env_name) and not isinstance(v, (dict, list)):
                out[k] = REDACTED
            else:
                out[k] = redact_secrets(v, k)
        return out
    if isinstance(obj, list):
        return [redact_secrets(item, key) for item in obj]
    if is_secret_key(key) and obj not in (None, ""):
        return REDACTED
    if isinstance(obj, str) and '=' in obj:
        name, _, value = obj.partition('=')
        if is_secret_key(name) and value:
            return f"{name}={REDACTED}"
    return obj


# ===========================================================================
# GitHub URLs and cloning
# ===========================================================================

CLONE_TIMEOUT = 120
GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0")

GITHUB_OWNER_REPO = r'[\w\-\.]+/[\w\-\.]+'
GIT_REF_PATTERN = re.compile(r'^[\w][\w\-\./]*$')


def is_github_url(path):
    """Check if the path is a GitHub URL."""
    github_patterns = [
        r'^https?://github\.com/' + GITHUB_OWNER_REPO,
        r'^git@github\.com:' + GITHUB_OWNER_REPO,
        r'^github\.com/' + GITHUB_OWNER_REPO,
    ]
    for pattern in github_patterns:
        if re.match(pattern, path):
            return True
    return False


def normalize_github_url(url):
    """Normalize GitHub URL to HTTPS clone format."""
    # Remove trailing slashes, then a single trailing ".git" suffix.
    # (rstrip('.git') would strip any trailing '.', 'g', 'i', 't' chars,
    # corrupting repo names like "...config" or "...integration".)
    url = url.rstrip('/')
    if url.endswith('.git'):
        url = url[:-len('.git')]

    if url.startswith('git@github.com:'):
        url = url.replace('git@github.com:', 'https://github.com/')
    elif url.startswith('github.com/'):
        url = 'https://' + url
    elif not url.startswith('http'):
        url = 'https://' + url

    return url + '.git'


def valid_git_ref(ref):
    """Accept only plain branch/tag names: no '..', no leading '-', no control chars."""
    return bool(ref) and bool(GIT_REF_PATTERN.match(ref)) and '..' not in ref


def valid_subpath(subpath):
    """Reject any subpath that could escape the clone directory."""
    if not subpath:
        return True
    parts = subpath.split('/')
    return all(part not in ('', '.', '..') for part in parts) and not subpath.startswith('-')


def resolve_ref_and_subpath(clone_url, ref_and_path):
    """
    Split the text after /tree/ or /blob/ into (ref, subpath).

    Branch names may contain '/', so the first segment is not always the
    whole ref. One `git ls-remote` call lists the real refs; the longest
    ref that prefixes the path wins. Falls back to the first segment.
    """
    segments = ref_and_path.split('/')
    if len(segments) == 1:
        return segments[0], None

    candidates = ['/'.join(segments[:i]) for i in range(len(segments), 0, -1)]
    try:
        result = subprocess.run(
            ['git', 'ls-remote', '--heads', '--tags', clone_url],
            capture_output=True, text=True, timeout=30, env=GIT_ENV,
            stdin=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            remote_refs = set()
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) == 2:
                    name = parts[1]
                    for prefix in ('refs/heads/', 'refs/tags/'):
                        if name.startswith(prefix):
                            remote_refs.add(name[len(prefix):])
            for candidate in candidates:
                if candidate in remote_refs:
                    rest = ref_and_path[len(candidate):].strip('/')
                    return candidate, (rest or None)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    rest = '/'.join(segments[1:]).strip('/')
    return segments[0], (rest or None)


def clone_repository(url, ref=None, subpath=None):
    """
    Clone a GitHub repository to a temporary directory.

    Args:
        url: GitHub repository URL
        ref: Optional branch or tag to clone
        subpath: Optional path within the repo to use

    Returns:
        tuple: (temp_dir, target_path) where target_path is the path to parse
    """
    normalized_url = normalize_github_url(url)

    if ref is not None and not valid_git_ref(ref):
        print(f"ERROR: Invalid git ref in URL: {ref!r}")
        return None, None
    if not valid_subpath(subpath):
        print(f"ERROR: Invalid subpath in URL (must stay inside the repository): {subpath!r}")
        return None, None

    temp_dir = tempfile.mkdtemp(prefix='iac_parser_')

    print(f"Cloning repository: {normalized_url}")
    if ref:
        print(f"  Ref: {ref}")
    print(f"  Temp directory: {temp_dir}")

    try:
        # Shallow, single-branch clone; never wait on a credential prompt.
        cmd = ['git', 'clone', '--depth', '1', '--single-branch']
        if ref:
            cmd += ['--branch', ref]
        cmd += ['--', normalized_url, temp_dir]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT,
            env=GIT_ENV,
            stdin=subprocess.DEVNULL,
        )

        if result.returncode != 0:
            print(f"ERROR: Git clone failed: {result.stderr.strip()}")
            if ref:
                print(f"  Check that the branch or tag '{ref}' exists.")
            print("  Private repositories are not supported (no credential prompt).")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None, None

        print("  Clone successful!")

        # Determine target path, and confirm it stays inside the clone.
        target_path = temp_dir
        if subpath:
            root = Path(temp_dir).resolve()
            target = (root / subpath).resolve()
            if root != target and root not in target.parents:
                print(f"ERROR: Subpath escapes the repository: {subpath}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None, None
            if not target.exists():
                print(f"ERROR: Subpath does not exist in repo: {subpath}")
                shutil.rmtree(temp_dir, ignore_errors=True)
                return None, None
            target_path = str(target)

        return temp_dir, target_path

    except subprocess.TimeoutExpired:
        print(f"ERROR: Git clone timed out ({CLONE_TIMEOUT}s). "
              "Large repositories may exceed the limit; clone it locally and pass the path.")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None
    except FileNotFoundError:
        print("ERROR: Git is not installed or not in PATH")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None
    except Exception as e:
        print(f"ERROR: Failed to clone repository: {str(e)}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, None


def cleanup_temp_dir(temp_dir):
    """Clean up temporary directory."""
    if temp_dir and os.path.exists(temp_dir):
        print(f"\nCleaning up temp directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


def extract_github_subpath(url):
    """
    Split a GitHub URL into (base_url, ref, subpath).

    Examples:
        https://github.com/user/repo/tree/main/terraform -> ('https://github.com/user/repo', 'main', 'terraform')
        https://github.com/user/repo/blob/v1.2/infra/main.tf -> (..., 'v1.2', 'infra/main.tf')
        https://github.com/user/repo -> ('https://github.com/user/repo', None, None)

    Query strings and fragments are dropped. Branch names that contain '/'
    are resolved against the remote in resolve_ref_and_subpath.
    """
    url = url.split('#', 1)[0].split('?', 1)[0].rstrip('/')
    match = re.match(r'^(https?://github\.com/' + GITHUB_OWNER_REPO + r')(?:/(?:tree|blob)/(.+))?$', url)
    if not match:
        return url, None, None
    base_url = match.group(1)
    ref_and_path = match.group(2)
    if not ref_and_path:
        return base_url, None, None
    ref, subpath = resolve_ref_and_subpath(normalize_github_url(base_url), ref_and_path)
    return base_url, ref, subpath


# ===========================================================================
# CloudFormation YAML short tags (PyYAML tier)
# ===========================================================================

def cloudformation_constructor(loader, tag_suffix, node):
    """
    Generic constructor for CloudFormation short-form intrinsic functions.

    Normalises every short tag to its long form so `!GetAtt VPC.VpcId`
    becomes {"Fn::GetAtt": ["VPC", "VpcId"]} and `!Sub "..."` becomes
    {"Fn::Sub": "..."}; the dependency scanner then sees one shape.
    """
    key = 'Ref' if tag_suffix == 'Ref' else f'Fn::{tag_suffix}'

    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
        if tag_suffix == 'GetAtt' and isinstance(value, str):
            value = value.split('.', 1)
        return {key: value}
    elif isinstance(node, yaml.SequenceNode):
        return {key: loader.construct_sequence(node, deep=True)}
    elif isinstance(node, yaml.MappingNode):
        return {key: loader.construct_mapping(node, deep=True)}
    else:
        return {key: None}


if yaml is not None:
    yaml.add_multi_constructor('!', cloudformation_constructor, Loader=yaml.SafeLoader)


# ===========================================================================
# Paths, services, and the `location` contract
# ===========================================================================

def normalize_repo_path(file_path, root=None):
    """
    Normalize a source file path to a repo-relative POSIX path with NO leading
    slash. This is the join key every downstream consumer (Checkov adapter,
    SARIF emitter, patcher) keys off, so it has exactly one shape.
    """
    if not file_path:
        return ""

    p = str(file_path).replace("\\", "/")

    if root:
        root_abs = os.path.abspath(root)
        if os.path.isfile(root_abs):
            root_abs = os.path.dirname(root_abs)
        if os.path.isabs(p):
            try:
                p = os.path.relpath(os.path.abspath(p), root_abs).replace("\\", "/")
            except ValueError:
                pass
        else:
            # Strip a redundant leading copy of the scan root, if present.
            root_rel = str(root).replace("\\", "/").rstrip("/")
            if root_rel and p.startswith(root_rel + "/"):
                p = p[len(root_rel) + 1:]

    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def derive_service(resource_type):
    """
    Derive the cloud service from a Terraform resource type.
      aws_s3_bucket        -> s3
      aws_cloudwatch_...   -> cloudwatch
      aws_api_gateway_...  -> apigateway
    """
    if not resource_type or "_" not in resource_type:
        return resource_type or "unknown"

    parts = resource_type.split("_")
    remainder = parts[1:]
    if not remainder:
        return "unknown"

    two = "_".join(remainder[:2])
    if two in SERVICE_ALIASES:
        return SERVICE_ALIASES[two]
    if remainder[0] in SERVICE_ALIASES:
        return SERVICE_ALIASES[remainder[0]]
    return remainder[0]


def split_resource_address(address, resource_type):
    """
    Split a tfparse address into (resourceType, resourceName).

    Handles module-nested and for_each-expanded addresses:
      aws_s3_bucket.each["alpha"]                -> (aws_s3_bucket, each["alpha"])
      module.storage.aws_s3_bucket.inner         -> (aws_s3_bucket, inner)
    """
    if not address:
        return resource_type, "unknown"

    marker = f"{resource_type}."
    idx = address.find(marker)
    if idx == -1:
        return resource_type, address
    return resource_type, address[idx + len(marker):]


def strip_instance_index(path):
    """aws_s3_bucket.each["alpha"] -> aws_s3_bucket.each ; aws_instance.web[0] -> aws_instance.web"""
    return re.sub(r'\[[^\]]*\]', '', path or '')


def _module_prefix(address):
    """module.a.module.b.aws_x.y -> "module.a.module.b"; aws_x.y -> "" """
    parts = (address or '').split('.')
    prefix = []
    i = 0
    while i + 1 < len(parts) and parts[i] == 'module':
        prefix += parts[i:i + 2]
        i += 2
    return '.'.join(prefix)


def build_location(file_path, start_line, end_line, address, resource_type, root=None):
    """Build the §5 `location` object. The public contract — do not improvise."""
    return {
        "file": normalize_repo_path(file_path, root),
        "startLine": start_line,
        "endLine": end_line,
        "resourceAddress": address,
        "resourceType": resource_type,
        "service": derive_service(resource_type),
    }


def build_yaml_location(file_path, start_line, end_line, address, resource_type,
                        service, root=None):
    """The same §5 `location` shape as build_location, but for the YAML-based
    formats (CloudFormation / Kubernetes / Docker Compose) whose `service` is not
    derivable from an AWS `aws_*` resource-type slug. Field-for-field identical to
    what the Terraform path emits — downstream code (SARIF, report, findings)
    joins on it, so it must not improvise fields.
    """
    # Absolute-ize the file so normalize_repo_path can always take the relpath
    # against the scan root — including the single-file case (CFN template,
    # compose file) where the given path IS the root.
    norm_file = os.path.abspath(file_path) if file_path else file_path
    return {
        "file": normalize_repo_path(norm_file, root),
        "startLine": start_line,
        "endLine": end_line,
        "resourceAddress": address,
        "resourceType": resource_type,
        "service": service,
    }


def _mark_line(node, attr):
    """1-based line for a cfn-lint decoded node's start/end mark, or None."""
    mark = getattr(node, attr, None)
    line = getattr(mark, "line", None)
    return (line + 1) if line is not None else None


def cfn_resource_line_index(resources_node):
    """{logical_id: (startLine, endLine)} 1-based, from cfn-lint's line marks.

    `startLine` is the line of the logical-ID key (what Checkov reports too).
    `endLine` is the resource value's end mark, capped at the next resource's
    start so trailing comments/blank lines don't bleed one block into the next.
    Returns {} if the node carries no marks (e.g. a plain dict from a JSON reload).
    """
    entries = []
    try:
        keys = list(resources_node.keys())
    except AttributeError:
        return {}
    for key in keys:
        value = resources_node[key]
        start = _mark_line(key, "start_mark")
        raw_end = getattr(getattr(value, "end_mark", None), "line", None)
        entries.append((str(key), start, raw_end))

    index = {}
    for i, (lid, start, raw_end) in enumerate(entries):
        end = raw_end
        next_start = entries[i + 1][1] if i + 1 < len(entries) else None
        if next_start is not None:
            capped = next_start - 1
            if end is None or end > capped:
                end = capped
        if start is not None and end is not None and end < start:
            end = start
        index[lid] = (start, end)
    return index


def _file_line_count(path):
    try:
        with open(path, "r") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return None


def _lc_line(node):
    line = getattr(getattr(node, "lc", None), "line", None)
    return (line + 1) if line is not None else None


def kubernetes_line_index(yaml_file):
    """{(kind, name): (startLine, endLine)} 1-based for one manifest file.

    A Kubernetes resource IS a YAML document, so its block spans from the
    document's first line to the line before the next document (or EOF for the
    last). Items inside a ``kind: List`` document get their own span, from the
    item's first line to the line before the next item (or the List's end).
    Returns None when ruamel is unavailable (the DEGRADED signal).
    """
    if not RUAMEL_AVAILABLE:
        return None
    try:
        ry = _RuamelYAML()
        with open(yaml_file, "r") as fh:
            docs = list(ry.load_all(fh))
    except Exception:
        return None

    total = _file_line_count(yaml_file)
    starts = [_lc_line(doc) for doc in docs]

    index = {}
    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            continue
        start = starts[i]
        end = None
        for j in range(i + 1, len(starts)):
            if starts[j] is not None:
                end = starts[j] - 1
                break
        if end is None:
            end = total
        if start is not None and end is not None and end < start:
            end = start

        if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            items = doc["items"]
            item_starts = [_lc_line(item) for item in items]
            for j, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                item_start = item_starts[j]
                item_end = None
                for k in range(j + 1, len(item_starts)):
                    if item_starts[k] is not None:
                        item_end = item_starts[k] - 1
                        break
                if item_end is None:
                    item_end = end
                if item_start is not None and item_end is not None and item_end < item_start:
                    item_end = item_start
                kind = item.get("kind")
                name = (item.get("metadata") or {}).get("name")
                index[(str(kind), str(name))] = (item_start, item_end)
            continue

        kind = doc.get("kind")
        name = (doc.get("metadata") or {}).get("name")
        index[(str(kind), str(name))] = (start, end)
    return index


def compose_line_index(path):
    """{service_name: (startLine, endLine)} 1-based for a Docker Compose file.

    Each service block runs from its key line to the line before the next
    service (or EOF for the last). Returns None when ruamel is unavailable.
    """
    if not RUAMEL_AVAILABLE:
        return None
    try:
        ry = _RuamelYAML()
        with open(path, "r") as fh:
            data = ry.load(fh)
    except Exception:
        return None
    if not isinstance(data, dict):
        return {}
    services = data.get("services")
    if not isinstance(services, dict):
        return {}

    total = _file_line_count(path)
    lc = getattr(services, "lc", None)
    lc_data = getattr(lc, "data", None) if lc is not None else None

    key_lines = {}
    for name in services.keys():
        info = lc_data.get(name) if isinstance(lc_data, dict) else None
        key_lines[str(name)] = (info[0] + 1) if info else None

    ordered = sorted(
        ((n, s) for n, s in key_lines.items() if s is not None),
        key=lambda pair: pair[1],
    )
    index = {}
    for idx, (name, start) in enumerate(ordered):
        end = ordered[idx + 1][1] - 1 if idx + 1 < len(ordered) else total
        if end is not None and end < start:
            end = start
        index[name] = (start, end)
    for name, start in key_lines.items():
        index.setdefault(name, (start, start))
    return index


# ===========================================================================
# Terraform
# ===========================================================================

def parse_terraform(path):
    """
    Parse Terraform files (.tf) to extract resources.

    Tiered, but not equal tiers:
      1. tfparse  — ALWAYS tried first. No `terraform init` required.
                    The ONLY tier that yields line provenance.       [FULL]
      2. python-hcl2 — resources, NO line numbers.                   [DEGRADED]
      3. regex       — best effort, NO line numbers.                 [DEGRADED]
    """
    print(f"Parsing Terraform files in: {path}")

    forced = os.environ.get(FORCE_TIER_ENV, "").strip().lower()
    if forced:
        print(f"  {FORCE_TIER_ENV}={forced} — parser tier forced (test/debug path)")

    # Tier 1: tfparse — unconditionally. No `.terraform/` gate.
    if TFPARSE_AVAILABLE and not forced:
        print("  Using tfparse (line provenance available)")
        result = parse_terraform_with_tfparse(path)
        if "error" not in result:
            return result
        print(f"  tfparse failed: {result.get('error')}, falling back to a DEGRADED tier...")
    elif not TFPARSE_AVAILABLE:
        print("  WARNING: tfparse is not installed — install it with: pip install tfparse")

    # Tier 2: python-hcl2 — DEGRADED (no line numbers)
    if HCL2_AVAILABLE and forced != "regex":
        print("  Using python-hcl2 [DEGRADED: no line numbers]")
        result = parse_terraform_with_hcl2(path)
        if "error" not in result:
            return result
        print(f"  hcl2 failed: {result.get('error')}, falling back...")

    # Tier 3: regex — DEGRADED (no line numbers)
    print("  Using regex fallback [DEGRADED: basic extraction, no line numbers]")
    return parse_terraform_with_regex(path)


def _tf_files(path):
    if os.path.isfile(path):
        return [path]
    return sorted(file_glob.glob(os.path.join(path, "**/*.tf"), recursive=True))


def parse_terraform_with_tfparse(path):
    """
    Parse Terraform using tfparse (Cloud Custodian).

    Full expression evaluation, module traversal, for_each/dynamic expansion, and
    — the reason this is tier 1 — per-resource line provenance via `__tfmeta`.
    Does NOT require `terraform init`.

    tfparse output shape (0.6.x): top-level keys are resource types (plus
    `module`, `variable`, `output`, `locals`, `provider`, `terraform`); each
    value is a list of instances carrying `__tfmeta` with `type` ("resource" or
    "data"), `path` (the full address), `filename`, `line_start`/`line_end` and
    `references`. Data sources are flattened into keys named after the DATA
    type; only `__tfmeta.type` tells them apart from resources.
    """
    try:
        parsed = tfparse_load(path)

        resources = []
        dependencies = {}
        modules = []
        data_sources = []
        missing_provenance = []
        raw_refs = {}  # address -> {"label.name"} from __tfmeta.references

        for block_type, instances in parsed.items():
            if block_type in TF_TFPARSE_SKIP_BLOCKS:
                continue
            if not isinstance(instances, list):
                continue

            if block_type == 'module':
                for instance in instances:
                    if not isinstance(instance, dict):
                        continue
                    meta = instance.get('__tfmeta', {}) or {}
                    address = meta.get('path') or ''
                    if address.startswith("module."):
                        name = address[len("module."):]
                    else:
                        name = address or meta.get('label') or 'unknown'
                    modules.append({
                        "name": name,
                        "address": address,
                        "source": instance.get('source', ''),
                        "file": meta.get('filename'),
                        "location": {
                            "file": normalize_repo_path(meta.get('filename'), path),
                            "startLine": meta.get('line_start'),
                            "endLine": meta.get('line_end'),
                        },
                    })
                continue

            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                meta = instance.get('__tfmeta', {}) or {}
                meta_type = meta.get('type')

                if meta_type == 'data':
                    address = meta.get('path') or 'unknown'
                    base = strip_instance_index(address)
                    name = base.split('.')[-1]
                    data_sources.append({
                        "type": block_type,
                        "address": address,
                        "name": name,
                        "full_name": f"data.{block_type}.{name}",
                        "module": _module_prefix(base) or None,
                        "file": meta.get('filename'),
                        "location": {
                            "file": normalize_repo_path(meta.get('filename'), path),
                            "startLine": meta.get('line_start'),
                            "endLine": meta.get('line_end'),
                        },
                    })
                    continue

                if meta_type != 'resource':
                    continue

                resource_type = block_type
                address = meta.get('path') or f"{resource_type}.unknown"
                _, resource_name = split_resource_address(address, resource_type)

                provider = resource_type.split("_")[0] if "_" in resource_type else "unknown"

                location = build_location(
                    meta.get('filename'),
                    meta.get('line_start'),
                    meta.get('line_end'),
                    address,
                    resource_type,
                    root=path,
                )

                if location["startLine"] is None or location["endLine"] is None:
                    missing_provenance.append(address)

                attributes = {k: v for k, v in instance.items() if not k.startswith('__')}

                resource_data = {
                    "type": resource_type,
                    "name": resource_name,
                    "full_name": address,
                    "provider": provider,
                    "module": address.startswith("module."),
                    "module_path": _module_prefix(address) or None,
                    "file": meta.get('filename'),
                    "instances": 1,
                    "location": location,
                    # __tfmeta.references are free dependency edges — the
                    # exposure-chain pass consumes these.
                    "references": meta.get('references', []) or [],
                    "attributes": redact_secrets(attributes),
                }
                resources.append(resource_data)

                deps = set(extract_tfparse_dependencies(instance, resource_type))
                refs = raw_refs.setdefault(address, set())
                for ref in meta.get('references') or []:
                    if not isinstance(ref, dict):
                        continue
                    label = ref.get('label')
                    name = ref.get('name')
                    if label and name:
                        refs.add(f"{label}.{strip_instance_index(name)}")
                if deps:
                    dependencies[address] = deps

        # count / for_each: how many instances share each base address.
        base_counts = Counter(strip_instance_index(r["full_name"]) for r in resources)
        for r in resources:
            r["instances"] = base_counts[strip_instance_index(r["full_name"])]

        # Resolve __tfmeta.references against known resources and data sources.
        # A reference inside a module names the local address (`aws_x.y`); match
        # it to the module-qualified base, preferring the referrer's own module.
        local_index = {}
        for base in base_counts:
            prefix = _module_prefix(base)
            local = base[len(prefix) + 1:] if prefix else base
            local_index.setdefault(local, []).append(base)
        known_data = {d["full_name"] for d in data_sources}

        for address, refs in raw_refs.items():
            own_base = strip_instance_index(address)
            own_prefix = _module_prefix(address)
            deps = dependencies.setdefault(address, set())
            for ref in refs:
                candidates = local_index.get(ref, [])
                same_module = [c for c in candidates if _module_prefix(c) == own_prefix]
                target = None
                if same_module:
                    target = same_module[0]
                elif len(candidates) == 1:
                    target = candidates[0]
                if target is not None and target != own_base:
                    deps.add(target)
                elif target is None and f"data.{ref}" in known_data:
                    deps.add(f"data.{ref}")
            if not deps:
                dependencies.pop(address, None)

        dependencies = {k: sorted(v) for k, v in dependencies.items()}

        total = len(resources)
        with_lines = total - len(missing_provenance)

        return {
            "format": "terraform",
            "parser": "tfparse",
            "parseTier": "tfparse",
            "degraded": False,
            "lineProvenance": True,
            "resources": resources,
            "modules": modules,
            "data_sources": data_sources,
            "total_resources": total,
            "resources_with_line_provenance": with_lines,
            "resources_missing_line_provenance": missing_provenance,
            "dependencies": dependencies,
            "dependencies_source": "references",
        }

    except Exception as e:
        return {"error": f"tfparse failed: {str(e)}"}


def extract_tfparse_dependencies(resource_attrs, resource_type):
    """
    Extract resource dependencies from tfparse output.
    Looks for references in attribute values.
    """
    dependencies = set()

    def find_references(obj, path=""):
        if isinstance(obj, str):
            ref_pattern = r'([a-z_]+\.[a-z0-9_-]+)(?:\.[a-z_]+)?'
            for match in re.finditer(ref_pattern, obj):
                ref = match.group(1)
                if not ref.startswith(('var.', 'local.', 'data.', 'module.', 'path.', 'terraform.')):
                    parts = ref.split('.')
                    if len(parts) == 2 and '_' in parts[0]:
                        dependencies.add(ref)
        elif isinstance(obj, dict):
            for key, value in obj.items():
                if not key.startswith('__'):
                    find_references(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                find_references(item, f"{path}[{i}]")

    find_references(resource_attrs)
    return list(dependencies)


def hcl2_clean(value):
    """
    Normalise python-hcl2 output across versions.

    python-hcl2 >= 8 wraps literal strings (and block labels) in quotes,
    e.g. '"10.0.0.0/16"', and adds `__is_block__` / `__comments__` entries.
    Older versions return bare strings. Strip all of it so the rest of the
    parser sees one shape (and comments cannot create references).
    """
    if isinstance(value, dict):
        return {hcl2_clean(k): hcl2_clean(v) for k, v in value.items()
                if not (isinstance(k, str) and k.startswith('__'))}
    if isinstance(value, list):
        return [hcl2_clean(v) for v in value]
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _hcl2_block_bodies(parsed):
    """Yield every (container, key) whose value is a block body dict, so a
    normaliser can rewrite bodies in place. Labeled blocks (resource, data)
    nest {type: {name: body}}; single-label blocks nest {name: body}; locals
    are bodies themselves."""
    for block_type, blocks in parsed.items():
        if not isinstance(blocks, list):
            continue
        for i, block in enumerate(blocks):
            if not isinstance(block, dict):
                continue
            if block_type == 'locals':
                yield blocks, i
                continue
            for label, body in block.items():
                if block_type in ('resource', 'data') and isinstance(body, dict) \
                        and all(isinstance(v, dict) for v in body.values()):
                    for name in body:
                        yield body, name
                elif isinstance(body, dict):
                    yield block, label


def hcl2_is_bc_shape(parsed):
    """
    True when the loaded `hcl2` module is Bridgecrew's fork (bc-python-hcl2,
    a Checkov dependency that installs over python-hcl2's `hcl2` package).

    That fork wraps EVERY attribute value in a one-element list
    (`cidr_block = "10.0.0.0/16"` -> `["10.0.0.0/16"]`, `owners = ["a"]` ->
    `[["a"]]`) and tags block bodies with `__start_line__` / `__end_line__`.
    Detected structurally first, by version string second.
    """
    for container, key in _hcl2_block_bodies(parsed):
        body = container[key]
        if isinstance(body, dict) and '__start_line__' in body:
            return True
    version = str(getattr(hcl2, '__version__', '') or '') if HCL2_AVAILABLE else ''
    return version.startswith('0.')


def _hcl2_bc_looks_like_block(value):
    """A bc-fork nested block body: a dict whose every value is list-wrapped."""
    return isinstance(value, dict) and all(
        isinstance(v, list) for k, v in value.items()
        if not (isinstance(k, str) and k.startswith('__'))
    )


def hcl2_unwrap_bc(body):
    """
    Undo bc-python-hcl2's list wrapping for one block body (recursively for
    nested blocks), yielding python-hcl2's shape: scalars bare, nested blocks
    as a list of bodies, object literals as dicts.
    """
    if not isinstance(body, dict):
        return body
    out = {}
    for k, v in body.items():
        if isinstance(k, str) and k.startswith('__'):
            continue
        out[k] = _hcl2_bc_value(v)
    return out


def _hcl2_bc_value(value):
    """One attribute value from a bc-fork body: nested block list, wrapped scalar,
    or a genuine list."""
    if isinstance(value, list):
        if value and all(_hcl2_bc_looks_like_block(item) for item in value):
            return [hcl2_unwrap_bc(item) for item in value]
        if len(value) == 1:
            return _hcl2_bc_unwrapped(value[0])
        return value
    return _hcl2_bc_unwrapped(value)


def _hcl2_bc_unwrapped(value):
    """An unwrapped value may still hold block bodies (a `dynamic "x"` label
    dict, or an object literal). Normalise those; leave everything else."""
    if isinstance(value, dict):
        if _hcl2_bc_looks_like_block(value):
            return hcl2_unwrap_bc(value)
        return {k: _hcl2_bc_unwrapped(v) for k, v in value.items()}
    return value


def hcl2_normalize(parsed):
    """`hcl2.load` output -> one shape, whichever `hcl2` package is installed."""
    bc_shape = hcl2_is_bc_shape(parsed)
    parsed = hcl2_clean(parsed)
    if bc_shape:
        for container, key in list(_hcl2_block_bodies(parsed)):
            container[key] = hcl2_unwrap_bc(container[key])
    return parsed


def hcl2_labeled_blocks(parsed, block_type):
    """
    Yield (label, body) for every block of `block_type`.

    python-hcl2 returns `resource`, `data`, `variable`, `module`, `output`
    as a list of single-key dicts: [{"aws_vpc": {"main": {...}}}, ...]
    (dicts of dicts, not lists). Confirmed on 2.0.3, 4.3.5, 7.3.1, 8.1.4.
    Older releases wrapped the inner mapping in a list; both are tolerated.
    """
    for block in parsed.get(block_type, []) or []:
        if not isinstance(block, dict):
            continue
        for label, body in block.items():
            if isinstance(body, list):
                merged = {}
                for item in body:
                    if isinstance(item, dict):
                        merged.update(item)
                body = merged
            yield label, body


def parse_terraform_with_hcl2(path):
    """
    Parse Terraform using python-hcl2.
    Good for syntax parsing without terraform init. DEGRADED: no line numbers,
    no module traversal, no for_each / dynamic expansion.
    """
    try:
        tf_files = _tf_files(path)
        if not tf_files:
            return {"error": "No Terraform files found", "resources": [], "dependencies": {}}

        resources = []
        data_sources = []
        variables = {}
        modules = []
        locals_block = {}
        outputs = {}
        failed_files = []

        for tf_file in tf_files:
            print(f"    Reading: {tf_file}")
            try:
                with open(tf_file, 'r') as f:
                    parsed = hcl2_normalize(hcl2.load(f))

                for resource_type, instances in hcl2_labeled_blocks(parsed, 'resource'):
                    if not isinstance(instances, dict):
                        continue
                    for resource_name, attrs in instances.items():
                        attrs = attrs if isinstance(attrs, dict) else {}
                        full_name = f"{resource_type}.{resource_name}"
                        provider = resource_type.split("_")[0] if "_" in resource_type else "unknown"
                        resource = {
                            "type": resource_type,
                            "name": resource_name,
                            "full_name": full_name,
                            "provider": provider,
                            "file": tf_file,
                            # DEGRADED: python-hcl2 preserves no line numbers.
                            "location": build_location(
                                tf_file, None, None, full_name, resource_type, root=path
                            ),
                            "references": [],
                            "attributes": redact_secrets(attrs),
                        }
                        if "count" in attrs:
                            resource["count"] = attrs["count"]
                        if "for_each" in attrs:
                            resource["for_each"] = attrs["for_each"]
                        resources.append(resource)

                for data_type, instances in hcl2_labeled_blocks(parsed, 'data'):
                    if not isinstance(instances, dict):
                        continue
                    for data_name, attrs in instances.items():
                        full_name = f"data.{data_type}.{data_name}"
                        data_sources.append({
                            "type": data_type,
                            "address": full_name,
                            "name": data_name,
                            "full_name": full_name,
                            "module": None,
                            "file": tf_file,
                            "location": {
                                "file": normalize_repo_path(tf_file, path),
                                "startLine": None,
                                "endLine": None,
                            },
                            "attributes": redact_secrets(attrs if isinstance(attrs, dict) else {}),
                        })

                for var_name, var_config in hcl2_labeled_blocks(parsed, 'variable'):
                    var_config = var_config if isinstance(var_config, dict) else {}
                    variables[var_name] = {
                        "name": var_name,
                        "file": tf_file,
                        "default": redact_secrets(var_config.get('default'), var_name),
                        "type": var_config.get('type'),
                        "description": var_config.get('description'),
                    }

                for module_name, module_config in hcl2_labeled_blocks(parsed, 'module'):
                    module_config = module_config if isinstance(module_config, dict) else {}
                    modules.append({
                        "name": module_name,
                        "source": module_config.get('source', ''),
                        "file": tf_file,
                    })

                for locals_block_item in parsed.get('locals', []) or []:
                    if isinstance(locals_block_item, dict):
                        locals_block.update(redact_secrets(locals_block_item))

                for output_name, output_config in hcl2_labeled_blocks(parsed, 'output'):
                    output_config = output_config if isinstance(output_config, dict) else {}
                    outputs[output_name] = {
                        "name": output_name,
                        "value": redact_secrets(output_config.get('value'), output_name),
                        "file": tf_file,
                    }

            except Exception as e:
                print(f"    Warning: Error parsing {tf_file}: {e}")
                failed_files.append(tf_file)
                continue

        if not resources and failed_files:
            # Every file that mattered failed: let the regex tier try instead of
            # reporting an empty architecture.
            return {"error": f"hcl2 could not parse {len(failed_files)} file(s) and found no resources"}

        dependencies = extract_hcl2_dependencies(resources, data_sources)

        return {
            "format": "terraform",
            "parser": "hcl2",
            "parseTier": "hcl2",
            "degraded": True,
            "degradationReason": (
                "Fell back to python-hcl2. This tier yields NO line numbers, so "
                "findings cannot populate SARIF and cannot be auto-patched. "
                "Module contents, for_each and dynamic blocks are NOT expanded."
            ),
            "lineProvenance": False,
            "resources": resources,
            "data_sources": data_sources,
            "variables": variables,
            "modules": modules,
            "locals": locals_block,
            "outputs": outputs,
            "total_resources": len(resources),
            "resources_with_line_provenance": 0,
            "dependencies": dependencies,
            "dependencies_source": "references",
            "unparsed_files": failed_files,
        }

    except Exception as e:
        return {"error": f"hcl2 parsing failed: {str(e)}"}


# resource_type.name or data.type.name, optionally followed by attributes
TF_REFERENCE_PATTERN = re.compile(r'\b(data\.)?([a-z][a-z0-9_]*)\.([A-Za-z0-9_-]+)\b')


def find_terraform_references(value, known_resources, known_data):
    """Find references to known resources / data sources anywhere in a value."""
    refs = set()
    if isinstance(value, str):
        for match in TF_REFERENCE_PATTERN.finditer(value):
            is_data, r_type, r_name = match.groups()
            ref = f"{r_type}.{r_name}"
            if is_data:
                if f"data.{ref}" in known_data:
                    refs.add(f"data.{ref}")
            elif ref in known_resources:
                refs.add(ref)
    elif isinstance(value, dict):
        for v in value.values():
            refs.update(find_terraform_references(v, known_resources, known_data))
    elif isinstance(value, list):
        for item in value:
            refs.update(find_terraform_references(item, known_resources, known_data))
    return refs


def extract_hcl2_dependencies(resources, data_sources=()):
    """
    Extract dependencies from HCL2 parsed resources by analyzing attribute
    references (implicit, including `${}` interpolation) and depends_on (explicit).
    """
    dependencies = {}
    known_resources = {r["full_name"] for r in resources}
    known_data = {d["full_name"] for d in data_sources}

    for resource in resources:
        full_name = resource["full_name"]
        attrs = resource.get("attributes", {})
        refs = find_terraform_references(attrs, known_resources, known_data)
        refs.discard(full_name)
        if refs:
            dependencies[full_name] = sorted(refs)

    return dependencies


def parse_terraform_with_regex(path):
    """
    Parse Terraform using regex (fallback).
    Basic extraction without full HCL understanding. DEGRADED: no line numbers.
    """
    tf_files = _tf_files(path)
    if not tf_files:
        return {"error": "No Terraform files found", "resources": [], "dependencies": {}}

    resources = []
    data_sources = []
    variables = {}
    modules = []
    bodies = {}  # full_name -> block body text, for reference scanning

    block_pattern = re.compile(r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)

    for tf_file in tf_files:
        print(f"    Reading: {tf_file}")
        try:
            with open(tf_file, 'r') as f:
                content = f.read()

            for match in block_pattern.finditer(content):
                block_kind, block_type, block_name = match.groups()
                body = extract_brace_block(content, match.end() - 1)
                provider = block_type.split("_")[0] if "_" in block_type else "unknown"

                if block_kind == "data":
                    full_name = f"data.{block_type}.{block_name}"
                    data_sources.append({
                        "type": block_type,
                        "address": full_name,
                        "name": block_name,
                        "full_name": full_name,
                        "module": None,
                        "file": tf_file,
                        "location": {
                            "file": normalize_repo_path(tf_file, path),
                            "startLine": None,
                            "endLine": None,
                        },
                    })
                    continue

                full_name = f"{block_type}.{block_name}"
                resource = {
                    "type": block_type,
                    "name": block_name,
                    "full_name": full_name,
                    "file": tf_file,
                    # DEGRADED: no line numbers, no module/for_each/dynamic expansion.
                    "location": build_location(
                        tf_file, None, None, full_name, block_type, root=path
                    ),
                    "references": [],
                    "provider": provider,
                }
                count = re.search(r'^\s*count\s*=\s*(.+?)\s*$', body, re.MULTILINE)
                for_each = re.search(r'^\s*for_each\s*=\s*(.+?)\s*$', body, re.MULTILINE)
                if count:
                    resource["count"] = count.group(1)
                if for_each:
                    resource["for_each"] = for_each.group(1)
                resources.append(resource)
                bodies[full_name] = body

            for match in re.finditer(r'variable\s+"([^"]+)"\s+\{', content):
                var_name = match.group(1)
                variables[var_name] = {"name": var_name, "file": tf_file}

            for match in re.finditer(r'module\s+"([^"]+)"\s+\{', content):
                module_name = match.group(1)
                modules.append({"name": module_name, "file": tf_file})

        except Exception as e:
            print(f"    Warning: Error reading {tf_file}: {e}")
            continue

    return {
        "format": "terraform",
        "parser": "regex",
        "parseTier": "regex",
        "degraded": True,
        "degradationReason": (
            "Fell back to the regex parser. This tier yields NO line numbers, so "
            "findings cannot populate SARIF and cannot be auto-patched. Heredocs, "
            "dynamic blocks, for_each and multi-line expressions are NOT handled "
            "correctly — resources may be missed entirely."
        ),
        "lineProvenance": False,
        "resources": resources,
        "data_sources": data_sources,
        "variables": variables,
        "modules": modules,
        "total_resources": len(resources),
        "resources_with_line_provenance": 0,
        "dependencies": extract_regex_dependencies(resources, data_sources, bodies),
        "dependencies_source": "references",
    }


def extract_brace_block(content, open_index):
    """
    Return the text between the brace at `open_index` and its matching close,
    with `#` and `//` line comments removed so they cannot create references.
    """
    depth = 0
    in_string = False
    i = open_index
    kept = []
    start = open_index + 1
    while i < len(content):
        ch = content[i]
        if in_string:
            if ch == '\\':
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == '#' or content.startswith('//', i):
            kept.append(content[start:i])
            newline = content.find('\n', i)
            i = len(content) if newline == -1 else newline
            start = i
            continue
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                kept.append(content[start:i])
                return ''.join(kept)
        i += 1
    kept.append(content[start:])
    return ''.join(kept)


def extract_regex_dependencies(resources, data_sources=(), bodies=None):
    """
    Extract dependencies by scanning each resource body for references to
    known resources and data sources (`aws_subnet.main.id`, `data.aws_ami.al2`)
    and for explicit `depends_on` lists. No type-pair guessing.
    """
    dependencies = {}
    bodies = bodies or {}
    known_resources = {r["full_name"] for r in resources}
    known_data = {d["full_name"] for d in data_sources}

    for resource in resources:
        full_name = resource["full_name"]
        body = bodies.get(full_name, "")
        refs = find_terraform_references(body, known_resources, known_data)
        refs.discard(full_name)
        if refs:
            dependencies[full_name] = sorted(refs)

    return dependencies


# ===========================================================================
# CloudFormation
# ===========================================================================

CFN_TEMPLATE_GLOBS = ("*.yaml", "*.yml", "*.json", "*.template")
CFN_TEMPLATE_EXTENSIONS = tuple(g.lstrip("*") for g in CFN_TEMPLATE_GLOBS)


def _looks_like_cfn_template(path):
    """Cheap sniff: a CloudFormation template declares a top-level `Resources`
    map (and usually `AWSTemplateFormatVersion`). Skips k8s manifests, compose
    files, parameter files and lockfiles that share the extensions."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(65536)
    except OSError:
        return False
    if "AWSTemplateFormatVersion" in head:
        return True
    if path.endswith(".json"):
        return '"Resources"' in head
    return bool(re.search(r"^Resources\s*:", head, re.MULTILINE))


looks_like_cloudformation = _looks_like_cfn_template


def find_cloudformation_templates(path):
    """Every template file under ``path`` (recursive), sorted, sniffed. A file
    path is returned as a one-element list."""
    if os.path.isfile(path):
        return [path]
    found = set()
    for pattern in CFN_TEMPLATE_GLOBS:
        found.update(file_glob.glob(os.path.join(path, "**", pattern), recursive=True))
    return sorted(p for p in found if os.path.isfile(p) and _looks_like_cfn_template(p))


def parse_cloudformation(path):
    """
    Parse a CloudFormation template (YAML or JSON), or a DIRECTORY of them.

    Uses a tiered approach:
    1. cfn-lint (most accurate, resolves intrinsic functions, line marks)
    2. PyYAML fallback (basic parsing, DEGRADED)

    For a directory every template is parsed and the results are merged; each
    resource's ``location.file`` is relative to the directory, so downstream
    joins (Checkov, the CFN patcher, SARIF) line up the same way they do for
    a Terraform tree.
    """
    if os.path.isdir(path):
        return _parse_cloudformation_dir(path)
    return _parse_cloudformation_file(path, root=path)


def _parse_cloudformation_file(path, root=None):
    print(f"Parsing CloudFormation template: {path}")

    if CFNLINT_AVAILABLE:
        print("  Using cfn-lint")
        result = parse_cloudformation_with_cfnlint(path, root=root)
        if "error" not in result:
            return result
        print(f"  cfn-lint failed: {result.get('error')}, falling back...")

    print("  Using PyYAML fallback")
    return parse_cloudformation_with_yaml(path, root=root)


parse_cloudformation_file = _parse_cloudformation_file


def _parse_cloudformation_dir(root):
    root = os.path.abspath(root)
    templates = find_cloudformation_templates(root)
    print(f"Parsing CloudFormation templates in: {root} ({len(templates)} found)")
    if not templates:
        return {
            "error": (
                "No CloudFormation templates found under %s (looked for %s with a "
                "top-level Resources map)" % (root, ", ".join(CFN_TEMPLATE_GLOBS))
            )
        }

    merged = {
        "format": "cloudformation",
        "parser": "cfn-lint",
        "parseTier": "cfn-lint",
        "degraded": False,
        "degradationReason": None,
        "lineProvenance": True,
        "resources_with_line_provenance": 0,
        "resources_missing_line_provenance": [],
        "resources": [],
        "parameters": {},
        "outputs": {},
        "conditions": [],
        "total_resources": 0,
        "dependencies": {},
        "templates": [],
        "files": [],
        "template_errors": {},
    }
    degraded_reasons = []
    for template in templates:
        rel = normalize_repo_path(template, root)
        result = _parse_cloudformation_file(template, root=root)
        if "error" in result:
            merged["template_errors"][rel] = result["error"]
            degraded_reasons.append("%s: %s" % (rel, result["error"]))
            continue
        merged["templates"].append(rel)
        merged["files"].append(template)
        merged["resources"].extend(result.get("resources") or [])
        merged["resources_with_line_provenance"] += result.get(
            "resources_with_line_provenance", 0
        )
        merged["resources_missing_line_provenance"].extend(
            result.get("resources_missing_line_provenance") or []
        )
        # cfn-lint tier returns dicts; the yaml tier returns key lists.
        for key in ("parameters", "outputs"):
            value = result.get(key) or {}
            if isinstance(value, dict):
                merged[key].update(value)
            else:
                merged[key].update({k: {} for k in value})
        merged["conditions"].extend(result.get("conditions") or [])
        for k, v in (result.get("dependencies") or {}).items():
            if k in merged["dependencies"]:
                print(f"  Warning: '{k}' is defined in more than one template; dependencies merged")
                merged["dependencies"][k] = sorted(set(merged["dependencies"][k]) | set(v))
            else:
                merged["dependencies"][k] = v
        if result.get("degraded"):
            merged["parser"] = result.get("parser", merged["parser"])
            merged["parseTier"] = result.get("parseTier", merged["parseTier"])
            degraded_reasons.append(
                "%s: %s" % (rel, result.get("degradationReason") or "degraded parse")
            )

    merged["total_resources"] = len(merged["resources"])
    if not merged["templates"]:
        return {"error": "Failed to parse every CloudFormation template: " + "; ".join(degraded_reasons)}
    if degraded_reasons:
        merged["degraded"] = True
        merged["lineProvenance"] = False
        merged["degradationReason"] = "; ".join(degraded_reasons)
    return merged


def plain_data(obj):
    """Convert cfn-lint node subclasses (dict_node, list_node, str_node) to plain types."""
    if isinstance(obj, dict):
        return {str(k): plain_data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [plain_data(v) for v in obj]
    if isinstance(obj, str):
        return str(obj)
    return obj


def _cfn_decode(path):
    """Decode a CFN template via cfn-lint, tolerant of the loader's return shape.

    Older cfn-lint returned `(template, matches)`; current versions return just
    the decorated template node. Handle both so the line-mark tier does not
    silently regress to the PyYAML fallback on a version bump.
    """
    loaded = cfn_json.load(path) if path.endswith('.json') else cfn_yaml.load(path)
    if isinstance(loaded, tuple):
        return loaded[0]
    return loaded


def _cfn_split_type(resource_type):
    parts = str(resource_type).split('::')
    provider = parts[0] if len(parts) > 0 else 'Unknown'
    service = parts[1] if len(parts) > 1 else 'Unknown'
    name = parts[2] if len(parts) > 2 else 'Unknown'
    return provider, service, name


def parse_cloudformation_with_cfnlint(path, root=None):
    """
    Parse CloudFormation using cfn-lint.
    Provides intrinsic function resolution and accurate dependency tracking, and
    — the reason this is the FULL tier — per-resource line provenance from
    cfn-lint's decoded line marks.

    ``root`` is what ``location.file`` is made relative to (the template itself
    for a single-file scan, the directory for a directory scan).
    """
    root = root or path
    try:
        template_node = _cfn_decode(path)

        if template_node is None:
            return {"error": "Failed to decode template"}

        # Per-logical-ID line ranges from cfn-lint's marks. If the marks are
        # absent the index is empty and this tier degrades to no line numbers,
        # surfaced via `degraded` below.
        line_index = cfn_resource_line_index(template_node.get('Resources', {}) or {})

        template_data = plain_data(template_node)
        if not isinstance(template_data, dict):
            return {"error": "Failed to decode template"}

        resources = []
        cfn_resources = template_data.get('Resources', {}) or {}
        parameters = template_data.get('Parameters', {}) or {}
        outputs = template_data.get('Outputs', {}) or {}
        conditions = template_data.get('Conditions', {}) or {}
        missing_provenance = []

        for logical_id, resource in cfn_resources.items():
            logical_id = str(logical_id)
            resource = resource if isinstance(resource, dict) else {}
            resource_type = str(resource.get('Type', 'Unknown'))
            properties = resource.get('Properties', {})
            provider, service, resource_name = _cfn_split_type(resource_type)
            condition = resource.get('Condition')

            start_line, end_line = line_index.get(logical_id, (None, None))
            if start_line is None or end_line is None:
                missing_provenance.append(logical_id)

            location = build_yaml_location(
                path, start_line, end_line, logical_id, resource_type, service,
                root=root,
            )

            resources.append({
                "logical_id": logical_id,
                "type": resource_type,
                "provider": provider,
                "service": service,
                "resource_name": resource_name,
                "file": path,
                "location": location,
                "properties": redact_secrets(properties),
                "condition": condition,
                "depends_on": resource.get('DependsOn', []),
                "metadata": redact_secrets(resource.get('Metadata', {})),
            })

        dependencies = extract_cfnlint_dependencies(cfn_resources, parameters)

        degraded = len(missing_provenance) == len(resources) and len(resources) > 0

        def _param(k, v):
            v = v if isinstance(v, dict) else {}
            return {
                "type": v.get('Type', 'String'),
                "default": REDACTED if v.get('NoEcho') is True and v.get('Default') not in (None, "")
                else redact_secrets(v.get('Default'), k),
                "description": v.get('Description'),
                "allowed_values": v.get('AllowedValues'),
            }

        def _output(v):
            v = v if isinstance(v, dict) else {}
            export = v.get('Export') or {}
            return {
                "value": v.get('Value'),
                "description": v.get('Description'),
                "export": export.get('Name') if isinstance(export, dict) else None,
            }

        return {
            "format": "cloudformation",
            "parser": "cfn-lint",
            "parseTier": "cfn-lint",
            "degraded": degraded,
            "degradationReason": (
                "cfn-lint decoded the template but carried no line marks, so "
                "findings cannot populate SARIF and cannot be auto-patched."
            ) if degraded else None,
            "lineProvenance": not degraded,
            "resources_with_line_provenance": len(resources) - len(missing_provenance),
            "resources_missing_line_provenance": missing_provenance,
            "resources": resources,
            "parameters": {k: _param(k, v) for k, v in parameters.items()},
            "outputs": {k: _output(v) for k, v in outputs.items()},
            "conditions": list(conditions.keys()) if isinstance(conditions, dict) else [],
            "total_resources": len(resources),
            "dependencies": dependencies,
        }

    except Exception as e:
        return {"error": f"cfn-lint parsing failed: {str(e)}"}


def extract_cfnlint_dependencies(resources, parameters):
    """
    Extract dependencies from CloudFormation resources using deep intrinsic function analysis.
    """
    dependencies = {}
    resource_ids = set(resources.keys())
    parameter_ids = set(parameters.keys()) if isinstance(parameters, dict) else set()

    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        deps = set()

        depends_on = resource.get('DependsOn', [])
        if isinstance(depends_on, str):
            deps.add(depends_on)
        elif isinstance(depends_on, list):
            deps.update(d for d in depends_on if isinstance(d, str))

        refs = extract_cloudformation_refs_deep(resource, resource_ids, parameter_ids)
        deps.update(refs)

        resource_deps = [d for d in deps if d in resource_ids]

        if resource_deps:
            dependencies[logical_id] = resource_deps

    return dependencies


def extract_cloudformation_refs_deep(obj, resource_ids, parameter_ids, refs=None):
    """
    Recursively extract Ref and GetAtt references from CloudFormation template.
    Handles all intrinsic function formats including short and long forms.
    """
    if refs is None:
        refs = set()

    if isinstance(obj, dict):
        if 'Ref' in obj:
            ref_value = obj['Ref']
            if isinstance(ref_value, str) and ref_value in resource_ids:
                refs.add(ref_value)

        elif 'Fn::GetAtt' in obj:
            get_att = obj['Fn::GetAtt']
            if isinstance(get_att, list) and len(get_att) > 0:
                if get_att[0] in resource_ids:
                    refs.add(get_att[0])
            elif isinstance(get_att, str):
                logical_id = get_att.split('.')[0]
                if logical_id in resource_ids:
                    refs.add(logical_id)

        elif 'Fn::Sub' in obj:
            sub_value = obj['Fn::Sub']
            if isinstance(sub_value, str):
                for match in re.finditer(r'\$\{([^}!]+?)(?:\.[^}]+)?\}', sub_value):
                    ref = match.group(1)
                    if ref in resource_ids:
                        refs.add(ref)
            elif isinstance(sub_value, list) and len(sub_value) >= 1:
                if isinstance(sub_value[0], str):
                    for match in re.finditer(r'\$\{([^}!]+?)(?:\.[^}]+)?\}', sub_value[0]):
                        ref = match.group(1)
                        if ref in resource_ids:
                            refs.add(ref)
                for item in sub_value[1:]:
                    extract_cloudformation_refs_deep(item, resource_ids, parameter_ids, refs)

        elif 'Fn::If' in obj:
            if_value = obj['Fn::If']
            if isinstance(if_value, list):
                for item in if_value[1:]:
                    extract_cloudformation_refs_deep(item, resource_ids, parameter_ids, refs)

        else:
            for key, value in obj.items():
                if isinstance(key, str) and key.startswith('!'):
                    continue
                extract_cloudformation_refs_deep(value, resource_ids, parameter_ids, refs)

    elif isinstance(obj, list):
        for item in obj:
            extract_cloudformation_refs_deep(item, resource_ids, parameter_ids, refs)

    return refs


def parse_cloudformation_with_yaml(path, root=None):
    """
    Parse CloudFormation using PyYAML (fallback).
    Basic parsing without intrinsic function resolution. DEGRADED: no line numbers.
    """
    _require_yaml()
    root = root or path
    try:
        with open(path, 'r') as f:
            if path.endswith('.json'):
                template = json.load(f)
            else:
                template = yaml.safe_load(f)

        if not isinstance(template, dict) or not isinstance(template.get('Resources'), dict):
            return {"error": f"Not a CloudFormation template (no Resources section): {path}"}

        resources = []
        parameters = template.get('Parameters', {}) or {}
        outputs = template.get('Outputs', {}) or {}
        cfn_resources = template.get('Resources', {})

        for logical_id, resource in cfn_resources.items():
            resource = resource if isinstance(resource, dict) else {}
            resource_type = resource.get('Type', 'Unknown')
            properties = resource.get('Properties', {})
            provider, service, _ = _cfn_split_type(resource_type)

            resources.append({
                "logical_id": logical_id,
                "type": resource_type,
                "provider": provider,
                "service": service,
                "file": path,
                # DEGRADED: PyYAML preserves no line numbers.
                "location": build_yaml_location(
                    path, None, None, logical_id, resource_type, service, root=root
                ),
                "properties": redact_secrets(properties),
                "depends_on": resource.get('DependsOn', [])
            })

        dependencies = {}
        resource_ids = set(cfn_resources.keys())
        parameter_ids = set(parameters.keys()) if isinstance(parameters, dict) else set()

        for logical_id, resource in cfn_resources.items():
            if not isinstance(resource, dict):
                continue
            deps = set()

            depends_on = resource.get('DependsOn', [])
            if isinstance(depends_on, str):
                deps.add(depends_on)
            elif isinstance(depends_on, list):
                deps.update(d for d in depends_on if isinstance(d, str))

            refs = extract_cloudformation_refs_deep(resource, resource_ids, parameter_ids)
            deps.update(refs)

            if deps:
                dependencies[logical_id] = list(deps)

        return {
            "format": "cloudformation",
            "parser": "yaml",
            "parseTier": "yaml",
            "degraded": True,
            "degradationReason": (
                "Fell back to PyYAML (cfn-lint unavailable or failed). This tier "
                "yields NO line numbers, so findings cannot populate SARIF and "
                "cannot be auto-patched. Intrinsic functions are not resolved."
            ),
            "lineProvenance": False,
            "resources": resources,
            "parameters": list(parameters.keys()) if parameters else [],
            "outputs": list(outputs.keys()) if outputs else [],
            "total_resources": len(resources),
            "resources_with_line_provenance": 0,
            "dependencies": dependencies
        }

    except Exception as e:
        return {"error": f"Failed to parse CloudFormation template: {str(e)}"}


def extract_cloudformation_refs(obj, refs=None):
    """Recursively extract Ref and GetAtt references from CloudFormation template."""
    if refs is None:
        refs = set()

    if isinstance(obj, dict):
        if 'Ref' in obj:
            ref_value = obj['Ref']
            if isinstance(ref_value, str) and not ref_value.startswith('AWS::'):
                refs.add(ref_value)
        elif 'Fn::GetAtt' in obj:
            get_att = obj['Fn::GetAtt']
            if isinstance(get_att, list) and len(get_att) > 0:
                refs.add(get_att[0])
            elif isinstance(get_att, str):
                refs.add(get_att.split('.')[0])
        else:
            for value in obj.values():
                extract_cloudformation_refs(value, refs)
    elif isinstance(obj, list):
        for item in obj:
            extract_cloudformation_refs(item, refs)

    return refs


# ===========================================================================
# Kubernetes
# ===========================================================================

def parse_kubernetes(path):
    """
    Parse Kubernetes manifests (YAML) with enhanced relationship detection.

    Identifies relationship types (inspired by KubeDiagrams):
    - REFERENCE: Direct resource references
    - SELECTOR: Label-based selection (Service -> Pod)
    - OWNER: Ownership hierarchies (Deployment -> ReplicaSet -> Pod)
    - COMMUNICATION: Network policies between pods
    - MOUNT: Volume/ConfigMap/Secret mounts

    ``kind: List`` documents are expanded. Documents without apiVersion/kind
    (Helm values, Kustomizations, stray templates) are skipped and counted.
    """
    _require_yaml()
    print(f"Parsing Kubernetes manifests in: {path}")

    if os.path.isfile(path):
        yaml_files = [path]
    else:
        yaml_files = file_glob.glob(os.path.join(path, "**/*.yaml"), recursive=True)
        yaml_files.extend(file_glob.glob(os.path.join(path, "**/*.yml"), recursive=True))

    if not yaml_files:
        return {"error": "No Kubernetes manifest files found", "resources": []}

    resources = []
    skipped = 0
    unreadable = []
    # ruamel gives per-document line provenance; PyYAML (below) gives the data.
    # If ruamel is unavailable, no line index -> a DEGRADED scan (no SARIF/patches).
    any_line_index = RUAMEL_AVAILABLE
    missing_provenance = []

    for yaml_file in sorted(set(yaml_files)):
        print(f"  Reading: {yaml_file}")
        line_index = kubernetes_line_index(yaml_file)
        if line_index is None:
            any_line_index = False
            line_index = {}
        try:
            with open(yaml_file, 'r') as f:
                documents = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"  Warning: Error reading {yaml_file}: {e}")
            unreadable.append(yaml_file)
            continue

        for doc in iter_kubernetes_documents(documents):
            if not is_kubernetes_object(doc):
                skipped += 1
                continue

            kind = doc['kind']
            if kind == 'Kustomization':
                skipped += 1
                continue

            api_version = doc['apiVersion']
            metadata = doc.get('metadata') or {}
            spec = doc.get('spec') or {}

            name = metadata.get('name', 'unnamed')
            namespace = metadata.get('namespace', 'default')
            labels = metadata.get('labels') or {}
            annotations = metadata.get('annotations') or {}
            owner_refs = metadata.get('ownerReferences', [])

            start_line, end_line = line_index.get(
                (str(kind), str(name)), (None, None)
            )
            address = f"{kind}/{name}"
            if start_line is None:
                missing_provenance.append(address)

            resource = {
                "kind": kind,
                "apiVersion": api_version,
                "name": name,
                "namespace": namespace,
                "labels": labels,
                "annotations": annotations,
                "owner_references": owner_refs,
                "file": yaml_file,
                "location": build_yaml_location(
                    yaml_file, start_line, end_line, address, kind,
                    "kubernetes", root=path,
                ),
                "spec": redact_secrets(spec),  # Keep full spec for relationship analysis
            }

            resource.update(extract_kubernetes_kind_fields(kind, spec, metadata, doc))

            resources.append(resource)

    if not resources:
        return {
            "error": f"No Kubernetes objects found under {path} "
                     f"({skipped} YAML document(s) without apiVersion/kind skipped, "
                     f"{len(unreadable)} file(s) unreadable)",
            "resources": [],
        }
    if skipped:
        print(f"  Skipped {skipped} YAML document(s) that are not Kubernetes objects")

    relationships = extract_kubernetes_relationships_enhanced(resources)

    by_namespace = {}
    by_kind = {}
    for r in resources:
        ns = r["namespace"]
        kind = r["kind"]
        by_namespace.setdefault(ns, []).append(f"{kind}/{r['name']}")
        by_kind.setdefault(kind, []).append(r["name"])

    degraded = not any_line_index
    return {
        "format": "kubernetes",
        "parser": "ruamel" if any_line_index else "yaml",
        "parseTier": "ruamel" if any_line_index else "yaml",
        "degraded": degraded,
        "degradationReason": (
            "ruamel.yaml is unavailable, so Kubernetes manifests were parsed "
            "without line numbers. Findings cannot populate SARIF and cannot be "
            "auto-patched. Install it with: pip install ruamel.yaml"
        ) if degraded else None,
        "lineProvenance": not degraded,
        "resources_with_line_provenance": len(resources) - len(missing_provenance),
        "resources_missing_line_provenance": missing_provenance,
        "resources": resources,
        "total_resources": len(resources),
        "namespaces": list(set(r["namespace"] for r in resources)),
        "by_namespace": by_namespace,
        "by_kind": by_kind,
        "relationships": relationships,
        "dependencies": convert_relationships_to_dependencies(relationships),
        "skipped_documents": skipped,
        "unreadable_files": unreadable,
    }


def is_kubernetes_object(doc):
    """A Kubernetes object has both apiVersion and kind."""
    return isinstance(doc, dict) and bool(doc.get('apiVersion')) and bool(doc.get('kind'))


def iter_kubernetes_documents(documents):
    """Yield documents, expanding `kind: List` into its items."""
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        if doc.get('kind') == 'List' and isinstance(doc.get('items'), list):
            for item in doc['items']:
                if isinstance(item, dict):
                    yield item
            continue
        yield doc


def extract_kubernetes_kind_fields(kind, spec, metadata, doc=None):
    """Extract kind-specific fields for Kubernetes resources.

    `doc` is the full manifest document; some fields (ConfigMap `data`,
    Secret `data`/`type`) live at the document top level, not under spec
    or metadata.
    """
    fields = {}
    if doc is None:
        doc = {}
    spec = spec or {}

    if kind == 'Service':
        fields["selector"] = spec.get('selector', {})
        fields["ports"] = spec.get('ports', [])
        fields["type"] = spec.get('type', 'ClusterIP')
        fields["cluster_ip"] = spec.get('clusterIP')

    elif kind in ('Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet'):
        fields["replicas"] = spec.get('replicas', 1)
        fields["selector"] = spec.get('selector', {})
        template = spec.get('template') or {}
        template_metadata = template.get('metadata') or {}
        fields["pod_labels"] = template_metadata.get('labels') or {}
        pod_spec = template.get('spec') or {}
        containers = pod_spec.get('containers') or []
        fields["containers"] = [{
            "name": c.get('name'),
            "image": c.get('image'),
            "ports": c.get('ports', []),
        } for c in containers if isinstance(c, dict)]
        fields["volume_claims"] = spec.get('volumeClaimTemplates', [])

    elif kind == 'Ingress':
        fields["rules"] = spec.get('rules', [])
        fields["tls"] = spec.get('tls', [])
        fields["ingress_class"] = spec.get('ingressClassName')

    elif kind == 'ConfigMap':
        data_keys = list((doc.get('data') or {}).keys())
        data_keys += list((doc.get('binaryData') or {}).keys())
        fields["data_keys"] = data_keys

    elif kind == 'Secret':
        fields["type"] = doc.get('type', 'Opaque')
        data_keys = list((doc.get('data') or {}).keys())
        data_keys += list((doc.get('stringData') or {}).keys())
        fields["data_keys"] = data_keys

    elif kind == 'PersistentVolumeClaim':
        fields["storage_class"] = spec.get('storageClassName')
        fields["access_modes"] = spec.get('accessModes', [])
        requests = (spec.get('resources') or {}).get('requests') or {}
        fields["storage"] = requests.get('storage')

    elif kind == 'PersistentVolume':
        fields["storage_class"] = spec.get('storageClassName')
        fields["capacity"] = (spec.get('capacity') or {}).get('storage')
        fields["access_modes"] = spec.get('accessModes', [])

    elif kind == 'NetworkPolicy':
        fields["pod_selector"] = spec.get('podSelector', {})
        fields["ingress_rules"] = spec.get('ingress', [])
        fields["egress_rules"] = spec.get('egress', [])
        fields["policy_types"] = spec.get('policyTypes', [])

    elif kind == 'ServiceAccount':
        fields["secrets"] = spec.get('secrets', []) if spec else []

    elif kind == 'Role' or kind == 'ClusterRole':
        fields["rules"] = spec.get('rules', []) if spec else []

    elif kind == 'RoleBinding' or kind == 'ClusterRoleBinding':
        fields["role_ref"] = spec.get('roleRef', {}) if spec else {}
        fields["subjects"] = spec.get('subjects', []) if spec else []

    elif kind == 'Job':
        fields["completions"] = spec.get('completions', 1)
        fields["parallelism"] = spec.get('parallelism', 1)
        pod_spec = (spec.get('template') or {}).get('spec') or {}
        containers = pod_spec.get('containers') or []
        fields["containers"] = [{"name": c.get('name'), "image": c.get('image')}
                                for c in containers if isinstance(c, dict)]

    elif kind == 'CronJob':
        fields["schedule"] = spec.get('schedule')
        job_spec = (spec.get('jobTemplate') or {}).get('spec') or {}
        pod_spec = (job_spec.get('template') or {}).get('spec') or {}
        containers = pod_spec.get('containers') or []
        fields["containers"] = [{"name": c.get('name'), "image": c.get('image')}
                                for c in containers if isinstance(c, dict)]

    return fields


def extract_kubernetes_relationships_enhanced(resources):
    """
    Extract relationships between Kubernetes resources using enhanced detection.

    Relationship types:
    - SELECTOR: Label-based selection (Service -> Pods)
    - OWNER: Ownership hierarchy (Deployment -> ReplicaSet -> Pod)
    - REFERENCE: Direct resource references (Ingress -> Service, env/envFrom,
      serviceAccountName, RBAC)
    - COMMUNICATION: Network policies
    - MOUNT: Volume/ConfigMap/Secret mounts
    """
    relationships = []

    by_kind_namespace = {}  # {(kind, namespace): [resources]}

    for resource in resources:
        key = (resource["kind"], resource["namespace"])
        by_kind_namespace.setdefault(key, []).append(resource)

    for resource in resources:
        kind = resource["kind"]
        name = resource["name"]
        namespace = resource["namespace"]
        spec = resource.get("spec") or {}

        # === SELECTOR relationships ===
        if kind == "Service":
            selector = resource.get("selector", {})
            if selector:
                matching_pods = find_resources_by_selector(
                    selector, namespace, ["Pod", "Deployment", "StatefulSet", "DaemonSet"],
                    by_kind_namespace, resources
                )
                for target in matching_pods:
                    relationships.append({
                        "from": f"Service/{name}",
                        "to": f"{target['kind']}/{target['name']}",
                        "type": "SELECTOR",
                        "namespace": namespace,
                        "selector": selector,
                    })

        # === OWNER relationships ===
        if kind in ("Deployment", "StatefulSet", "DaemonSet"):
            relationships.append({
                "from": f"{kind}/{name}",
                "to": f"Pod/{name}-*",
                "type": "OWNER",
                "namespace": namespace,
                "description": f"{kind} manages Pod replicas",
            })

        if kind == "CronJob":
            relationships.append({
                "from": f"CronJob/{name}",
                "to": f"Job/{name}-*",
                "type": "OWNER",
                "namespace": namespace,
            })

        # === REFERENCE relationships ===
        if kind == "Ingress":
            for rule in resource.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                host = rule.get("host", "*")
                http = rule.get("http") or {}
                for path_config in http.get("paths") or []:
                    if not isinstance(path_config, dict):
                        continue
                    backend = path_config.get("backend") or {}
                    service_name = None
                    service_port = None

                    if "serviceName" in backend:  # networking.k8s.io/v1beta1
                        service_name = backend["serviceName"]
                        service_port = backend.get("servicePort")
                    elif "service" in backend:  # networking.k8s.io/v1
                        service = backend.get("service") or {}
                        service_name = service.get("name")
                        port_info = service.get("port") or {}
                        service_port = port_info.get("number") or port_info.get("name")

                    if service_name:
                        relationships.append({
                            "from": f"Ingress/{name}",
                            "to": f"Service/{service_name}",
                            "type": "REFERENCE",
                            "namespace": namespace,
                            "host": host,
                            "path": path_config.get("path", "/"),
                            "port": service_port,
                        })

        if kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = resource.get("role_ref") or {}
            if role_ref:
                role_kind = role_ref.get("kind", "Role")
                role_name = role_ref.get("name")
                if role_name:
                    relationships.append({
                        "from": f"{kind}/{name}",
                        "to": f"{role_kind}/{role_name}",
                        "type": "REFERENCE",
                        "namespace": namespace if kind == "RoleBinding" else "cluster",
                    })

            for subject in resource.get("subjects") or []:
                if not isinstance(subject, dict):
                    continue
                subj_kind = subject.get("kind")
                subj_name = subject.get("name")
                subj_ns = subject.get("namespace", namespace)
                if subj_kind and subj_name:
                    relationships.append({
                        "from": f"{kind}/{name}",
                        "to": f"{subj_kind}/{subj_name}",
                        "type": "REFERENCE",
                        "namespace": subj_ns,
                        "description": "grants permissions to",
                    })

        # === MOUNT / env REFERENCE relationships (ConfigMap, Secret, PVC, SA) ===
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod", "Job", "CronJob"):
            pod_spec = kubernetes_pod_spec(kind, spec)
            volumes = pod_spec.get("volumes") or []

            for target, via in kubernetes_env_references(pod_spec):
                relationships.append({
                    "from": f"{kind}/{name}",
                    "to": target,
                    "type": "REFERENCE",
                    "namespace": namespace,
                    "via": via,
                })

            sa_name = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
            if sa_name and sa_name != "default":
                relationships.append({
                    "from": f"{kind}/{name}",
                    "to": f"ServiceAccount/{sa_name}",
                    "type": "REFERENCE",
                    "namespace": namespace,
                    "via": "serviceAccountName",
                })

            for volume in volumes:
                if not isinstance(volume, dict):
                    continue
                vol_name = volume.get("name")

                if isinstance(volume.get("configMap"), dict):
                    cm_name = volume["configMap"].get("name")
                    if cm_name:
                        relationships.append({
                            "from": f"{kind}/{name}",
                            "to": f"ConfigMap/{cm_name}",
                            "type": "MOUNT",
                            "namespace": namespace,
                            "volume": vol_name,
                        })

                if isinstance(volume.get("secret"), dict):
                    secret_name = volume["secret"].get("secretName")
                    if secret_name:
                        relationships.append({
                            "from": f"{kind}/{name}",
                            "to": f"Secret/{secret_name}",
                            "type": "MOUNT",
                            "namespace": namespace,
                            "volume": vol_name,
                        })

                if isinstance(volume.get("persistentVolumeClaim"), dict):
                    pvc_name = volume["persistentVolumeClaim"].get("claimName")
                    if pvc_name:
                        relationships.append({
                            "from": f"{kind}/{name}",
                            "to": f"PersistentVolumeClaim/{pvc_name}",
                            "type": "MOUNT",
                            "namespace": namespace,
                            "volume": vol_name,
                        })

        # === COMMUNICATION relationships (NetworkPolicy) ===
        if kind == "NetworkPolicy":
            pod_selector = resource.get("pod_selector", {})
            ingress_rules = resource.get("ingress_rules") or []
            egress_rules = resource.get("egress_rules") or []

            relationships.append({
                "from": f"NetworkPolicy/{name}",
                "to": f"Pods matching {pod_selector}",
                "type": "COMMUNICATION",
                "namespace": namespace,
                "description": "applies network rules to",
            })

            for rule in ingress_rules:
                if not isinstance(rule, dict):
                    continue
                for from_sel in rule.get("from") or []:
                    if isinstance(from_sel, dict) and "podSelector" in from_sel:
                        relationships.append({
                            "from": f"Pods matching {from_sel['podSelector']}",
                            "to": f"Pods matching {pod_selector}",
                            "type": "COMMUNICATION",
                            "namespace": namespace,
                            "direction": "ingress",
                        })

            for rule in egress_rules:
                if not isinstance(rule, dict):
                    continue
                for to_sel in rule.get("to") or []:
                    if isinstance(to_sel, dict) and "podSelector" in to_sel:
                        relationships.append({
                            "from": f"Pods matching {pod_selector}",
                            "to": f"Pods matching {to_sel['podSelector']}",
                            "type": "COMMUNICATION",
                            "namespace": namespace,
                            "direction": "egress",
                        })

    return relationships


def kubernetes_pod_spec(kind, spec):
    """Return the pod spec for a workload kind (Pod, template kinds, CronJob)."""
    spec = spec or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        return (job_spec.get("template") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def kubernetes_env_references(pod_spec):
    """
    Yield (target, via) for ConfigMaps and Secrets consumed through
    containers[].envFrom, containers[].env[].valueFrom, and initContainers.
    """
    seen = set()
    containers = (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or [])
    for container in containers:
        if not isinstance(container, dict):
            continue
        for source in container.get("envFrom") or []:
            if not isinstance(source, dict):
                continue
            cm = (source.get("configMapRef") or {}).get("name")
            secret = (source.get("secretRef") or {}).get("name")
            if cm:
                seen.add((f"ConfigMap/{cm}", "envFrom"))
            if secret:
                seen.add((f"Secret/{secret}", "envFrom"))
        for env in container.get("env") or []:
            if not isinstance(env, dict):
                continue
            value_from = env.get("valueFrom") or {}
            cm = (value_from.get("configMapKeyRef") or {}).get("name")
            secret = (value_from.get("secretKeyRef") or {}).get("name")
            if cm:
                seen.add((f"ConfigMap/{cm}", "configMapKeyRef"))
            if secret:
                seen.add((f"Secret/{secret}", "secretKeyRef"))
    return sorted(seen)


def find_resources_by_selector(selector, namespace, target_kinds, by_kind_namespace, all_resources):
    """Find resources that match a label selector."""
    matching = []

    for target_kind in target_kinds:
        key = (target_kind, namespace)
        candidates = by_kind_namespace.get(key, [])

        for candidate in candidates:
            if target_kind in ("Deployment", "StatefulSet", "DaemonSet"):
                labels_to_check = candidate.get("pod_labels", {})
            else:
                labels_to_check = candidate.get("labels", {})

            if selector and labels_to_check:
                match = all(
                    labels_to_check.get(k) == v
                    for k, v in selector.items()
                )
                if match:
                    matching.append(candidate)

    return matching


def convert_relationships_to_dependencies(relationships):
    """Convert relationships list to a dependencies dict for diagram generation."""
    dependencies = {}

    for rel in relationships:
        from_resource = rel["from"]
        to_resource = rel["to"]

        if from_resource not in dependencies:
            dependencies[from_resource] = []

        # Only add concrete resource references (not wildcards), once each
        if "*" not in to_resource and "matching" not in to_resource \
                and to_resource not in dependencies[from_resource]:
            dependencies[from_resource].append(to_resource)

    return dependencies


# ===========================================================================
# Docker Compose
# ===========================================================================

COMPOSE_FILE_NAMES = ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')


def find_compose_files(path):
    """Return Compose files under `path` (or [path] when it is a file)."""
    if os.path.isfile(path):
        return [path]
    found = []
    for name in COMPOSE_FILE_NAMES:
        found.extend(file_glob.glob(os.path.join(path, f"**/{name}"), recursive=True))
    return sorted(set(found))


def parse_docker_compose(path):
    """Parse Docker Compose file(s) (YAML). Accepts a file or a directory.

    A file parses exactly as before. For a directory every Compose file found
    is parsed with ``location.file`` relative to the directory; several files
    are merged into one result (``files`` lists them, each service carries
    ``file``)."""
    if os.path.isfile(path):
        return parse_docker_compose_file(path, root=path)

    compose_files = find_compose_files(path)
    if not compose_files:
        return {"error": f"No Compose files found under {path} "
                         f"(looked for {', '.join(COMPOSE_FILE_NAMES)})"}

    results = []
    errors = []
    for compose_file in compose_files:
        result = parse_docker_compose_file(compose_file, root=path)
        if "error" in result:
            if len(compose_files) == 1:
                return result
            print(f"  Warning: {result['error']}")
            errors.append(result["error"])
            continue
        result["file"] = compose_file
        results.append(result)

    if not results:
        return {"error": f"None of the {len(compose_files)} Compose file(s) under {path} could be parsed: "
                         + "; ".join(errors)}

    if len(results) == 1:
        single = results[0]
        single["files"] = [single["file"]]
        return single

    merged = dict(results[0])
    merged["files"] = [r["file"] for r in results]
    merged.pop("file", None)
    merged["services"] = []
    merged["dependencies"] = {}
    merged["resources_with_line_provenance"] = 0
    merged["resources_missing_line_provenance"] = []
    degraded_reasons = []
    for r in results:
        for service in r.get("services", []):
            merged["services"].append(dict(service, file=r["file"]))
        for k, v in r.get("dependencies", {}).items():
            if k in merged["dependencies"]:
                print(f"  Warning: service '{k}' is defined in more than one Compose file; dependencies merged")
                old = merged["dependencies"][k]
                merged["dependencies"][k] = {
                    "depends_on": sorted(set(old.get("depends_on", [])) | set(v.get("depends_on", []))),
                    "networks": sorted(set(old.get("networks", [])) | set(v.get("networks", []))),
                }
            else:
                merged["dependencies"][k] = v
        merged["resources_with_line_provenance"] += r.get("resources_with_line_provenance", 0)
        merged["resources_missing_line_provenance"].extend(r.get("resources_missing_line_provenance") or [])
        if r.get("degraded"):
            degraded_reasons.append("%s: %s" % (r["file"], r.get("degradationReason") or "degraded parse"))
    merged["networks"] = sorted({n for r in results for n in r.get("networks", [])})
    merged["volumes"] = sorted({v for r in results for v in r.get("volumes", [])})
    merged["total_services"] = len(merged["services"])
    if degraded_reasons:
        merged["parser"] = "yaml"
        merged["parseTier"] = "yaml"
        merged["degraded"] = True
        merged["lineProvenance"] = False
        merged["degradationReason"] = "; ".join(degraded_reasons)
    return merged


def parse_docker_compose_file(path, root=None):
    """Parse one Docker Compose file (YAML)."""
    _require_yaml()
    print(f"Parsing Docker Compose file: {path}")
    root = root or path

    try:
        with open(path, 'r') as f:
            compose = yaml.safe_load(f)

        if not isinstance(compose, dict) or not isinstance(compose.get('services'), dict):
            return {"error": f"Not a Compose file (no services section): {path}"}

        services = compose.get('services', {})
        networks = compose.get('networks') or {}
        volumes = compose.get('volumes') or {}

        # ruamel supplies per-service line provenance; None -> DEGRADED scan.
        line_index = compose_line_index(path)
        any_line_index = line_index is not None
        if line_index is None:
            line_index = {}
        missing_provenance = []

        service_list = []
        dependencies = {}

        for service_name, service_config in services.items():
            service_config = service_config if isinstance(service_config, dict) else {}
            depends_on = service_config.get('depends_on', [])

            # depends_on can be a list or a dict
            if isinstance(depends_on, dict):
                depends_on = list(depends_on.keys())

            service_networks = service_config.get('networks', [])
            if isinstance(service_networks, dict):
                service_networks = list(service_networks.keys())

            service_volumes = service_config.get('volumes', [])

            start_line, end_line = line_index.get(str(service_name), (None, None))
            if start_line is None:
                missing_provenance.append(service_name)

            service_list.append({
                "name": service_name,
                "image": service_config.get('image'),
                "build": service_config.get('build'),
                "ports": service_config.get('ports', []),
                "environment": redact_secrets(service_config.get('environment', {})),
                "networks": service_networks,
                "volumes": service_volumes,
                "location": build_yaml_location(
                    path, start_line, end_line, service_name, "service",
                    "docker-compose", root=root,
                ),
            })

            dependencies[service_name] = {
                "depends_on": depends_on,
                "networks": service_networks
            }

        degraded = not any_line_index
        return {
            "format": "docker-compose",
            "parser": "ruamel" if any_line_index else "yaml",
            "parseTier": "ruamel" if any_line_index else "yaml",
            "degraded": degraded,
            "degradationReason": (
                "ruamel.yaml is unavailable, so the Compose file was parsed "
                "without line numbers. Findings cannot populate SARIF and cannot "
                "be auto-patched. Install it with: pip install ruamel.yaml"
            ) if degraded else None,
            "lineProvenance": not degraded,
            "resources_with_line_provenance": len(service_list) - len(missing_provenance),
            "resources_missing_line_provenance": missing_provenance,
            "services": service_list,
            "networks": list(networks.keys()) if isinstance(networks, dict) else [],
            "volumes": list(volumes.keys()) if isinstance(volumes, dict) else [],
            "total_services": len(service_list),
            "dependencies": dependencies
        }

    except Exception as e:
        return {"error": f"Failed to parse Docker Compose file: {str(e)}"}


# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="parse_iac.py",
        description="Parse IaC files into a JSON resource graph.",
        epilog=(
            "Supported formats:\n"
            "  terraform       - Parse Terraform .tf files\n"
            "  cloudformation  - Parse CloudFormation templates (.yaml, .json)\n"
            "  kubernetes      - Parse Kubernetes manifests (.yaml)\n"
            "  docker-compose  - Parse Docker Compose files\n\n"
            "Path can be a local file or directory, or a GitHub URL such as\n"
            "  https://github.com/user/repo\n"
            "  https://github.com/user/repo/tree/<branch>/<subdir>\n"
            "  https://github.com/user/repo/blob/<branch>/<file>\n"
            "  github.com/user/repo, git@github.com:user/repo"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("format", nargs="?",
                        help="terraform | cloudformation | kubernetes | docker-compose")
    parser.add_argument("path", nargs="?", help="Local path or GitHub URL")
    parser.add_argument(
        "--json-only", action="store_true",
        help="Emit ONLY the JSON document on stdout; progress goes to stderr.",
    )
    parser.add_argument(
        "--data-dir", default=None, metavar="DIR",
        help="Plugin data directory for the managed Python environment "
             "(the diagram skill passes ${CLAUDE_PLUGIN_DATA}).",
    )
    parser.add_argument(
        "--install-optional", action="store_true",
        help="Install the optional parser tiers (python-hcl2, tfparse, cfn-lint) "
             "into the managed environment and exit.",
    )
    return parser, parser.parse_args(argv)


def parse_for_format(iac_format, path):
    """Route to the parser for ``iac_format``. Returns None for an unknown format."""
    if iac_format == "terraform":
        return parse_terraform(path)
    elif iac_format == "cloudformation":
        return parse_cloudformation(path)
    elif iac_format == "kubernetes":
        return parse_kubernetes(path)
    elif iac_format == "docker-compose":
        return parse_docker_compose(path)
    return None


def resource_count(result):
    """Number of top-level items the output describes."""
    return len(result.get("resources") or result.get("services") or [])


def main(argv=None, dispatch=None):
    """Main entry point for the IaC parser.

    ``dispatch(iac_format, path)`` lets a shim route formats itself; the default
    is ``parse_for_format``.
    """
    parser, args = parse_args(argv)
    _require_yaml()

    if not args.format or not args.path:
        print("ERROR: Missing required arguments.\n", file=sys.stderr)
        parser.print_help(sys.stderr)
        sys.exit(1)

    json_only = args.json_only
    iac_format = args.format.lower()
    path = args.path

    if iac_format not in SUPPORTED_FORMATS:
        print(f"ERROR: Unsupported format: {iac_format}")
        print("Supported formats: " + ", ".join(SUPPORTED_FORMATS))
        sys.exit(1)

    if json_only:
        # Keep stdout a clean JSON channel; progress chatter goes to stderr.
        sys.stdout = sys.stderr

    temp_dir = None

    try:
        if is_github_url(path):
            if path.startswith('git@'):
                base_url, ref, subpath = path, None, None
            else:
                base_url, ref, subpath = extract_github_subpath(
                    path if path.startswith('http') else 'https://' + path)

            temp_dir, path = clone_repository(base_url, ref, subpath)
            if not path:
                sys.exit(1)
        else:
            if not os.path.exists(path):
                print(f"ERROR: Path does not exist: {path}")
                sys.exit(1)

        result = (dispatch or parse_for_format)(iac_format, path)
        if result is None:
            print(f"ERROR: Unsupported format: {iac_format}")
            print("Supported formats: " + ", ".join(SUPPORTED_FORMATS))
            sys.exit(1)

        # A degraded scan must never look like a clean one.
        if result.get("degraded"):
            print("\n" + "!" * 60)
            print("DEGRADED SCAN — parser tier: " + str(result.get("parseTier")))
            print(result.get("degradationReason", ""))
            print("!" * 60)

        if "error" not in result and resource_count(result) == 0:
            result["warning"] = "Parsed successfully but found zero resources"
            print(f"\nWARNING: {result['warning']}. Check the format and path.")

        if json_only:
            print(json.dumps(result, indent=2, default=str), file=sys.__stdout__)
        else:
            print("\n" + "=" * 60)
            print("PARSE RESULT:")
            print("=" * 60)
            print(json.dumps(result, indent=2, default=str))

        if "error" in result:
            sys.exit(1)

    finally:
        if temp_dir:
            cleanup_temp_dir(temp_dir)
        sys.stdout = sys.__stdout__


if __name__ == "__main__":
    main()
