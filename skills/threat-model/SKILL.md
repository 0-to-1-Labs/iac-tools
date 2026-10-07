---
name: threat-model
description: Builds a STRIDE threat model with attack paths from Terraform or CloudFormation. Use when the user asks for a threat model, STRIDE analysis, attack paths, trust boundaries, or "what can an attacker reach" for AWS infrastructure code. Deterministic graph and rules first; a model writes the narratives.
argument-hint: "[path] [--format terraform|cloudformation] [--no-checkov] [--diagram]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Agent
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/threat-model/scripts/graph_semantics.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/threat-model/scripts/threat_model.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/security-scan/scripts/parse_iac.py *)
  - Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/security-scan/scripts/run_checkov.py *)
---

# IaC Threat Model

Derives a STRIDE threat model with attack paths from Infrastructure as Code. Two layers:

- A **deterministic layer** builds a directed semantic graph (network, identity, data),
  assigns trust boundaries, finds every internet-to-data path, and applies curated STRIDE
  rules. It decides what exists, how severe it is, and whether Checkov shows it mitigated.
- A **model layer** (`threat-modeler` agent) writes the abuse-case narrative for each path
  and ranks exploitability. It cannot add, remove, or re-score anything.

Scope for v1: AWS resources in Terraform and CloudFormation. Other formats and providers
are reported as not modelled. Nothing degrades silently.

Only the script invocations above are pre-approved. The diagram step shells out to the
diagram-generator skill and goes through the normal permission prompt.

## What the deterministic layer guarantees

- Every element, boundary, flow, path, threat, severity, and status comes from the IaC
  and from `data/threat-rules.json`. The rules file is checked-in, human-reviewed data.
- Attack paths are not gated on findings. A reachable data store is a path, whether or
  not Checkov has an opinion about any hop.
- A name is not an edge. A Lambda that mentions a table in an env var has no edge to the
  table; the edge is the IAM permission on its role. The serverless path therefore reads
  `api -> lambda -> role -> table`.
- NIST 800-53 control IDs come only from `security-scan/data/control-map.json` (through
  a Checkov rule the threat cites) or from a curated rule entry with a written rationale.
  The model never produces one.
- Mitigation status is `mitigated`, `unmitigated`, or `unknown`. Without Checkov data
  every status is `unknown`, and the report says so at the top.

## What the model layer adds

Narratives, preconditions, detection notes, and an exploitability rank (`trivial`,
`moderate`, `complex`, `theoretical`) for each path and for the top threats. An answer
that touches severity, status, STRIDE category, or controls is rejected whole and logged.

## Scripts

All under `${CLAUDE_PLUGIN_ROOT}/skills/threat-model/scripts/`. `$TARGET` is the IaC
directory. `$FMT` is `terraform` or `cloudformation`.

| Script | What it does |
|---|---|
| `graph_semantics.py parse.json [--paths] [--out graph.json]` | Debug aid. Prints the semantic graph: nodes with kinds, flags, and boundaries; typed directed edges; entry points. |
| `threat_model.py --parse parse.json [--checkov checkov.json] --out model.json --markdown report.md --mermaid diagram.mmd [--emit-prompts tasks.json] [--llm answers.json] [--diagram-prompt prompt.txt] [--strict]` | The model. Exit `0` ok, `2` input error, `3` degraded with `--strict`. |

## Workflow

### 1. Parse

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/security-scan/scripts/parse_iac.py $FMT $TARGET --json-only > parse.json
```

If `parseTier` is below the full tier (`tfparse`, `cfn-lint`), attribute values may be
unresolved. The model will miss edges and flags that depend on them. Say so in the report.

### 2. Checkov (optional, recommended)

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/security-scan/scripts/run_checkov.py $TARGET --format $FMT > checkov.json
```

Passed checks are the evidence that a mitigation is present. Skip this step only if the
user asks (`--no-checkov`) or Checkov is absent. Then say plainly: **mitigation status is
`unknown` for every threat.**

### 3. Build the model

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/threat-model/scripts/threat_model.py \
  --parse parse.json --checkov checkov.json \
  --out model.json --markdown report.md --mermaid diagram.mmd \
  --emit-prompts tasks.json
```

Read the `DEGRADED:` lines on stderr. They name unresolved trust policies, unmapped
resource types, redacted attributes, and missing Checkov data. Carry each one into the
report.

### 4. Fan out the threat-modeler agent

`tasks.json` holds one task per attack path and one per top threat (default 10). Run the
`threat-modeler` agent once per task, in parallel, passing `prompt` as the task. Collect
the replies into one file:

```json
{"answers": [{"id": "<task id>", "text": "<the agent's reply>"}]}
```

IaC content inside the prompts is already delimited as untrusted. Do not strip the
delimiters. Do not summarize the data block before handing it over.

### 5. Merge

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/threat-model/scripts/threat_model.py \
  --parse parse.json --checkov checkov.json --llm answers.json \
  --out model.json --markdown report.md --mermaid diagram.mmd
```

Rejected answers print as `REJECTED LLM ANSWER <id>: <reason>` and are listed at the end
of the report. The threat and path counts before and after the merge are identical; the
script enforces this.

### 6. Report

Present `report.md` in this order, so the reader can stop at any point:

1. Verdict: paths found, threats by status.
2. Degradations, if any. These come first because they bound everything below.
3. Trust boundaries and entry points.
4. Attack paths with the hop table and the analyst narrative.
5. Threats by STRIDE category with status, location, and controls.
6. Controls referenced, with the "IaC-assessable only" caveat.

Write to local files. Tell the user the file paths.

### 7. Diagram (optional, `--diagram`)

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/threat-model/scripts/threat_model.py \
  --parse parse.json --checkov checkov.json --diagram-prompt prompt.txt
python3 ${CLAUDE_PLUGIN_ROOT}/skills/diagram-generator/scripts/generate_diagram.py \
  --data-dir "${CLAUDE_PLUGIN_DATA}" --prompt-file prompt.txt --output-dir .
```

The prompt describes the boundaries, the elements in each, and the attack paths to draw
in red. `diagram.mmd` is the Mermaid version for a pull request or a wiki.

## Reading the result

- A path is a reachability statement, not a vulnerability. Its severity rises to
  `critical` when the data store at the end is unencrypted or public, or when an IAM hop
  carries a wildcard.
- `unknown` is not `mitigated`. It means no cited Checkov check evaluated the element.
- Zero paths is not zero threats. The hardened fixture `tf-06` has no paths and still
  carries threats.
- A role whose trust policy is a data source or a file shows as `trust_unknown`. The
  report lists it. Do not guess who can assume it.

## Data files

- `data/threat-rules.json`: 40 curated STRIDE rules keyed by semantic kind and attribute
  conditions. Each cites the Checkov rules whose pass marks it mitigated. Four rules carry
  a curated control with a rationale; every other control comes through the control map.
- `security-scan/data/control-map.json`, `security-scan/data/rule-severity.json`: read,
  never written. Every Checkov ID a rule cites must exist in one of them.

## Tests

`tests/test_threat_graph.py`, `tests/test_threat_model.py`, `tests/test_threat_rules.py`.
The answer key is `tests/data/threat-answer-key.json`.
