# Changelog

## 2.0.0 (2026-10-06)

iac-tools replaces two plugins. Both old names are mapped to `iac-tools` in the
0-to-1-labs marketplace `renames` map, so `/plugin marketplace update` followed
by `/plugin install iac-tools@0-to-1-labs` completes the move.

### Added
- `threat-model` skill: STRIDE threats and internet-to-data attack paths derived
  from the IaC resource graph. Directed network and IAM edges, trust boundaries,
  mitigation status from Checkov pass and fail results, NIST 800-53 controls
  through the curated control map only. Markdown, JSON, and Mermaid output, plus
  a rendering prompt for `diagram-generator`.
- `threat-modeler` agent for abuse-case narratives. It cannot add, remove, or
  re-score a threat.
- One shared parser in `lib/iac_tools/parse_iac.py`. Line provenance and
  CloudFormation directory scanning from the scanner, secret redaction, data
  sources, hcl2 8.x and tfparse metadata handling, and GitHub ref handling from
  the diagram generator.
- `CONTRIBUTING.md` with the layout and the rules for adding a skill.

### Changed
- `iac-security-scan` is now `iac-tools:security-scan`. The separate `/iac-scan`
  command is gone; the skill takes the same arguments.
- `iac-diagram-generator` is now `iac-tools:diagram-generator`. Adds `--lite`
  (Nano Banana 2 Lite) alongside `--fast`.
- Agents renamed: `security-analyst`, `remediation-engineer`.
- Checkov floor moved from `==3.2.500` to `>=3.3.25`. The corpus is re-graded
  against 3.3.25. New rules carry proposed severity seeds marked for review and
  are `unmapped` in the control map until a human maps them. The scan output
  now records the Checkov version and lists rules that have no severity seed.
- Apply gate flag file is `.claude/iac-tools.local.md`; environment overrides
  are `IAC_TOOLS_APPLY_GATE*`.
- License holder is Zero to One Labs LLC.

### Lineage
- iac-security-scan 1.1.0 (2026-09-30) and iac-diagram-generator 1.1.0
  (2026-09-30) are the last releases under the old names. Their repositories are
  archived with a pointer to this one.
