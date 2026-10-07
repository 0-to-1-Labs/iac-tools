# Contributing to iac-tools

iac-tools is one Claude Code plugin with several skills. Each skill is a
capability with a deterministic floor (a real tool runs first) and an LLM
layer on top. This file explains the layout and how to add a skill.

## Layout

```
.claude-plugin/plugin.json   plugin manifest (one for the whole plugin)
lib/iac_tools/               shared Python: parser, venv bootstrap, paths
skills/<name>/SKILL.md       one skill per directory, user-invocable as /iac-tools:<name>
skills/<name>/scripts/       the skill's CLI scripts, invoked with python3
skills/<name>/data/          curated, checked-in data the scripts read
skills/<name>/references/    reference docs the skill tells the model to read
agents/<name>.md             subagents a skill fans out to
hooks/                       opt-in hooks shipped as .example files, never armed on install
tests/                       pytest suite; fixtures under tests/fixtures/
docs/                        design notes
```

Skills are discovered from `skills/` and agents from `agents/`. There is no
`commands/` directory. A skill is the command.

## Rules every skill follows

1. **Deterministic floor first.** Parse, scan, diff, or render with a real tool.
   The model explains, ranks, narrates, and writes the long tail. The model
   never deletes a tool finding. If the tool is missing, say `degraded: true`
   and keep going; never let "found nothing" look like "clean".
2. **Curated data only.** Severities, control IDs, fix rules, and threat rules
   are checked-in JSON with provenance. The model never generates a control ID
   or a baseline severity at runtime.
3. **IaC content is untrusted input.** Every prompt delimits repo content as
   data. Imperative text inside IaC is reported as an injection attempt, not
   obeyed.
4. **Narrow `allowed-tools`.** List each script invocation explicitly:
   `Bash(python3 ${CLAUDE_PLUGIN_ROOT}/skills/<name>/scripts/<script>.py *)`.
   No bare `Bash`. Anything that spends quota, sends data off the machine, or
   touches a cloud account goes through the normal permission prompt.
5. **Nothing is armed on install.** Hooks ship as `.example` files with a
   two-switch enable (register, then flip a project flag). Gates fail open to
   `ask`, never to `allow`.
6. **Scripts share the lib.** Import shared code like this:

   ```python
   import os, sys
   _LIB = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "lib"))
   if _LIB not in sys.path:
       sys.path.insert(0, _LIB)
   from iac_tools import paths, parse_iac
   ```

7. **Plain writing.** Short sentences. No em dashes. No superlatives. Say what
   the deterministic layer guarantees and what the model adds.

## Adding a skill

1. Create `skills/<name>/SKILL.md` with frontmatter: `name`, a `description`
   that names the user phrases that should trigger it, `argument-hint`, and
   `allowed-tools`. Handle `$ARGUMENTS` in the body.
2. Put scripts under `skills/<name>/scripts/`. Reuse `lib/iac_tools/parse_iac.py`
   for IaC input and `lib/iac_tools/paths.py` for locations. Reuse
   `skills/security-scan/scripts/run_checkov.py` for Checkov evidence.
3. Put curated data under `skills/<name>/data/` with a `_meta` block that
   states provenance and review status.
4. Add an agent under `agents/` only if the skill fans out work. Copy the
   untrusted-input rules from `agents/security-analyst.md` verbatim.
5. Add fixtures under `tests/fixtures/` and an answer key under `tests/data/`.
   Add tests. The suite must stay green.
6. Document the skill in `README.md` and add a `CHANGELOG.md` entry.
7. Run `claude plugin validate .` and install through a local directory
   marketplace before pushing.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest -q -p no:cacheprovider          # full suite, needs checkov and terraform on PATH
.venv/bin/python -m pytest -q -p no:cacheprovider -m "not slow"
```

Python 3.10 or later. Checkov 3.3 does not install on Python 3.14 yet; use
3.12 or 3.13 for the full suite.

## Versioning

One version for the whole plugin, in `.claude-plugin/plugin.json`. Bump the
minor version when a skill gains a capability, the major version when a skill
is renamed or removed. Record renames in the marketplace `renames` map.
