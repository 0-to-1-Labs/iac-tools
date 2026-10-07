#!/usr/bin/env python3
"""WS-8: the regression harness. This is what GATE 2 is measured against.

Three levels, per the plan:

  1. DETECTION  -- every flaw in SECURITY_FLAWS.md is found. Recall is reported as
                   a number. A regression against the known-detected set is a HARD
                   FAILURE.
  2. FIX VALIDITY -- every generated fix survives `git apply`, `terraform validate`
                   and `terraform fmt -check`, and Checkov stops reporting the rule.
  3. SAFETY     -- the never-auto-apply categories are never marked autoApplicable.
                   Non-negotiable. This one never gets relaxed.

WHY RECALL IS 21/25 AND NOT 25/25
---------------------------------
Four of the twenty-five planted flaws are invisible to Checkov, and the reason is
the whole thesis of this product. On THREE of them Checkov did not merely lack a
rule -- it evaluated the flawed resource and put the check in `passed_checks`. It
looked straight at the planted flaw and called it fine:

  * TF-02-4  CKV_AWS_366 (Cognito MFA)        -> evaluated, PASSED
  * TF-04-2  CKV_AWS_336 (ECS read-only root) -> evaluated, PASSED
  * TF-02-1  CKV_AWS_63  (IAM wildcard action)-> evaluated, PASSED. It matches a bare
             "*"; `dynamodb:*` is a service-scoped wildcard and sails through. The
             policy's Resource is tightly scoped, so the resource is narrow and the
             ACTION is wide open -- the one shape no Checkov rule catches.
  * TF-01-4  0.0.0.0/0 on :443 -> Checkov's open-ingress rules are port-specific
             (22, 80, 3389). Nothing covers 443. All evaluated, all passed.

A deterministic scanner that is confidently wrong is exactly what the LLM layer is
for. So these four are tracked as `requiresLlmLayer`, asserted to be genuinely
absent from the deterministic output (if Checkov ever starts catching one, this
harness tells us, and the answer key gets updated), and they are what the
`security-analyst` pass must earn its keep on.

Recall is a number we REPORT. It is never a number we manage by relaxing the key.

CHECKOV VERSION POLICY
----------------------
requirements.txt is a FLOOR (checkov>=GRADED_CHECKOV). The key, the seeds and the
corpus counts are graded against exactly GRADED_CHECKOV. On that version every
rule that fires on the corpus must have a severity seed (``unseededRules`` empty).
On a newer version the harness prints the unseeded list and passes -- the rule
set moved, which is a re-grade job, not a bug in our code.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "skills", "security-scan", "scripts")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
ANSWER_KEY = os.path.join(ROOT, "tests", "data", "answer-key.json")
sys.path.insert(0, SCRIPTS)

import patch_terraform as pt  # noqa: E402
import run_checkov  # noqa: E402

#: Checkov's rule set moves between releases. The key is graded against exactly
#: this version; requirements.txt sets it as the floor. Re-graded 2026-10-06.
GRADED_CHECKOV = "3.3.25"


def _version_tuple(text):
    return tuple(int(p) for p in text.strip().split("."))


def _running_checkov_version():
    out = subprocess.run(["checkov", "--version"], capture_output=True, text=True)
    return out.stdout.strip()

FIXTURE_NAMES = [
    "tf-01-three-tier-webapp",
    "tf-02-serverless-api",
    "tf-03-data-lake",
    "tf-04-container-platform",
    "tf-05-cicd-pipeline",
]


def load_key():
    with open(ANSWER_KEY, encoding="utf-8") as fh:
        return json.load(fh)


ANSWERS = load_key()
ALL_FLAWS = [
    (fixture, flaw)
    for fixture in FIXTURE_NAMES
    for flaw in ANSWERS[fixture]
]
DETECTABLE = [(f, x) for f, x in ALL_FLAWS if x["detectedBy"]]
LLM_ONLY = [(f, x) for f, x in ALL_FLAWS if not x["detectedBy"]]


@pytest.fixture(scope="module")
def scan_payloads():
    """One Checkov pass per fixture, reused across the module. Checkov is slow.
    The full adapter payload, so version and unseededRules are inspectable."""
    return {
        name: run_checkov.run_checkov(os.path.join(FIXTURES, name))
        for name in FIXTURE_NAMES
    }


@pytest.fixture(scope="module")
def scans(scan_payloads):
    """Just the findings, per fixture."""
    return {name: payload["findings"] for name, payload in scan_payloads.items()}


def _git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True
    )


# ===========================================================================
# Level 0 -- the harness's own footing
# ===========================================================================


class TestHarnessFooting:
    def test_graded_version_is_the_adapters_graded_version(self):
        """The harness and the adapter must agree on what 'graded' means."""
        assert GRADED_CHECKOV == run_checkov.GRADED_CHECKOV_VERSION
        with open(ANSWER_KEY, encoding="utf-8") as fh:
            assert json.load(fh)["_meta"]["checkovGraded"] == GRADED_CHECKOV

    def test_checkov_meets_the_floor(self):
        """Its rule set moves. requirements.txt is a floor, so an OLDER Checkov
        than the graded one is a real error (rules the key expects do not exist);
        a NEWER one is allowed and handled by test_unseeded_rules_*."""
        running = _running_checkov_version()
        assert _version_tuple(running) >= _version_tuple(GRADED_CHECKOV), (
            f"answer key was graded against checkov {GRADED_CHECKOV}, found "
            f"{running}, which is OLDER than the floor. Install checkov>={GRADED_CHECKOV}."
        )

    def test_unseeded_rules_are_empty_on_the_graded_version(self, scan_payloads, capsys):
        """On exactly the graded version every rule that fires on the corpus has
        a severity seed. On a newer version the list is LOGGED and the test
        passes: the rule set moved, and that is a re-grade, not a regression."""
        unseeded = sorted(
            {r for p in scan_payloads.values() for r in (p.get("unseededRules") or [])}
        )
        running = None
        for p in scan_payloads.values():
            assert isinstance(p.get("unseededRules"), list)
            assert p.get("checkovVersion"), "adapter must record the version it ran"
            assert p["gradedVersion"] == GRADED_CHECKOV
            running = p["checkovVersion"]
        if running == GRADED_CHECKOV:
            assert not unseeded, (
                f"checkov {running} is the graded version and these rules fire on "
                f"the Terraform corpus with no severity seed: {unseeded}"
            )
        else:
            with capsys.disabled():
                print(
                    f"\n  checkov {running} != graded {GRADED_CHECKOV}; "
                    f"unseeded rules on the Terraform corpus: {unseeded or 'none'}"
                )

    def test_the_answer_key_covers_all_25_planted_terraform_flaws(self):
        assert len(ALL_FLAWS) == 25
        assert len(DETECTABLE) == 21
        assert len(LLM_ONLY) == 4

    def test_every_llm_only_flaw_states_why_it_escapes(self):
        """A miss without a reason is a miss nobody will ever fix."""
        for _fixture, flaw in LLM_ONLY:
            assert flaw.get("missReason"), f"{flaw['id']} has no missReason"
            assert flaw.get("requiresLlmLayer") is True


# ===========================================================================
# Level 1 -- DETECTION. The GATE 2 number.
# ===========================================================================


class TestDetectionRecall:
    @pytest.mark.parametrize(
        "fixture,flaw",
        DETECTABLE,
        ids=[f"{x['id']}" for _f, x in DETECTABLE],
    )
    def test_planted_flaw_is_detected(self, fixture, flaw, scans):
        """A regression here is a HARD FAILURE: we stopped finding a real flaw."""
        hits = [
            f
            for f in scans[fixture]
            if f["ruleId"] in flaw["detectedBy"]
            and f["location"]["file"] == flaw["file"]
        ]
        assert hits, (
            f"{flaw['id']} NOT DETECTED: {flaw['flaw']}\n"
            f"  expected one of {flaw['detectedBy']} in {flaw['file']}\n"
            f"  This flaw was detected when the key was graded. We have regressed."
        )

    @pytest.mark.parametrize(
        "fixture,flaw",
        LLM_ONLY,
        ids=[f"{x['id']}" for _f, x in LLM_ONLY],
    )
    def test_known_checkov_blind_spot_is_still_blind(self, fixture, flaw, scans):
        """The inverse assertion, and it is not a formality.

        If Checkov ever starts catching one of these, that is GOOD NEWS -- and this
        test fails loudly so the answer key gets promoted rather than quietly leaving
        a flaw credited to the LLM layer that the deterministic layer now covers.
        """
        hits = [f for f in scans[fixture] if f["location"]["file"] == flaw["file"]]
        by_rule = {f["ruleId"] for f in hits}
        assert flaw["id"] not in ("",)  # keep the id in the failure output
        assert not (by_rule & set(flaw.get("detectedBy") or [])), (
            f"{flaw['id']}: checkov now detects this. Promote it in answer-key.json."
        )

    def test_recall_is_reported_as_a_number(self, scans, capsys):
        """GATE 2. The number, printed, every run."""
        found, missed = [], []
        for fixture, flaw in DETECTABLE:
            hits = [
                f
                for f in scans[fixture]
                if f["ruleId"] in flaw["detectedBy"]
                and f["location"]["file"] == flaw["file"]
            ]
            (found if hits else missed).append(flaw["id"])

        total = len(ALL_FLAWS)
        pct = 100.0 * len(found) / total
        with capsys.disabled():
            print(f"\n\n  DETECTION RECALL (deterministic layer, graded on checkov {GRADED_CHECKOV})")
            print(f"     {len(found)}/{total} planted Terraform flaws = {pct:.0f}%")
            print(f"     {len(LLM_ONLY)}/{total} require the LLM layer:")
            for _f, flaw in LLM_ONLY:
                print(f"        {flaw['id']}  {flaw['flaw']}")
            if missed:
                print(f"     REGRESSION -- these were detected and now are not: {missed}")
            print()

        assert not missed, f"detection regression on {missed}"
        assert len(found) == 21


# ===========================================================================
# Level 2 -- FIX VALIDITY
# ===========================================================================


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    """Patch every fixture once, in a temp copy. Never touch tests/fixtures/."""
    out = {}
    for name in FIXTURE_NAMES:
        dst = str(tmp_path_factory.mktemp(name) / name)
        shutil.copytree(os.path.join(FIXTURES, name), dst)
        _git(dst, "init", "-q")
        _git(dst, "add", "-A")
        _git(dst, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")

        before = run_checkov.run_checkov(dst)["findings"]
        resources, _ = pt.load_terraform_resources(dst)
        patches = pt.generate_security_patches(dst, before, resources=resources, use_fmt=False)
        file_patches = pt.generate_file_patches(dst, patches, resources, use_fmt=False)
        out[name] = {
            "root": dst,
            "before": before,
            "patches": patches,
            "filePatches": file_patches,
            "resources": resources,
        }
    return out


class TestFixValidity:
    @pytest.mark.parametrize("fixture", FIXTURE_NAMES)
    def test_the_emitted_patch_set_applies(self, fixture, patched, tmp_path):
        """`git apply --check`, shelling out to real git. The only proof that counts:
        a tool whose headline output is 'here are your fixes' cannot emit fixes that
        do not apply."""
        p = patched[fixture]
        if not p["filePatches"]:
            pytest.skip("no patches for this fixture")
        patch_file = str(tmp_path / f"{fixture}.patch")
        pt.write_patch_set(p["filePatches"], patch_file)
        proc = _git(p["root"], "apply", "--check", patch_file)
        assert proc.returncode == 0, f"{fixture} patch set does not apply:\n{proc.stderr}"

    @pytest.mark.parametrize("fixture", FIXTURE_NAMES)
    def test_patching_closes_findings_and_introduces_no_new_rule(self, fixture, patched):
        """Checkov must stop reporting the rules we claimed to fix."""
        p = patched[fixture]
        root = p["root"]
        pt.apply_patches_to_tree(root, p["patches"], p["resources"], use_fmt=False)
        after = run_checkov.run_checkov(root)["findings"]

        claimed = {r for patch in p["patches"] for r in (patch.ruleIds or [])}
        still_firing = {
            f["ruleId"]
            for f in after
            if f["ruleId"] in claimed
            and any(
                f["location"]["resourceAddress"] == pp.address
                and f["ruleId"] in (pp.ruleIds or [])
                for pp in p["patches"]
            )
        }
        assert not still_firing, (
            f"{fixture}: claimed to fix {sorted(still_firing)} and checkov still "
            f"reports them on the same resource"
        )
        assert len(after) < len(p["before"]), f"{fixture}: patching closed nothing"


# ===========================================================================
# Level 3 -- SAFETY. Non-negotiable. Never relaxed.
# ===========================================================================


class TestSafetyLine:
    """The failure mode is a production outage landing on someone who did not run
    the scan. There is no confidence level at which an access-affecting change gets
    applied for you."""

    @pytest.mark.parametrize("fixture", FIXTURE_NAMES)
    def test_no_access_affecting_change_is_ever_auto_applicable(self, fixture, patched):
        for patch in patched[fixture]["patches"]:
            blocker = pt.auto_apply_blocker(patch.changes)
            if blocker:
                assert not patch.autoApplicable, (
                    f"{fixture}: patch on {patch.address} is access-affecting "
                    f"({blocker}) and is marked autoApplicable"
                )

    @pytest.mark.parametrize("fixture", FIXTURE_NAMES)
    def test_every_auto_applicable_patch_survives_the_blocker(self, fixture, patched):
        """The inverse: nothing marked auto may have a blocker. Belt and braces,
        because this is the one that puts a change on someone's tree unattended."""
        for patch in patched[fixture]["patches"]:
            if patch.autoApplicable:
                assert pt.auto_apply_blocker(patch.changes) is None, (
                    f"{fixture}: {patch.address} is autoApplicable but blocked"
                )

    def test_the_five_never_categories_are_hardcoded_not_heuristic(self):
        """SPEC 6.3's five, verbatim. Hard-coded, not a heuristic, not model-tunable."""
        assert pt.NEVER_AUTO_APPLY_CATEGORIES == frozenset(
            {
                "security-group-cidr",
                "iam-wildcard",
                "bucket-policy",
                "kms-key-policy",
                "network-acl",
            }
        )
