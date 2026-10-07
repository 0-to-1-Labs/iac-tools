"""Locations inside the iac-tools plugin, resolved from this file.

Every skill script and test imports these instead of building paths by hand,
so a skill can move without breaking its neighbours.
"""
from __future__ import annotations

import os

LIB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_ROOT = os.path.dirname(LIB_DIR)
SKILLS_DIR = os.path.join(PLUGIN_ROOT, "skills")
TESTS_DIR = os.path.join(PLUGIN_ROOT, "tests")
FIXTURES_DIR = os.path.join(TESTS_DIR, "fixtures")


def skill_dir(name: str) -> str:
    return os.path.join(SKILLS_DIR, name)


def skill_scripts(name: str) -> str:
    return os.path.join(skill_dir(name), "scripts")


def skill_data(name: str) -> str:
    return os.path.join(skill_dir(name), "data")


# Shared compliance data lives with security-scan and is read by threat-model.
CONTROL_MAP = os.path.join(skill_data("security-scan"), "control-map.json")
CONTROL_BASELINE_800_53 = os.path.join(skill_data("security-scan"), "control-baseline-800-53.json")
RULE_SEVERITY = os.path.join(skill_data("security-scan"), "rule-severity.json")
