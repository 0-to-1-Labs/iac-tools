"""Shared pytest setup: put ``lib/`` on sys.path so tests can import
``iac_tools`` directly, and never let a test spawn the managed venv."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB = os.path.join(ROOT, "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)

os.environ.setdefault("IAC_DIAGRAM_NO_VENV", "1")
