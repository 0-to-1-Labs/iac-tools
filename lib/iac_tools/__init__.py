"""Shared Python package for the iac-tools plugin.

Modules:
  paths       -- plugin directory layout
  plugin_env  -- managed venv bootstrap for the diagram-generator skill
  parse_iac   -- the one IaC parser (Terraform, CloudFormation, Kubernetes, Compose)

Keep this file free of imports: skill shims import ``iac_tools.plugin_env``
before any third-party dependency is guaranteed to exist.
"""
