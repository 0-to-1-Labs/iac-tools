#!/usr/bin/env python3
"""
IaC Parser -- security-scan entry point.

Thin shim over the shared parser in ``lib/iac_tools/parse_iac.py``. The
command line is unchanged:

    python3 parse_iac.py <format> <path> [--json-only]

    formats: terraform | cloudformation | kubernetes | docker-compose
    path:    local file/directory or a GitHub URL

Output contract (owned by the shared module): JSON on stdout, ``--json-only``
keeps stdout pure JSON, non-zero exit on error, and every resource carries a
``location`` object plus top-level ``parseTier`` / ``degraded`` /
``lineProvenance``. A tier below the full one is a DEGRADED SCAN and prints an
unmissable banner.

Sibling scripts import this file as ``parse_iac``. Every public name of the
shared module is re-exported, and on import this module name is bound to the
shared module itself, so ``parse_iac.X`` always reaches the implementation
(including monkeypatched globals such as ``RUAMEL_AVAILABLE``).
"""

import os
import sys

_LIB = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "lib"))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from iac_tools import parse_iac as _impl  # noqa: E402
from iac_tools.parse_iac import *  # noqa: E402,F401,F403  (re-export every public name)


def parse_for_format(iac_format, path):
    """Route a format keyword to its parser. The keywords are part of the CLI
    contract; downstream phases match on exactly these strings."""
    if iac_format == "terraform":
        return _impl.parse_terraform(path)
    elif iac_format == "cloudformation":
        return _impl.parse_cloudformation(path)
    elif iac_format == "kubernetes":
        return _impl.parse_kubernetes(path)
    elif iac_format == "docker-compose":
        return _impl.parse_docker_compose(path)
    return None


def main(argv=None):
    """Main entry point for the IaC parser (delegates to the shared module)."""
    return _impl.main(argv, dispatch=parse_for_format)


if __name__ == "__main__":
    main()
else:
    # `import parse_iac` yields the shared module: one implementation, one
    # namespace, so tests and siblings that patch or read module globals agree.
    sys.modules[__name__] = _impl
