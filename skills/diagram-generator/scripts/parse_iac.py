#!/usr/bin/env python3
"""
IaC Parser -- diagram-generator entry point.

Thin shim over the shared parser in ``lib/iac_tools/parse_iac.py``. The
command line is unchanged:

    python3 parse_iac.py <format> <path> [--data-dir DIR] [--json-only]
    python3 parse_iac.py --install-optional [--data-dir DIR]

Dependencies are installed on first run into a private virtual environment
(see ``lib/iac_tools/plugin_env.py``) and the script re-runs itself inside it.
Optional parser tiers (python-hcl2, tfparse, cfn-lint) are installed with
``--install-optional``. Set IAC_DIAGRAM_NO_VENV=1 to run in the current
interpreter.

When imported (``import parse_iac``) this module name is bound to the shared
module itself, so every public name is available and module globals are one
namespace.
"""

import os
import sys

_LIB = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "lib"))
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from iac_tools import plugin_env  # noqa: E402


def bootstrap(argv=None):
    """
    Parse the arguments that control the runtime, then re-run inside the
    managed venv when needed. Returns the parsed arguments.
    """
    from iac_tools.parse_iac import parse_args  # import is safe without PyYAML

    _parser, args = parse_args(argv)
    if args.install_optional:
        plugin_env.check_python_version()
        python = plugin_env.ensure_venv(args.data_dir, optional=True)
        print(f"Optional parsers installed. Interpreter: {python}")
        sys.exit(0)
    plugin_env.reexec_in_venv(args.data_dir)
    return args


def main(argv=None):
    """Bootstrap the environment, then run the shared parser CLI."""
    bootstrap(argv)
    from iac_tools import parse_iac as _impl

    return _impl.main(argv)


if __name__ == "__main__":
    main()
else:
    from iac_tools import parse_iac as _impl

    sys.modules[__name__] = _impl
