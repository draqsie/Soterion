"""Scanner adapters. Each one describes how to run a tool and how to read its output."""

from soterion.checks.gitleaks import GITLEAKS
from soterion.scan import ToolCheck

# The checks `soterion scan` runs. A scan can only be reported as clean when
# every check listed here completed.
DEFAULT_CHECKS: tuple[ToolCheck, ...] = (GITLEAKS,)
