"""Scanner adapters. Each one describes how to run a tool and how to read its output."""

from soterion.checks.gitleaks import GITLEAKS
from soterion.checks.osv import OSV_SCANNER
from soterion.checks.semgrep import SEMGREP
from soterion.scan import ToolCheck

# The checks `soterion scan` runs. A scan can only be reported as clean when
# every check listed here completed or did not apply.
DEFAULT_CHECKS: tuple[ToolCheck, ...] = (GITLEAKS, SEMGREP, OSV_SCANNER)
