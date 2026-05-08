"""CLI command modules for iStrix."""

from istrix.cli.scan import scan_command
from istrix.cli.config import config_app
from istrix.cli.plan import plan_command, consult_command
from istrix.cli.report import report_command
from istrix.cli.job import job_app

__all__ = [
    "scan_command",
    "config_app",
    "plan_command",
    "consult_command",
    "report_command",
    "job_app",
]
