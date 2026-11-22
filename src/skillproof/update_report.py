"""Moved to skillproof.engines.update_report (see docs/ARCHITECTURE.md). This alias keeps `skillproof.update_report` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import update_report as _moved

sys.modules[__name__] = _moved
