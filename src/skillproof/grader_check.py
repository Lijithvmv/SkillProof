"""Moved to skillproof.engines.grader_check (see docs/ARCHITECTURE.md). This alias keeps `skillproof.grader_check` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import grader_check as _moved

sys.modules[__name__] = _moved
