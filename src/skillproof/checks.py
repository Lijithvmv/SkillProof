"""Moved to skillproof.engines.checks (see docs/ARCHITECTURE.md). This alias keeps `skillproof.checks` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import checks as _moved

sys.modules[__name__] = _moved
