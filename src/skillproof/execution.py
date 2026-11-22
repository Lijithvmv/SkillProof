"""Moved to skillproof.engines.execution (see docs/ARCHITECTURE.md). This alias keeps `skillproof.execution` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import execution as _moved

sys.modules[__name__] = _moved
