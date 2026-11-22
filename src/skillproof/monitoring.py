"""Moved to skillproof.engines.monitoring (see docs/ARCHITECTURE.md). This alias keeps `skillproof.monitoring` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import monitoring as _moved

sys.modules[__name__] = _moved
