"""Moved to skillproof.engines.capabilities (see docs/ARCHITECTURE.md). This alias keeps `skillproof.capabilities` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import capabilities as _moved

sys.modules[__name__] = _moved
