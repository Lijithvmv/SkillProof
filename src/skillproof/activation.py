"""Moved to skillproof.engines.activation (see docs/ARCHITECTURE.md). This alias keeps `skillproof.activation` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import activation as _moved

sys.modules[__name__] = _moved
