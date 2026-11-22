"""Moved to skillproof.engines.confidence (see docs/ARCHITECTURE.md). This alias keeps `skillproof.confidence` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import confidence as _moved

sys.modules[__name__] = _moved
