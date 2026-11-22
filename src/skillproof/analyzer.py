"""Moved to skillproof.engines.analyzer (see docs/ARCHITECTURE.md). This alias keeps `skillproof.analyzer` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import analyzer as _moved

sys.modules[__name__] = _moved
