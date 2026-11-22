"""Moved to skillproof.engines.semantic (see docs/ARCHITECTURE.md). This alias keeps `skillproof.semantic` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import semantic as _moved

sys.modules[__name__] = _moved
