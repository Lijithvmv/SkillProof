"""Moved to skillproof.engines.operations (see docs/ARCHITECTURE.md). This alias keeps `skillproof.operations` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import operations as _moved

sys.modules[__name__] = _moved
