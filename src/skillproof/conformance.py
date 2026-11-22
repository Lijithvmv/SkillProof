"""Moved to skillproof.engines.conformance (see docs/ARCHITECTURE.md). This alias keeps `skillproof.conformance` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import conformance as _moved

sys.modules[__name__] = _moved
