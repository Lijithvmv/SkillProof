"""Moved to skillproof.engines.security (see docs/ARCHITECTURE.md). This alias keeps `skillproof.security` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import security as _moved

sys.modules[__name__] = _moved
