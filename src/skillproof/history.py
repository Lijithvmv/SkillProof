"""Moved to skillproof.storage.history (see docs/ARCHITECTURE.md). This alias keeps `skillproof.history` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.storage import history as _moved

sys.modules[__name__] = _moved
