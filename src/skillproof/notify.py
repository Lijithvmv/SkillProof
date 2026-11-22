"""Moved to skillproof.storage.notify (see docs/ARCHITECTURE.md). This alias keeps `skillproof.notify` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.storage import notify as _moved

sys.modules[__name__] = _moved
