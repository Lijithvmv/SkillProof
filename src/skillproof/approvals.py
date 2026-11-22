"""Moved to skillproof.storage.approvals (see docs/ARCHITECTURE.md). This alias keeps `skillproof.approvals` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.storage import approvals as _moved

sys.modules[__name__] = _moved
