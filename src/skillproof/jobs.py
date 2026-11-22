"""Moved to skillproof.storage.jobs (see docs/ARCHITECTURE.md). This alias keeps `skillproof.jobs` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.storage import jobs as _moved

sys.modules[__name__] = _moved
