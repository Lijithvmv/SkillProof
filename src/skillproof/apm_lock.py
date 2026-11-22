"""Moved to skillproof.engines.apm_lock (see docs/ARCHITECTURE.md). This alias keeps `skillproof.apm_lock` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import apm_lock as _moved

sys.modules[__name__] = _moved
