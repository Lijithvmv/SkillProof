"""Moved to skillproof.engines.triage (see docs/ARCHITECTURE.md). This alias keeps `skillproof.triage` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import triage as _moved

sys.modules[__name__] = _moved
