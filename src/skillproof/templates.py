"""Moved to skillproof.engines.templates (see docs/ARCHITECTURE.md). This alias keeps `skillproof.templates` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import templates as _moved

sys.modules[__name__] = _moved
