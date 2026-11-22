"""Moved to skillproof.adapters.openai_responses (see docs/ARCHITECTURE.md). This alias keeps `skillproof.openai_adapter` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.adapters import openai_responses as _moved

sys.modules[__name__] = _moved
