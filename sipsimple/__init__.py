# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

__version__ = "0.11.0"

_revision_required = 75
from core import CORE_REVISION
if CORE_REVISION != _revision_required:
    raise ImportError("Wrong SIP core revision %d (expected %d)" % (CORE_REVISION, _revision_required))

__all__ = ["__version__"]
