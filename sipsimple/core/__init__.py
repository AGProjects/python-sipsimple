# Copyright (C) 2010-2011 AG Projects. See LICENSE for details.
#

from sipsimple.core._core import *
from sipsimple.core._engine import *
from sipsimple.core._helpers import *
from sipsimple.core._primitives import *

required_revision = 178
if CORE_REVISION != required_revision:
    raise ImportError("Wrong SIP core revision %d (expected %d)" % (CORE_REVISION, required_revision))
del required_revision


