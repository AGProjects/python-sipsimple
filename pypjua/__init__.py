__version__ = "0.3.0"

_revision_required = 6
from core import REVISION
if REVISION != _revision_required:
    raise ImportError("Wrong PyPJUA core revision %d (expected %d)" % (REVISION, _revision_required))

import os.path
try:
    svn_revision = int(open(os.path.join(os.path.dirname(__file__), "svn_revision"), "rb").read())
except:
    svn_revision = "?"

from engine import Engine
from core import SIPURI, Credentials, Route
from core import Registration, Publication, Subscription, Invitation, send_message
from core import SDPAttribute, SDPConnection, SDPMedia, SDPSession
from core import RTPTransport, AudioTransport

__all__ = ["Engine",
           "SIPURI", "Credentials", "Route",
           "Registration", "Publication", "Subscription", "Invitation", "send_message",
           "SDPAttribute", "SDPConnection", "SDPMedia", "SDPSession",
           "RTPTransport", "AudioTransport"]