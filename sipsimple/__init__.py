__version__ = "0.4.0"

_revision_required = 29
from core import CORE_REVISION
if CORE_REVISION != _revision_required:
    raise ImportError("Wrong SIP core revision %d (expected %d)" % (CORE_REVISION, _revision_required))

from engine import Engine
from core import SIPURI, Credentials, Route
from core import Registration, Publication, Subscription, Invitation, send_message
from core import SDPAttribute, SDPConnection, SDPMedia, SDPSession
from core import RTPTransport, AudioTransport
from core import SIPCoreError, PJSIPError
from core import WaveFile, RecordingWaveFile
from session import Session, SessionManager

__all__ = ["Engine",
           "SIPURI", "Credentials", "Route",
           "Registration", "Publication", "Subscription", "Invitation", "send_message",
           "SDPAttribute", "SDPConnection", "SDPMedia", "SDPSession",
           "RTPTransport", "AudioTransport",
           "SIPCoreError", "PJSIPError",
           "WaveFile", "RecordingWaveFile",
           "Session", "SessionManager"]