# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

# includes

include "core.error.pxi"
include "core.lib.pxi"
include "core.sound.pxi"
include "core.util.pxi"

include "core.ua.pxi"

include "core.event.pxi"
include "core.request.pxi"
include "core.helper.pxi"
include "core.headers.pxi"
include "core.subscription.pxi"
include "core.invitation.pxi"
include "core.sdp.pxi"
include "core.mediatransport.pxi"

# constants

PJ_VERSION = pj_get_version()
PJ_SVN_REVISION = int(PJ_SVN_REV)
CORE_REVISION = 76

# exports

__all__ = ["PJ_VERSION", "PJ_SVN_REVISION", "CORE_REVISION",
           "SIPCoreError", "PJSIPError",
           "ConferenceBridge", "ToneGenerator", "RecordingWaveFile", "WaveFile",
           "sip_status_messages",
           "BaseCredentials", "Credentials", "FrozenCredentials", "BaseSIPURI", "SIPURI", "FrozenSIPURI",
           "BaseHeader", "Header", "FrozenHeader", "BaseContactHeader", "ContactHeader", "FrozenContactHeader",
           "BaseIdentityHeader", "IdentityHeader", "FrozenIdentityHeader", "FromHeader", "FrozenFromHeader", "ToHeader", "FrozenToHeader",
           "RouteHeader", "FrozenRouteHeader", "RecordRouteHeader", "FrozenRecordRouteHeader", "BaseRetryAfterHeader", "RetryAfterHeader", "FrozenRetryAfterHeader",
           "BaseViaHeader", "ViaHeader", "FrozenViaHeader", "BaseWarningHeader", "WarningHeader", "FrozenWarningHeader",
           "BaseEventHeader", "EventHeader", "FrozenEventHeader", "BaseSubscriptionStateHeader", "SubscriptionStateHeader", "FrozenSubscriptionStateHeader",
           "Request",
           "Subscription",
           "Invitation",
           "SDPSession", "FrozenSDPSession", "SDPMediaStream", "FrozenSDPMediaStream", "SDPConnection", "FrozenSDPConnection", "SDPAttribute", "FrozenSDPAttribute",
           "RTPTransport", "AudioTransport"]


# Initialize the GIL in the PyMODINIT function of the module.
# This is a hack because Cython does not support #ifdefs.
cdef extern from *:
    cdef void emit_ifdef_with_thread "#ifdef WITH_THREAD //" ()
    cdef void emit_endif "#endif //" ()

emit_ifdef_with_thread()
PyEval_InitThreads()
emit_endif()

