# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

# includes

include "_core.error.pxi"
include "_core.lib.pxi"
include "_core.sound.pxi"
include "_core.util.pxi"

include "_core.ua.pxi"

include "_core.event.pxi"
include "_core.request.pxi"
include "_core.helper.pxi"
include "_core.headers.pxi"
include "_core.subscription.pxi"
include "_core.invitation.pxi"
include "_core.referral.pxi"
include "_core.sdp.pxi"
include "_core.mediatransport.pxi"

# constants

PJ_VERSION = pj_get_version()
PJ_SVN_REVISION = int(PJ_SVN_REV)
CORE_REVISION = 164

# exports

__all__ = ["PJ_VERSION", "PJ_SVN_REVISION", "CORE_REVISION",
           "SIPCoreError", "PJSIPError", "PJSIPTLSError", "SIPCoreInvalidStateError",
           "AudioMixer", "ToneGenerator", "RecordingWaveFile", "WaveFile", "MixerPort",
           "sip_status_messages",
           "BaseCredentials", "Credentials", "FrozenCredentials", "BaseSIPURI", "SIPURI", "FrozenSIPURI",
           "BaseHeader", "Header", "FrozenHeader",
           "BaseContactHeader", "ContactHeader", "FrozenContactHeader",
           "BaseContentTypeHeader", "ContentType", "ContentTypeHeader", "FrozenContentTypeHeader",
           "BaseIdentityHeader", "IdentityHeader", "FrozenIdentityHeader", "FromHeader", "FrozenFromHeader", "ToHeader", "FrozenToHeader",
           "RouteHeader", "FrozenRouteHeader", "RecordRouteHeader", "FrozenRecordRouteHeader", "BaseRetryAfterHeader", "RetryAfterHeader", "FrozenRetryAfterHeader",
           "BaseViaHeader", "ViaHeader", "FrozenViaHeader", "BaseWarningHeader", "WarningHeader", "FrozenWarningHeader",
           "BaseEventHeader", "EventHeader", "FrozenEventHeader", "BaseSubscriptionStateHeader", "SubscriptionStateHeader", "FrozenSubscriptionStateHeader",
           "BaseReasonHeader", "ReasonHeader", "FrozenReasonHeader",
           "BaseReferToHeader", "ReferToHeader", "FrozenReferToHeader",
           "BaseSubjectHeader", "SubjectHeader", "FrozenSubjectHeader",
           "BaseReplacesHeader", "ReplacesHeader", "FrozenReplacesHeader",
           "Request",
           "Referral",
           "sipfrag_re",
           "Subscription",
           "Invitation",
           "DialogID",
           "SDPSession", "FrozenSDPSession", "SDPMediaStream", "FrozenSDPMediaStream", "SDPConnection", "FrozenSDPConnection", "SDPAttribute", "FrozenSDPAttribute", "SDPNegotiator",
           "RTPTransport", "AudioTransport"]


# Initialize the GIL in the PyMODINIT function of the module.
# This is a hack because Cython does not support #ifdefs.
cdef extern from *:
    cdef void emit_ifdef_with_thread "#ifdef WITH_THREAD //" ()
    cdef void emit_endif "#endif //" ()

emit_ifdef_with_thread()
PyEval_InitThreads()
emit_endif()

