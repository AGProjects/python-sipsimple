# includes

include "core.error.pxi"
include "core.lib.pxi"
include "core.sound.pxi"
include "core.util.pxi"
include "core.event.pxi"

include "core.ua.pxi"

include "core.message.pxi"
include "core.helper.pxi"
include "core.registration.pxi"
include "core.publication.pxi"
include "core.subscription.pxi"
include "core.invitation.pxi"
include "core.sdp.pxi"
include "core.mediatransport.pxi"

# constants
PJ_VERSION = pj_get_version()
PJ_SVN_REVISION = int(PJ_SVN_REV)
PYPJUA_REVISION = 10