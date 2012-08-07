
SIP SIMPLE client Payloads
--------------------------

These applications provide functionality that are required for implementing
a feature-rich SIP SIMPLE client.

These applications are used for parsing and generating bodies carried using
PUBLISH, SUBSCRIBE and NOTIFY methods designed for asynchronous event
notifications, to convey in near real-time, information between SIP
end-points.

An example of such information is presence, which in its basic form it
provides user availability information based on end-user choice.  In its
advanced form, presence can provide rich state information including but not
limited to user mood, geo-location, environment, noise level and the type of
communication desired.  The information can be disseminated based on a
granular policy which allows end-users to decide who has access to which
part of the published information.


addressbook.py

High-level implementation of an addressbook stored in XCAP documents.  The
contacts, groups and their attributes are stored in resource lists and OMA
extensions described in OMA-TS-Presence_SIMPLE_XDM are used for describing
policy and RLS services by references to resource lists.  Multiple client
instances can synchronize this addressbook using XCAP-diff event package.


watcherinfo.py (RFC3857 and RFC3858)

Parses NOTIFY body for presence.winfo event. Used for keeping track of
watchers that subscribed to our presentity.  Based on this information the
the user can manage its presence policy.  To retrieve this information the
SIP client must subscribe to its own address for event presence.winfo.


resourcelists.py (RFC4826)

Parses and generates XML documents for constructing resource lists
documents.  Used for server side storage of presence related buddy lists
using XCAP protocol.  The SIP clients maintain the resource-lists on the
XCAP server which provides persisten storage and aggregation point for
multiple devices.


rlsservices.py (RFC4826)

Parses and generates XML documents for constructing rls-services documents. 
Used for delegating presence related works to the server.  The client build
rls-services lists with buddies and instructs the server to subscribe to the
sip uris indicated in the lists.  This way the client can save bandwidth as
the server performs the signalling for subscription and collection of
notifications and provides consolidated answer to the sip user agent.


rlmi.py, rlsnotify.py (RFC4482)

Document handling for NOTIFY body for Resource Lists Contact Information.


policy.py (RFC4745)

Generic data types to be used in policy applications.


presrules.py (RFC5025)

Parses and generates authorization rules in XML format for presence or other
applications.  Authorization rules are stored on the XCAP server.  The
presence rules are generated either based on user initiative or as a
response to a new subscription signaled by a change in the watcherinfo
application.


omapolicy.py (OMA-TS-Presence_SIMPLE_XDM-V1_1)

Conditions extension handling according to OMA-TS-Presence_SIMPLE_XDM-V1_1. 
This module provides an extension to common policy defined in RFC4745 to
support condition extensions defined by OMA.


prescontent.py (OMA-TS-Presence_SIMPLE_XDM-V1_1)

Generates presence content application documents according to OMA TS
Presence SIMPLE Content.


directory.py (OMA Core Specifications)

Parses xcap-directory messages according to OMA TS XDM Core.


dialoginfo.py (RFC4235)

Parses and produces dialog-info messages according to RFC4235.


dialogrules.py

Parses and produces Dialog Authorization Rules documents. As there is no RFC
for this, common-policy format from RFC 4745 is used.  Subscription Handling
has been taken from RFC 5025.


pidf.py (RFC3863 and RFC3379)

This module provides classes to parse and generate PIDF documents, and also
uses the XML Application extensibility API to allow extensions to PIDF. It
is used to parse NOTIFY body for presence event and generates rich presence
state information for use with PUBLISH. Used to generate own presence
information and to parse the state of buddy lists entries we have subscribed
to. A SIP client typically instantiates a new pidf object for itself and for
each buddy it SUBSCRIBEs to and update each object when a NOTIFY is
received. The list of buddys is maintained using resourcelists application.


rpid.py (RFC4480)

This module provides an extension to PIDF to support rich presence.


presdm.py (RFC4479)

This module provides an extension to the PIDF to support the data module
defined in RFC4479.


cipid.py (RFC4482)
 
This module provides an extension to PIDF to provide person related information.


caps.py (RFC5196)

This module provides capabilities application: displays OPTIONS request-like information
as an extension to the PIDF.


xcapcaps.py (RFC4825)

Support for parsing and building xcap-caps documents, as defined by RFC4825.


xcapdiff.py (RFC5874)

Parses NOTIFY body for xcap-diff event. Used to detect changes in XCAP
documents changed by other device configured for the same presentity.


iscomposing.py (RFC3994)

This module parses and generates isComposing messages according to RFC3994. It's used
mainly in chat environments to indicate the other party that the user is actually
typing a message.


conference.py (RFC4575)

This module implements conference-info payload parsing and generating for
describing information about conference participants and related resources.


messagesummary.py (RFC3842)

This module implements a parser and generator for message-summary payload,
which is used to indicate missed calls or voice mail recordings.

