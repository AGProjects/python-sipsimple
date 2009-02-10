
SIP SIMPLE applications
-----------------------

These applications provide non-SIP functionality that are required for
implementing a feature-rich SIP SIMPLE client.

Some applications are for parsing and generating bodies carried using SIP
PUBLISH/SUBSCRIBE/NOTIFY methods. These SIP methods have been designed for
asynchronous event notifications to convey in real-time state and other
information between end-points.

An example of state information is presence, which in its basic form it
provides user availability information based on end-user choice. In its
advanced form, presence can provide rich state information including but not
limited to user mood, geo-location, environment, noise level and type of
communication desired. The information can be disseminated based on a
granular policy which allows end-users to decide who has access to which
part of the published information.

Other applications are used for lookup network addresses using DNS or to
broadcast availability using bonjour.


watcherinfo.py (RFC3857 and RFC3858)

Parses NOTIFY body for presence.winfo event. Used for keeping track of
watchers that subscribed to our presentity. Based on this information the
authorization rules can be managed using presrules.py. To retrieve this
information the SIP client must subscribe to its own address for event
presence.winfo.


resourcelists.py (RFC4826)

Parses and generates XML documents for constructing resource lists
documents. Used for server side storage of presence related buddy lists
using XCAP protocol. The SIP clients maintain the resource-lists on the XCAP
server which provides persisten storage and aggregation point for multiple
devices.


rlsservices.py (RFC4826)

Parses and generates XML documents for constructing rls-services documents.
Used for delegating presence related works to the server. The client build
rls-services lists with buddies and instructs the server to subscribe to the
sip uris indicated in the lists. This way the client can save bandwidth as
the server performs the signalling for subscription and collection of
notifications and provides consolidated answer to the sip user agent.


presrules.py (RFC5025)

Parses and generates authorization rules in XML format for presence or other
applications. Authorization rules are stored on the XCAP server. The
presence rules are generated either based on user initiative or as a
response to a new subscription signaled by a change in the watcherinfo
application.


pidf.py (RFC3863)

This module provides classes to parse and generate PIDF documents, and also
uses the XML Application extensibility API to allow extensions to PIDF. It
is used to parse NOTIFY body for presence event and generates rich presence
state information for use with PUBLISH. Used to generate own presence
information and to parse the state of buddy lists entries we have subscribed
to. A SIP client typically instantiates a new pidf object for itself and for
each buddy it SUBSCRIBEs to and update each object when a NOTIFY is
received. The list of buddys is maintained using resourcelists application.


policy.py (RFC4745)

Generic data types to be used in policy applications.


presdm.py (RFC4479)

This module provides an extension to the PIDF (module sipsimple.applications.pidf)
to support the data module defined in RFC4479.


xcap-diff.py

Parses NOTIFY body for xcap-diff event. Used to detect changes in XCAP
documents changed by other device configured for the same presentity.


pidf-manipulation.py

Parses and generates pidf-manipulation stored on the XCAP server. Used to
publish persistent information which remains active after the user agent
goes off-line.


mwi.py

Parses NOTIFY body with message waiting indicator information. Used for
alerting the user about the presence of voice messages stored on the
voicemail server.


bonjour.py

Maintains state of online neighbours using multicast DNS technology. Used
for zero-conf functionality on the local LAN.

