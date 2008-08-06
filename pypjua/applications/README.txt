
SIP SIMPLE applications
-----------------------

This folder contains non-SIP applications required for implementing a
feature-rich SIP SIMPLE client.

The applications can be used for parsing and generating bodies carried using
PUBLISH/SUBSCRIBE/NOTIFY SIP methods. These SIP methods have been designed
for asynchronous event notifications and convey in real-time state and other
information between SIP end-points.

An example of state is presence, which in its basic form it provides user
availability information based on end-user choice. In its advanced form,
presence can provide rich state information including but not limited to
user mood, geo-location, environment, noise level and type of communication
desired. The information can be diseminated based on a granular policy which
allows end-user to device who has access to which part of the published
information.


watcherinfo.py 

Parses NOTIFY body for presence.winfo event. Used for keeping track of
watchers that subscribed to our presentity. Based on this information the
authorization rules can be managed using presrules.py. To retrieve this
information the SIP client must subscribe to its own address for event
presence.winfo.


resourcelists.py

Parses and generates XML documents for constructing resource lists and
rls-services documents. Used for server side storage of presence related
buddy lists using XCAP protocol. The SIP clients maintains the
resource-lists on the XCAP server which provides persisten storage and
aggregation point for multiple devices.


presrules.py

Parses and generates authorization rules in XML format for presence or other
applications. Authorization rules are stored on the XCAP server. The
presence rules are generated either based on user initiative or as a
response to a new subscription signaled by a change in the watherinfo
application.


pidf.py

Parses NOTIFY body for presence event and generates rich presence state
information published using PUBLISH. Used to generate own presence
information and to parse the state of buddy lists entries we have subscribed
to. A SIP client typically instantiates a new pidf object for itself and for
each buddy it SUBSCRIBEs to and update each object when a NOTIFY is
received. The list of buddys is maintained using resourcelists application.


xcap-diff.py

Parses NOTIFY body for xcap-diff event. Used to detect changes in XCAP
documents changed by other device configured for the same presentity.


pidf-manipulation.py

Parses and generates pidf-manipulation stored on the XCAP server. Used to
publish persistent information which remains active after the user agent
goes off-line.

mwi.py Parses NOTIFY body with message waiting indicator information. Used
for alerting the user about the presence of voice messages stored on the
voicemail server.

