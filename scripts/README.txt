
Command line tools
------------------

Command line tools are available for setting up audio, Instant Messaging
(IM) and file transfer sessions, publish and subscribe to presence or other
type of events.

Running each script with --help argument displays the script capabilities
and the required arguments.

The command line tools require the presence of a configuration file
~/.sipclient/config.ini that contains at least one SIP account. Each SIP
account definition contains the credentials and other settings.

You need a SIP account from a service provider or to setup your own SIP
infrastructure using the following elements:

OpenSIPS >= 1.4.2 from http://opensips.org
OpenXCAP >= 1.0.6 from http://openxcap.org
MSRPRelay >= 1.0.0 from http://msrprelay.org

A SIP account with all SIP SIMPLE client features can be obtained for free
from http://sip2sip.info

A sample configuration file is generated at first run of any of the command
line tools as follows:

[Account]
sip_address=alice@example.com
password=1234
xcap_root=https://xcap.example.com/xcap-root/
use_presence_agent=true

Outbound proxy setting

If the outbound_proxy option is set the SIP messages will always go
throughthe proxy determined from this setting. Otherwise the outbound proxy
is the SIP registrar for the account's own domain, which is looked up based
on the logic from RFC 3263. The outbound proxy syntax can be one of the
following :

 - domain name (for which DNS SRV and A record lookups will be performed)
 - hostname:port combination (for which DNS A record lookup will be performed)
 - hostname (for which DNS A record lookup will be performed)
 - IP
 - IP:port

MSRP relay setting

If the msrp_relay option is set the MSRP connections will always be
established through the relay determined from this setting. Otherwise by
default an ougoing MSRP connection will use no relay and an incomming MSRP
connection will use the relay configured in the DNS for the called SIP
account.

The MSRP relay syntax can be one of the following :

 - domain name (for which DNS SRV and A record lookups will be performed) -
 hostname:port combination (for which DNS A record lookup will be performed)
 - hostname (for which DNS A record lookup will be performed) - IP - IP:port

Is possible to define multiple accounts and select one of them with -a NAME
parameter where NAME is the suffix of each defined accounts in the
configuration file:

[Account]
sip_address=alice@example.com
password=1234
xcap_root=https://xcap.example.com/xcap-root/
use_presence_agent=true

[Account_blue]
username=bob@blue.example.com
password=1234
xcap_root=https://xcap.blue.example.com/xcap-root/
use_presence_agent=true

[Account_green]
sip_address=alan@green.example.com
password=1234

; XCAP settings
xcap_root=https://xcap.green.example.com/xcap-root/

; Presence settings 
use_presence_agent=true
subscribe_rls_services=true

; MSRP settings
msrp_relay=msrprelay.example.com

For all available settings of the configuration file see config.ini.sample

