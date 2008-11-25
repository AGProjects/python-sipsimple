
Command line tools
------------------

Several command line tools are available for setting up real time voice, IM
and file transfer sessions, publish and subscribe to presence or other type
of events:

 * sip_register - REGISTER a SIP end-point with a SIP REGISTRAR
 * sip_audio_session - Setup a voice audio session (VoIP)
 * sip_msrp_im_session - Setup an IM session using MSRP protocol
 * sip_msrp_file_transfer - File Transfer session using MSRP protocol
 * sip_message - Send text message in page mode using MESSAGE method
 * sip_publish_presence - PUBLISH presence to a SIP Presence Agent
 * sip_subscribe_presence - SUBSCRIBE to presence information
 * sip_subscribe_winfo - SUBSCRIBE to watcher list on a SIP Presence Agent
 * sip_subscribe_rls - SUBSCRIBE to lists managed by Resource List Server

Running each script with --help argument displays the script capabilities
and the required arguments.

You must have a SIP account in order to use these scripts. If you do not
have a SIP account you may register one for free at: http://sip2sip.info.
After your have obtained a SIP account, create a configuration file in your
home directory called .sipclient/config.ini. This configuration file must
contain the credentials for your SIP account.

A sample configuration file is generated at first run of any of the command
line tools as follows:

[Account]
sip_address=alice@example.com
password=1234
xcap_root=https://xcap.example.com/xcap-root/
use_presence_agent=true

You may also define multiple accounts and select one during runtime as
follows:

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
xcap_root=https://xcap.green.example.com/xcap-root/
use_presence_agent=true

At runtime you can select one of the configured accounts with -a NAME
parameter where NAME is the suffix of each defined accounts in the
configuration file.

