
PyPjUA test scripts
-------------------

These scripts have been tested against the following SIP server software:
OpenSER, OpenXCAP, MSRPRelay and MediaProxy.

The following scripts are available to test the functionality of pypjua
library:

- sip_register
- sip_rtp_audio_session
- sip_msrp_im_session
- sip_msrp_file_transfer
- sip_presence_publish
- sip_presence_subscribe
- sip_message

Some scripts can be used to setup audio (VoIP), interactive mesaging (IM)
and file transfer sessions. Other scripts can be used to publish presence
information and subscribe to presence or other type of event notifications.
Running each script with --help argument displays the script capabilities
and the required arguments.

You must have a SIP account in order to use these scripts. If you do not
have a SIP account you may register one for free at http://sip2sip.info

After your have obtained a SIP account, create a configuration file in your
home directory called pypjua.ini. This configuration file must contain the
credentials for your SIP account.

Example configuration file:

[Account]
username=alice
domain=example.com
password=1234
xcap_root=https://xcap.example.com/xcap-root/

