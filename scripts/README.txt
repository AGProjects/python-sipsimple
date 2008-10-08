
Command line tools
------------------

The following scripts are available to test the functionality of pypjua
library:

sip_register
sip_rtp_audio_session
sip_msrp_im_session
sip_msrp_file_transfer
sip_publish_presence
sip_subscribe_presence
sip_subscribe_winfo
sip_message

Some scripts can be used to setup audio (VoIP), interactive mesaging (IM)
and file transfer sessions. Other scripts can be used to publish presence
information and subscribe to presence or other type of event notifications.
Running each script with --help argument displays the script capabilities
and the required arguments.

You must have a SIP account in order to use these scripts. If you do not
have a SIP account you may register one for free at: http://sip2sip.info

After your have obtained a SIP account, create a configuration file in your
home directory called .sipclient/config.ini. This configuration file must
at least contain the credentials for your SIP account.

Example configuration file:

[Account]
sip_address=alice@example.com
password=1234
xcap_root=https://xcap.example.com/xcap-root/
presence=true

You may also create a configuration file with multiple accounts and select
one during runtime as follows:

[Account]
sip_address=alice@example.com
password=1234
xcap_root=https://xcap.example.com/xcap-root/
presence=true

[Account_blue]
username=bob@blue.example.com
password=1234
xcap_root=https://xcap.blue.example.com/xcap-root/
presence=true

[Account_green]
sip_address=alan@green.example.com
password=1234
xcap_root=https://xcap.green.example.com/xcap-root/
presence=true

At runtime you can select one of the configured accounts with -a NAME
parameter where NAME is the suffix of each defined accounts in the
configuration file.

