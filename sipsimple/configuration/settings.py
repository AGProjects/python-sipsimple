# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
SIP SIMPLE settings.

Definition of general (non-account related) settings.
"""

import os

from sipsimple import __version__
from sipsimple.configuration import Setting, SettingsGroup, SettingsObject
from sipsimple.configuration.datatypes import Path, ContentTypeList, UserDataPath, ImageDepth, LocalIPAddress, MSRPTransport, NonNegativeInteger, Port, PortRange, Resolution, SampleRate, SoundFile, TLSProtocol, Transports, AudioCodecs


__all__ = ['SIPSimpleSettings']


class AudioSettings(SettingsGroup):
    alert_device = Setting(type=str, default=None, nillable=True)
    input_device = Setting(type=str, default=None, nillable=True)
    output_device = Setting(type=str, default=None, nillable=True)
    tail_length = Setting(type=NonNegativeInteger, default=200)
    recordings_directory = Setting(type=UserDataPath, default=UserDataPath('history'))
    sample_rate = Setting(type=SampleRate, default=32000)
    silent = Setting(type=bool, default=False)
    codec_list = Setting(type=AudioCodecs, default=('speex', 'G722', 'PCMU', 'PCMA', 'iLBC', 'GSM'))


class ChatSettings(SettingsGroup):
    message_received_sound = Setting(type=SoundFile, default=None, nillable=True)
    message_sent_sound = Setting(type=SoundFile, default=None, nillable=True)
    history_directory = Setting(type=UserDataPath, default=UserDataPath('history'))
    accept_types = Setting(type=ContentTypeList, default=('message/cpim', 'text/*'))
    accept_wrapped_types = Setting(type=ContentTypeList, default=('*',))


class DesktopSharingSettings(SettingsGroup):
    color_depth = Setting(type=ImageDepth, default=8)
    resolution = Setting(type=Resolution, default=Resolution(width=1024, height=768))
    client_command = Setting(type=Path, default=None, nillable=True)
    server_command = Setting(type=Path, default=None, nillable=True)


class FileTransferSettings(SettingsGroup):
    directory = Setting(type=UserDataPath, default=UserDataPath('file_transfers'))
    file_received_sound = Setting(type=SoundFile, default=None, nillable=True)
    file_sent_sound = Setting(type=SoundFile, default=None, nillable=True)


class LoggingSettings(SettingsGroup):
    directory = Setting(type=UserDataPath, default=UserDataPath('logs'))
    trace_sip = Setting(type=bool, default=False)
    trace_pjsip = Setting(type=bool, default=False)
    trace_msrp = Setting(type=bool, default=False)
    trace_xcap = Setting(type=bool, default=False)
    trace_notifications = Setting(type=bool, default=False)
    pjsip_level = Setting(type=NonNegativeInteger, default=5)


class MSRPSettings(SettingsGroup):
    transport = Setting(type=MSRPTransport, default='tls')
    local_port = Setting(type=Port, default=0)


class RingtoneSettings(SettingsGroup):
    inbound = Setting(type=SoundFile, default=None, nillable=True)
    outbound = Setting(type=SoundFile, default=None, nillable=True)


class RTPSettings(SettingsGroup):
    port_range = Setting(type=PortRange, default=PortRange(50000, 50400))
    timeout = Setting(type=NonNegativeInteger, default=30)
    local_ip = Setting(type=LocalIPAddress, default=LocalIPAddress())


class SIPSettings(SettingsGroup):
    local_udp_port = Setting(type=Port, default=0)
    local_tcp_port = Setting(type=Port, default=0)
    local_tls_port = Setting(type=Port, default=0)
    transports = Setting(type=Transports, default=('tls', 'tcp', 'udp'))
    ignore_missing_ack = Setting(type=bool, default=False)


class TLSSettings(SettingsGroup):
    ca_list_file = Setting(type=UserDataPath, default=None, nillable=True)
    certificate_file = Setting(type=UserDataPath, default=None, nillable=True)
    private_key_file = Setting(type=UserDataPath, default=None, nillable=True)
    protocol = Setting(type=TLSProtocol, default='TLSv1')
    verify_server = Setting(type=bool, default=False)
    timeout = Setting(type=NonNegativeInteger, default=1000)


class SIPSimpleSettings(SettingsObject):
    __section__ = 'Global'
    __id__ = 'SIPSimple'
    
    user_data_directory = Setting(type=Path, default=os.path.expanduser('~/.sipclient'))
    resources_directory = Setting(type=Path, default=None, nillable=True)
    default_account = Setting(type=str, default='bonjour@local', nillable=True)
    local_ip = Setting(type=LocalIPAddress, default=LocalIPAddress(), nillable=True)
    user_agent = Setting(type=str, default='sipsimple %s' % __version__)

    audio = AudioSettings
    chat = ChatSettings
    desktop_sharing = DesktopSharingSettings
    file_transfer = FileTransferSettings
    logging = LoggingSettings
    msrp = MSRPSettings
    ringtone = RingtoneSettings
    rtp = RTPSettings
    sip = SIPSettings
    tls = TLSSettings


