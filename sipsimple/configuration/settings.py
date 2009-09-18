# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
SIP SIMPLE settings.

Definition of general (non-account related) settings.
"""

import os

from sipsimple import __version__
from sipsimple.configuration import Setting, SettingsGroup, SettingsObject
from sipsimple.configuration.datatypes import ContentTypeList, NonNegativeInteger
from sipsimple.configuration.datatypes import AudioCodecs, AudioInputDevice, AudioOutputDevice, SampleRate
from sipsimple.configuration.datatypes import LocalIPAddress, MSRPTransport, Port, PortRange, TLSProtocol, Transports
from sipsimple.configuration.datatypes import ImageDepth, Resolution
from sipsimple.configuration.datatypes import Path, SoundFile , UserDataPath


__all__ = ['SIPSimpleSettings']


class AudioSettings(SettingsGroup):
    alert_device = Setting(type=AudioOutputDevice, default='system_default', nillable=True)
    input_device = Setting(type=AudioInputDevice, default='system_default', nillable=True)
    output_device = Setting(type=AudioOutputDevice, default='system_default', nillable=True)
    tail_length = Setting(type=NonNegativeInteger, default=200)
    directory = Setting(type=UserDataPath, default=UserDataPath('history'))
    sample_rate = Setting(type=SampleRate, default=32000)
    silent = Setting(type=bool, default=False)


class ChatSettings(SettingsGroup):
    directory = Setting(type=UserDataPath, default=UserDataPath('history'))


class DesktopSharingSettings(SettingsGroup):
    color_depth = Setting(type=ImageDepth, default=8)
    resolution = Setting(type=Resolution, default=Resolution(width=1024, height=768))
    client_command = Setting(type=Path, default=None, nillable=True)
    server_command = Setting(type=Path, default=None, nillable=True)


class FileTransferSettings(SettingsGroup):
    directory = Setting(type=UserDataPath, default=UserDataPath('file_transfers'))


class LogsSettings(SettingsGroup):
    directory = Setting(type=UserDataPath, default=UserDataPath('logs'))
    trace_sip = Setting(type=bool, default=False)
    trace_pjsip = Setting(type=bool, default=False)
    trace_msrp = Setting(type=bool, default=False)
    trace_xcap = Setting(type=bool, default=False)
    trace_notifications = Setting(type=bool, default=False)
    pjsip_level = Setting(type=NonNegativeInteger, default=5)


class MSRPSettings(SettingsGroup):
    transport = Setting(type=MSRPTransport, default='tls')
    port = Setting(type=Port, default=0)


class RTPSettings(SettingsGroup):
    ip_address = Setting(type=LocalIPAddress, default=LocalIPAddress())
    port_range = Setting(type=PortRange, default=PortRange(50000, 50400))
    timeout = Setting(type=NonNegativeInteger, default=30)
    audio_codecs = Setting(type=AudioCodecs, default=('speex', 'G722', 'PCMU', 'PCMA', 'iLBC', 'GSM'))


class SIPSettings(SettingsGroup):
    ip_address = Setting(type=LocalIPAddress, default=LocalIPAddress())
    udp_port = Setting(type=Port, default=0)
    tcp_port = Setting(type=Port, default=0)
    tls_port = Setting(type=Port, default=0)
    transports = Setting(type=Transports, default=('tls', 'tcp', 'udp'))


class TLSSettings(SettingsGroup):
    ca_list = Setting(type=UserDataPath, default=None, nillable=True)
    certificate = Setting(type=UserDataPath, default=None, nillable=True)
    private_key = Setting(type=UserDataPath, default=None, nillable=True)
    protocol = Setting(type=TLSProtocol, default='TLSv1')
    verify_server = Setting(type=bool, default=False)
    timeout = Setting(type=NonNegativeInteger, default=1000)

class SoundsSettings(SettingsGroup):
    audio_inbound = Setting(type=SoundFile, default=None, nillable=True)
    audio_outbound = Setting(type=SoundFile, default=None, nillable=True)
    message_received = Setting(type=SoundFile, default=None, nillable=True)
    message_sent = Setting(type=SoundFile, default=None, nillable=True)
    file_received = Setting(type=SoundFile, default=None, nillable=True)
    file_sent = Setting(type=SoundFile, default=None, nillable=True)
    answering_machine = Setting(type=SoundFile, default=None, nillable=True)

class SIPSimpleSettings(SettingsObject):
    __section__ = 'Global'
    __id__ = 'SIPSimple'
    
    user_data_directory = Setting(type=Path, default=os.path.expanduser('~/.sipclient'))
    resources_directory = Setting(type=Path, default=None, nillable=True)
    default_account = Setting(type=str, default='bonjour@local', nillable=True)
    user_agent = Setting(type=str, default='sipsimple %s' % __version__)

    audio = AudioSettings
    chat = ChatSettings
    desktop_sharing = DesktopSharingSettings
    file_transfer = FileTransferSettings
    sounds = SoundsSettings 
    logs = LogsSettings
    msrp = MSRPSettings
    rtp = RTPSettings
    sip = SIPSettings
    tls = TLSSettings


