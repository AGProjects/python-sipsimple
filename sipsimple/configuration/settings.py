# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

"""
SIP SIMPLE settings.

Definition of general (non-account related) settings.
"""

from application.python.util import Singleton

from sipsimple import __version__
from sipsimple.configuration import Setting, SettingsGroup, SettingsObject
from sipsimple.configuration.datatypes import NonNegativeInteger
from sipsimple.configuration.datatypes import AudioCodecList, AudioInputDevice, AudioOutputDevice, SampleRate
from sipsimple.configuration.datatypes import MSRPTransport, Port, PortRange, SIPTransportList, TLSProtocol
from sipsimple.configuration.datatypes import Path


__all__ = ['SIPSimpleSettings']


class AudioSettings(SettingsGroup):
    alert_device = Setting(type=AudioOutputDevice, default='system_default', nillable=True)
    input_device = Setting(type=AudioInputDevice, default='system_default', nillable=True)
    output_device = Setting(type=AudioOutputDevice, default='system_default', nillable=True)
    tail_length = Setting(type=NonNegativeInteger, default=200)
    sample_rate = Setting(type=SampleRate, default=44100)
    silent = Setting(type=bool, default=False)


class ChatSettings(SettingsGroup):
    pass


class DesktopSharingSettings(SettingsGroup):
    pass


class FileTransferSettings(SettingsGroup):
    pass


class LogsSettings(SettingsGroup):
    pjsip_level = Setting(type=NonNegativeInteger, default=5)


class RTPSettings(SettingsGroup):
    port_range = Setting(type=PortRange, default=PortRange(50000, 50400))
    timeout = Setting(type=NonNegativeInteger, default=30)
    audio_codec_list = Setting(type=AudioCodecList, default=AudioCodecList(('speex', 'G722', 'PCMU', 'PCMA')))


class SIPSettings(SettingsGroup):
    invite_timeout = Setting(type=NonNegativeInteger, default=180, nillable=True)
    udp_port = Setting(type=Port, default=0)
    tcp_port = Setting(type=Port, default=0)
    tls_port = Setting(type=Port, default=0)
    transport_list = Setting(type=SIPTransportList, default=SIPTransportList(('tls', 'tcp', 'udp')))


class TLSSettings(SettingsGroup):
    ca_list = Setting(type=Path, default=None, nillable=True)
    protocol = Setting(type=TLSProtocol, default='TLSv1')
    timeout = Setting(type=NonNegativeInteger, default=1000)


class SIPSimpleSettings(SettingsObject):
    __metaclass__ = Singleton

    __id__ = 'SIPSimpleSettings'

    default_account = Setting(type=str, default='bonjour@local', nillable=True)
    user_agent = Setting(type=str, default='sipsimple %s' % __version__)

    audio = AudioSettings
    chat = ChatSettings
    desktop_sharing = DesktopSharingSettings
    file_transfer = FileTransferSettings
    logs = LogsSettings
    rtp = RTPSettings
    sip = SIPSettings
    tls = TLSSettings


