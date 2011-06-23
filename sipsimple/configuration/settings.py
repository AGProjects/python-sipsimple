# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
SIP SIMPLE settings.

Definition of general (non-account related) settings.
"""

from sipsimple import __version__
from sipsimple.configuration import CorrelatedSetting, Setting, SettingsGroup, SettingsObject
from sipsimple.configuration.datatypes import NonNegativeInteger, PJSIPLogLevel
from sipsimple.configuration.datatypes import AudioCodecList, SampleRate
from sipsimple.configuration.datatypes import Port, PortRange, SIPTransportList, TLSProtocol
from sipsimple.configuration.datatypes import Path


__all__ = ['SIPSimpleSettings']


class AudioSettings(SettingsGroup):
    alert_device = Setting(type=unicode, default=u'system_default', nillable=True)
    input_device = Setting(type=unicode, default=u'system_default', nillable=True)
    output_device = Setting(type=unicode, default=u'system_default', nillable=True)
    tail_length = Setting(type=NonNegativeInteger, default=100)
    sample_rate = Setting(type=SampleRate, default=44100)
    silent = Setting(type=bool, default=False)


class ChatSettings(SettingsGroup):
    pass


class DesktopSharingSettings(SettingsGroup):
    pass


class FileTransferSettings(SettingsGroup):
    pass


class LogsSettings(SettingsGroup):
    pjsip_level = Setting(type=PJSIPLogLevel, default=5)


class RTPSettings(SettingsGroup):
    port_range = Setting(type=PortRange, default=PortRange(50000, 50500))
    timeout = Setting(type=NonNegativeInteger, default=30)
    audio_codec_list = Setting(type=AudioCodecList, default=AudioCodecList(('G722', 'speex', 'PCMU', 'PCMA')))


def sip_port_validator(port, sibling_port):
    if port == sibling_port != 0:
        raise ValueError("the TCP and TLS ports must be different")

class SIPSettings(SettingsGroup):
    invite_timeout = Setting(type=NonNegativeInteger, default=90, nillable=True)
    udp_port = Setting(type=Port, default=0)
    tcp_port = CorrelatedSetting(type=Port, sibling='tls_port', validator=sip_port_validator, default=0)
    tls_port = CorrelatedSetting(type=Port, sibling='tcp_port', validator=sip_port_validator, default=0)
    transport_list = Setting(type=SIPTransportList, default=SIPTransportList(('tls', 'tcp', 'udp')))


class TLSSettings(SettingsGroup):
    ca_list = Setting(type=Path, default=None, nillable=True)
    protocol = Setting(type=TLSProtocol, default='TLSv1')
    timeout = Setting(type=NonNegativeInteger, default=3000)


class SIPSimpleSettings(SettingsObject):
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


