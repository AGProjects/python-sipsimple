from application.python.util import Singleton
from sipsimple.engine import Engine
from sipsimple.configuration.settings import SIPSimpleSettings

class ConfiguredEngine(object):
    """Configuration-aware Engine"""

    __metaclass__ = Singleton
    klass = Engine

    def __init__(self, *args, **kwargs):
        self._obj = kwargs.pop('__obj', None)
        if self._obj is None:
            self._obj = self.klass(*args, **kwargs)
        else:
            assert not args, args
            assert not kwargs, kwargs

    def __getattr__(self, item):
        if item == '_obj':
            raise AttributeError(item)
        return getattr(self._obj, item)

    def start(self, sound=True, local_ip=None, **kwargs):
        settings = SIPSimpleSettings()
        if local_ip is None:
            local_ip = settings.local_ip.value
        setdefault(kwargs,
            local_udp_port=settings.sip.local_udp_port if "udp" in settings.sip.transports else None,
            local_tcp_port=settings.sip.local_tcp_port if "tcp" in settings.sip.transports else None,
            local_tls_port=settings.sip.local_tls_port if "tls" in settings.sip.transports else None,
            tls_protocol=settings.tls.protocol,
            tls_verify_server=settings.tls.verify_server,
            tls_ca_file=settings.tls.ca_list_file.value if settings.tls.ca_list_file is not None else None,
            tls_cert_file=settings.tls.certificate_file.value if settings.tls.certificate_file is not None else None,
            tls_privkey_file=settings.tls.private_key_file.value if settings.tls.private_key_file is not None else None,
            tls_timeout=settings.tls.timeout,
            ec_tail_length=settings.audio.echo_delay,
            user_agent=settings.user_agent,
            sample_rate=settings.audio.sample_rate,
            playback_dtmf=settings.audio.playback_dtmf,
            rtp_port_range=(settings.rtp.port_range.start, settings.rtp.port_range.end))
        self._obj.start(auto_sound=False, local_ip=local_ip, **kwargs)
        if sound:
            self._obj.set_sound_devices(playback_device=settings.audio.output_device, recording_device=settings.audio.input_device)

def setdefault(where, **what):
    for k, x in what.iteritems():
        where.setdefault(k, x)

