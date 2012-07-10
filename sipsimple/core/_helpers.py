# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""Miscellaneous SIP related helpers"""

__all__ = ['Route']

import socket
from sipsimple.core._core import SIPURI


class Route(object):
    def __init__(self, address, port=None, transport='udp'):
        self.address = address
        self.port = port
        self.transport = transport

    def _get_address(self):
        return self._address
    def _set_address(self, address):
        try:
            socket.inet_aton(address)
        except:
            raise ValueError('illegal address: %s' % address)
        self._address = address
    address = property(_get_address, _set_address)
    del _get_address, _set_address

    def _get_port(self):
        if self._port is None:
            return 5060 if self.transport in ('udp', 'tcp') else 5061
        else:
            return self._port
    def _set_port(self, port):
        port = int(port) if port is not None else None
        if port is not None and not (0 < port < 65536):
            raise ValueError('illegal port value: %d' % port)
        self._port = port
    port = property(_get_port, _set_port)
    del _get_port, _set_port

    def _get_transport(self):
        return self._transport
    def _set_transport(self, transport):
        if transport not in ('udp', 'tcp', 'tls'):
            raise ValueError('illegal transport value: %s' % transport)
        self._transport = transport
    transport = property(_get_transport, _set_transport)
    del _get_transport, _set_transport

    @property
    def uri(self):
        if self.transport in ('udp', 'tcp') and self.port == 5060:
            port = None
        elif self.transport == 'tls' and self.port == 5061:
            port = None
        else:
            port = self.port
        parameters = {'transport': self.transport} if self.transport != 'udp' else {}
        return SIPURI(host=self.address, port=port, parameters=parameters)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__, self.address, self.port, self.transport)

    def __str__(self):
        return 'sip:%s:%d;transport=%s' % (self.address, self.port, self.transport)


