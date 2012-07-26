# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""Miscellaneous SIP related helpers"""

__all__ = ['Route', 'ContactURIFactory', 'NoGRUU', 'PublicGRUU', 'TemporaryGRUU', 'PublicGRUUIfAvailable', 'TemporaryGRUUIfAvailable']

import random
import socket
import string

from application.python.types import MarkerType
from application.system import host

from sipsimple.core._core import SIPURI
from sipsimple.core._engine import Engine


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


class ContactURIType(MarkerType): pass

class NoGRUU:                   __metaclass__ = ContactURIType
class PublicGRUU:               __metaclass__ = ContactURIType
class TemporaryGRUU:            __metaclass__ = ContactURIType
class PublicGRUUIfAvailable:    __metaclass__ = ContactURIType
class TemporaryGRUUIfAvailable: __metaclass__ = ContactURIType


class ContactURIFactory(object):
    def __init__(self, username=None):
        self.username = username or ''.join(random.sample(string.lowercase, 8))
        self.public_gruu = None
        self.temporary_gruu = None

    def __repr__(self):
        return '%s(username=%r)' % (self.__class__.__name__, self.username)

    def __getitem__(self, key):
        if isinstance(key, tuple):
            contact_type, key = key
            if not isinstance(contact_type, ContactURIType):
                raise KeyError("unsupported contact type: %r" % contact_type)
        else:
            contact_type = NoGRUU
        if not isinstance(key, (basestring, Route)):
            raise KeyError("key must be a transport name or Route instance")

        transport = key if isinstance(key, basestring) else key.transport
        parameters = {} if transport=='udp' else {'transport': transport}

        if contact_type is PublicGRUU:
            if self.public_gruu is None:
                raise KeyError("could not get Public GRUU")
            uri = SIPURI.new(self.public_gruu)
        elif contact_type is TemporaryGRUU:
            if self.temporary_gruu is None:
                raise KeyError("could not get Temporary GRUU")
            uri = SIPURI.new(self.temporary_gruu)
        elif contact_type is PublicGRUUIfAvailable and self.public_gruu is not None:
            uri = SIPURI.new(self.public_gruu)
        elif contact_type is TemporaryGRUUIfAvailable and self.temporary_gruu is not None:
            uri = SIPURI.new(self.temporary_gruu)
        else:
            ip = host.default_ip if isinstance(key, basestring) else host.outgoing_ip_for(key.address)
            if ip is None:
                raise KeyError("could not get outgoing IP address")
            port = getattr(Engine(), '%s_port' % transport, None)
            if port is None:
                raise KeyError("unsupported transport: %s" % transport)
            uri = SIPURI(user=self.username, host=ip, port=port)
        uri.parameters.update(parameters)
        return uri


