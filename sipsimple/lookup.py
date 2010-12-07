# Copyright (C) 2008-2010 AG Projects. See LICENSE for details.
#

"""
Implements DNS lookups in the context of SIP, STUN and MSRP relay based
on RFC3263 and related standards. This can be used to determine the next
hop(s) and failover for routing of SIP messages and reservation of network
resources prior the starting of a SIP session.
"""

from __future__ import absolute_import

import re
from itertools import chain
from time import time
from urlparse import urlparse

# patch dns.entropy module which is not thread-safe
import dns
import sys
from functools import partial
from random import randint, randrange

dns.entropy = dns.__class__('dns.entropy')
dns.entropy.__file__ = dns.__file__.replace('__init__.py', 'entropy.py')
dns.entropy.__builtins__ = dns.__builtins__
dns.entropy.random_16 = partial(randrange, 2**16)
dns.entropy.between = randint

sys.modules['dns.entropy'] = dns.entropy

del partial, randint, randrange, sys

# replace standard select and socket modules with versions from eventlet
from eventlet.green import select
from eventlet.green import socket
import dns.resolver
import dns.query
dns.resolver.socket = socket
dns.query.select = select
dns.query.socket = socket

from application.notification import NotificationCenter
from application.python.decorator import decorator, preserve_signature
from dns import exception, rdatatype

from sipsimple.util import Route, TimestampedNotificationData, limit, run_in_waitable_green_thread


def domain_iterator(domain):
    """
    A generator which returns the domain and its parent domains.
    """
    while domain not in ('.', ''):
        yield domain
        domain = (domain.split('.', 1)+[''])[1]


@decorator
def post_dns_lookup_notifications(func):
    @preserve_signature(func)
    def wrapper(obj, *args, **kwargs):
        notification_center = NotificationCenter()
        try:
            result = func(obj, *args, **kwargs)
        except DNSLookupError, e:
            notification_center.post_notification('DNSLookupDidFail', sender=obj, data=TimestampedNotificationData(error=str(e)))
            raise
        else:
            notification_center.post_notification('DNSLookupDidSucceed', sender=obj, data=TimestampedNotificationData(result=result))
            return result
    return wrapper


class DNSLookupError(Exception):
    """
    The error raised by DNSLookup when a lookup cannot be performed.
    """


class DNSCache(object):
    """
    A simple DNS cache which uses twisted's timers to invalidate its expired
    data.
    """
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key, None)

    def put(self, key, value):
        from twisted.internet import reactor
        expiration = value.expiration-time()
        if expiration > 0:
            self.data[key] = value
            reactor.callLater(limit(expiration, max=3600), self.data.pop, key, None)

    def flush(self, key=None):
        if key is not None:
            self.data.pop(key, None)
        else:
            self.data = {}


class DNSResolver(dns.resolver.Resolver):
    """
    The resolver used by DNSLookup.

    The lifetime setting on it applies to all the queries made on this resolver.
    Each time a query is performed, its duration is subtracted from the lifetime
    value.
    """

    def __init__(self):
        dns.resolver.Resolver.__init__(self, configure=False)
        default_resolver = dns.resolver.get_default_resolver()
        self.search = default_resolver.search
        self.domain = default_resolver.domain
        self.nameservers = ['8.8.8.8', '8.8.4.4']

    def query(self, *args, **kw):
        start_time = time()
        try:
            return dns.resolver.Resolver.query(self, *args, **kw)
        finally:
            self.lifetime -= min(self.lifetime, time()-start_time)


class SRVResult(object):
    """
    Internal object used to save the result of SRV queries.
    """
    def __init__(self, priority, weight, port, address):
        self.priority = priority
        self.weight = weight
        self.port = port
        self.address = address


class NAPTRResult(object):
    """
    Internal object used to save the result of NAPTR queries.
    """
    def __init__(self, service, order, preference, priority, weight, port, address):
        self.service = service
        self.order = order
        self.preference = preference
        self.priority = priority
        self.weight = weight
        self.port = port
        self.address = address


class DNSLookup(object):

    cache = DNSCache()

    @run_in_waitable_green_thread
    @post_dns_lookup_notifications
    def lookup_service(self, uri, service, timeout=3.0, lifetime=15.0):
        """
        Performs an SRV query to determine the servers used for the specified
        service from the domain in uri.host. If this fails and falling back is
        supported, also performs an A query on uri.host, returning the default
        port of the service along with the IP addresses in the answer.

        The services supported are `stun' and 'msrprelay'.

        The DNSLookupDidSucceed notification contains a result attribute which
        is a list of (address, port) tuples. The DNSLookupDidFail notification
        contains an error attribute describing the error encountered.
        """
        service_srv_record_map = {"stun": ("_stun._udp", 3478, False),
                                  "msrprelay": ("_msrps._tcp", 2855, True)}
        log_context = dict(context='lookup_service', service=service, uri=uri)

        try:
            service_prefix, service_port, service_fallback = service_srv_record_map[service]
        except KeyError:
            raise DNSLookupError("Unknown service: %s" % service)

        try:
            resolver = DNSResolver()
            resolver.cache = self.cache
            resolver.timeout = timeout
            resolver.lifetime = lifetime

            # If the host part of the URI is an IP address, we will not do any lookup
            if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", uri.host):
                return [(uri.host, uri.port or service_port)]

            record_name = '%s.%s' % (service_prefix, uri.host)
            services = self._lookup_srv_records(resolver, [record_name], log_context=log_context)
            if services[record_name]:
                return [(result.address, result.port) for result in services[record_name]]
            elif service_fallback:
                addresses = self._lookup_a_records(resolver, [uri.host], log_context=log_context)
                if addresses[uri.host]:
                    return [(addr, service_port) for addr in addresses[uri.host]]
        except dns.resolver.Timeout:
            raise DNSLookupError('Timeout in lookup for %s servers for domain %s' % (service, uri.host))
        else:
            raise DNSLookupError('No %s servers found for domain %s' % (service, uri.host))


    @run_in_waitable_green_thread
    @post_dns_lookup_notifications
    def lookup_sip_proxy(self, uri, supported_transports, timeout=3.0, lifetime=15.0):
        """
        Performs an RFC 3263 compliant lookup of transport/ip/port combinations
        for a particular SIP URI. As arguments it takes a SIPURI object
        and a list of supported transports, in order of preference of the
        application. It returns a list of Route objects that can be used in
        order of preference.

        The DNSLookupDidSucceed notification contains a result attribute which
        is a list of Route objects. The DNSLookupDidFail notification contains
        an error attribute describing the error encountered.
        """

        naptr_service_transport_map = {"sips+d2t": "tls",
                                       "sip+d2t": "tcp",
                                       "sip+d2u": "udp"}
        transport_service_map = {"udp": "_sip._udp",
                                 "tcp": "_sip._tcp",
                                 "tls": "_sips._tcp"}

        log_context = dict(context='lookup_sip_proxy', uri=uri)

        if not supported_transports:
            raise DNSLookupError("No transports are supported")
        supported_transports = [transport.lower() for transport in supported_transports]
        unknown_transports = set(supported_transports).difference(transport_service_map)
        if unknown_transports:
            raise DNSLookupError("Unknown transports: %s" % ', '.join(unknown_transports))

        try:
            resolver = DNSResolver()
            resolver.cache = self.cache
            resolver.timeout = timeout
            resolver.lifetime = lifetime

            # If the host part of the URI is an IP address, we will not do any lookup
            if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", uri.host):
                transport = 'tls' if uri.secure else uri.parameters.get('transport', 'udp').lower()
                if transport not in supported_transports:
                    raise DNSLookupError("Transport %s dictated by URI is not supported" % transport)
                port = uri.port or (5061 if transport=='tls' else 5060)
                return [Route(address=uri.host, port=port, transport=transport)]

            # If the port is specified in the URI, we will only do an A lookup
            elif uri.port:
                transport = 'tls' if uri.secure else uri.parameters.get('transport', 'udp')
                if transport not in supported_transports:
                    raise DNSLookupError("Transport %s dictated by URI is not supported" % transport)
                addresses = self._lookup_a_records(resolver, [uri.host], log_context=log_context)
                if addresses[uri.host]:
                    return [Route(address=addr, port=uri.port, transport=transport) for addr in addresses[uri.host]]

            # If the transport was already set as a parameter on the SIP URI, only do SRV lookups
            elif 'transport' in uri.parameters:
                transport = uri.parameters['transport'].lower()
                if transport not in supported_transports:
                    raise DNSLookupError("Requested lookup for URI with %s transport, but it is not supported" % transport)
                if uri.secure and transport != 'tls':
                    raise DNSLookupError("Requested lookup for SIPS URI, but with %s transport parameter" % transport)
                record_name = '%s.%s' % (transport_service_map[transport], uri.host)
                services = self._lookup_srv_records(resolver, [record_name], log_context=log_context)
                if services[record_name]:
                    return [Route(address=result.address, port=result.port, transport=transport) for result in services[record_name]]
                else:
                    # If SRV lookup fails, try A lookup
                    addresses = self._lookup_a_records(resolver, [uri.host], log_context=log_context)
                    port = 5061 if transport=='tls' else 5060
                    if addresses[uri.host]:
                        return [Route(address=addr, port=port, transport=transport) for addr in addresses[uri.host]]

            # Otherwise, it means we don't have a numeric IP address, a port isn't specified and neither is a transport. So we have to do a full NAPTR lookup
            else:
                # If the URI is a SIPS URI, we only support the TLS transport.
                if uri.secure:
                    if 'tls' not in supported_transports:
                        raise DNSLookupError("Requested lookup for SIPS URI, but TLS transport is not supported")
                    supported_transports = ['tls']
                # First try NAPTR lookup
                naptr_services = [service for service, transport in naptr_service_transport_map.iteritems() if transport in supported_transports]
                pointers = self._lookup_naptr_record(resolver, uri.host, naptr_services, log_context=log_context)
                if pointers:
                    return [Route(address=result.address, port=result.port, transport=naptr_service_transport_map[result.service]) for result in pointers]
                else:
                    # If that fails, try SRV lookup
                    routes = []
                    for transport in supported_transports:
                        record_name = '%s.%s' % (transport_service_map[transport], uri.host)
                        services = self._lookup_srv_records(resolver, [record_name], log_context=log_context)
                        if services[record_name]:
                            routes.extend(Route(address=result.address, port=result.port, transport=transport) for result in services[record_name])
                    if routes:
                        return routes
                    else:
                        # If SRV lookup fails, try A lookup
                        transport = 'tls' if uri.secure else 'udp'
                        if transport in supported_transports:
                            addresses = self._lookup_a_records(resolver, [uri.host], log_context=log_context)
                            port = 5061 if transport=='tls' else 5060
                            if addresses[uri.host]:
                                return [Route(address=addr, port=port, transport=transport) for addr in addresses[uri.host]]
        except dns.resolver.Timeout:
            raise DNSLookupError("Timeout in lookup for routes for SIP URI %s" % uri)
        else:
            raise DNSLookupError("No routes found for SIP URI %s" % uri)

    @run_in_waitable_green_thread
    @post_dns_lookup_notifications
    def lookup_xcap_server(self, uri, timeout=3.0, lifetime=15.0):
        """
        Performs a TXT query against xcap.<uri.host> and returns all results
        that look like HTTP URIs.
        """
        log_context = dict(context='lookup_xcap_server', uri=uri)
        notification_center = NotificationCenter()

        try:
            resolver = DNSResolver()
            resolver.cache = self.cache
            resolver.timeout = timeout
            resolver.lifetime = lifetime

            # If the host part of the URI is an IP address, we cannot not do any lookup
            if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", uri.host):
                raise DNSLookupError("Cannot perform DNS query because the host is an IP address")

            record_name = 'xcap.%s' % uri.host
            results = []
            try:
                answer = resolver.query(record_name, rdatatype.TXT)
            except dns.resolver.Timeout, e:
                notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='TXT', query_name=str(record_name), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
                raise
            except exception.DNSException, e:
                notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='TXT', query_name=str(record_name), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
            else:
                notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='TXT', query_name=str(record_name), nameservers=resolver.nameservers, answer=answer, error=None, **log_context))
                for result_uri in list(chain(*(r.strings for r in answer.rrset))):
                    parsed_uri = urlparse(result_uri)
                    if parsed_uri.scheme in ('http', 'https') and parsed_uri.netloc:
                        results.append(result_uri)
            if not results:
                raise DNSLookupError('No XCAP servers found for domain %s' % uri.host)
            return results
        except dns.resolver.Timeout:
            raise DNSLookupError('Timeout in lookup for XCAP servers for domain %s' % uri.host)


    def _lookup_a_records(self, resolver, hostnames, additional_records=[], log_context={}):
        notification_center = NotificationCenter()
        additional_addresses = dict((rset.name.to_text(), rset) for rset in additional_records if rset.rdtype == rdatatype.A)
        addresses = {}
        for hostname in hostnames:
            if hostname in additional_addresses:
                addresses[hostname] = [r.address for r in additional_addresses[hostname]]
            else:
                try:
                    answer = resolver.query(hostname, rdatatype.A)
                except dns.resolver.Timeout, e:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='A', query_name=str(hostname), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
                    raise
                except exception.DNSException, e:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='A', query_name=str(hostname), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
                    addresses[hostname] = []
                else:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='A', query_name=str(hostname), nameservers=resolver.nameservers, answer=answer, error=None, **log_context))
                    addresses[hostname] = [r.address for r in answer.rrset]
        return addresses


    def _lookup_srv_records(self, resolver, srv_names, additional_records=[], log_context={}):
        notification_center = NotificationCenter()
        additional_services = dict((rset.name.to_text(), rset) for rset in additional_records if rset.rdtype == rdatatype.SRV)
        services = {}
        for srv_name in srv_names:
            services[srv_name] = []
            if srv_name in additional_services:
                addresses = self._lookup_a_records(resolver, [r.target.to_text() for r in additional_services[srv_name]], additional_records)
                for record in additional_services[srv_name]:
                    services[srv_name].extend(SRVResult(record.priority, record.weight, record.port, addr) for addr in addresses.get(record.target.to_text(), ()))
            else:
                try:
                    answer = resolver.query(srv_name, rdatatype.SRV)
                except dns.resolver.Timeout, e:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='SRV', query_name=str(srv_name), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
                    raise
                except exception.DNSException, e:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='SRV', query_name=str(srv_name), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
                else:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='SRV', query_name=str(srv_name), nameservers=resolver.nameservers, answer=answer, error=None, **log_context))
                    addresses = self._lookup_a_records(resolver, [r.target.to_text() for r in answer.rrset], answer.response.additional, log_context)
                    for record in answer.rrset:
                        services[srv_name].extend(SRVResult(record.priority, record.weight, record.port, addr) for addr in addresses.get(record.target.to_text(), ()))
            services[srv_name].sort(key=lambda result: (result.priority, -result.weight))
        return services


    def _lookup_naptr_record(self, resolver, domain, services, log_context={}):
        notification_center = NotificationCenter()
        pointers = []
        try:
            answer = resolver.query(domain, rdatatype.NAPTR)
        except dns.resolver.Timeout, e:
            notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='NAPTR', query_name=str(domain), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
            raise
        except exception.DNSException, e:
            notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='NAPTR', query_name=str(domain), nameservers=resolver.nameservers, answer=None, error=e, **log_context))
        else:
            notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(query_type='NAPTR', query_name=str(domain), nameservers=resolver.nameservers, answer=answer, error=None, **log_context))
            records = [r for r in answer.rrset if r.service.lower() in services]
            services = self._lookup_srv_records(resolver, [r.replacement.to_text() for r in records], answer.response.additional, log_context)
            for record in records:
                pointers.extend(NAPTRResult(record.service.lower(), record.order, record.preference, r.priority, r.weight, r.port, r.address) for r in services.get(record.replacement.to_text(), ()))
        pointers.sort(key=lambda result: (result.order, result.preference))
        return pointers


