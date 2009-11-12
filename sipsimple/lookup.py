# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""Implements DNS lookups in the context of SIP, STUN and MSRP relay based
on RFC3263 and related standards. This can be used to determine the next
hop(s) and failover for routing of SIP messages and reservation of network
resources prior the starting of a SIP session. 
"""

import re

# replace standard select and socket modules with versions from eventlet
from eventlet.green import select
from eventlet.green import socket
import dns.resolver
import dns.query
dns.resolver.socket = socket
dns.query.select = select
dns.query.socket = socket

from application.notification import NotificationCenter

from sipsimple.util import Route, TimestampedNotificationData, run_in_green_thread


class DNSLookup(object):

    _service_srv_record_map = {"stun": ("_stun._udp", 3478, False),
                               "msrprelay": ("_msrps._tcp", 2855, True)}
    
    @run_in_green_thread
    def lookup_service(self, uri, service):
        notification_center = NotificationCenter()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 15.0
        try:
            service_prefix, service_port, service_fallback = self._service_srv_record_map[service]
        except KeyError:
            notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="Unknown service: %s" % service))
            return
        a_candidates = []
        servers = []
        try:
            srv_answers = resolver.query("%s.%s" % (service_prefix, uri.host), "SRV")
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers), e:
            notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_service', uri=uri, service=service, query_type='SRV', query_name='%s.%s' % (service_prefix, uri.host), answer=None, error=e))
            if service_fallback:
                a_candidates.append((uri.host, service_port))
        else:
            notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_service', uri=uri, service=service, query_type='SRV', query_name='%s.%s' % (service_prefix, uri.host), answer=srv_answers, error=None))
            srv_answers = sorted(srv_answers, key=lambda x: x.priority)
            srv_answers.sort(key=lambda x: x.weight, reverse=True)
            a_candidates = [(srv_answer.target, srv_answer.port) for srv_answer in srv_answers]
        for a_host, a_port in a_candidates:
            try:
                a_answers = resolver.query(a_host, "A")
            except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers), e:
                notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_service', uri=uri, service=service, query_type='A', query_name=a_host, answer=None, error=e))
            else:
                notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_service', uri=uri, service=service, query_type='A', query_name=a_host, answer=a_answers, error=None))
                for a_answer in a_answers:
                    servers.append((a_answer.address, a_port))
        if servers:
            notification_center.post_notification('DNSLookupDidSucceed', sender=self, data=TimestampedNotificationData(result=servers))
        else:
            notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="No %s servers found for domain %s" % (service, uri.host)))

    _naptr_service_transport_map = {"sips+d2t": "tls",
                                    "sip+d2t": "tcp",
                                    "sip+d2u": "udp"}
    _transport_srv_service_map = {"udp": "_sip._udp",
                                  "tcp": "_sip._tcp",
                                  "tls": "_sips._tls"}
    
    @run_in_green_thread
    def lookup_sip_proxy(self, uri, supported_transports):
        """This function performs RFC 3263 compliant lookup of transport/ip/port
        combinations for a particular SIP URI. As arguments it takes a SIPURI object
        and a list of supported transports, in order of preference of the application.
        It returns a list of Route objects that can be used in order of preference."""
        notification_center = NotificationCenter()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 15.0
        if len(supported_transports) == 0:
            notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="No transports are supported"))
            return
        for supported_transport in supported_transports:
            if supported_transport not in self._transport_srv_service_map:
                notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="Unsupported transport: %s" % supported_transport))
                return
        supported_transports = [transport.lower() for transport in supported_transports]
        # If the URI is a SIPS URI, only a TLS transport can be returned.
        if uri.secure:
            if "tls" not in supported_transports:
                notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="Requested lookup for SIPS URI, but TLS transport is not supported"))
                return
            supported_transports = ["tls"]
        transport = None
        port = None
        ip = None
        srv_candidates = []
        a_candidates = []
        routes = []
        error_type = None
        # Check if the transport was already set as a parameter on the SIP URI.
        if uri.parameters and "transport" in uri.parameters:
            transport = uri.parameters["transport"]
        # Check if the port was already set, we can skip NAPTR/SRV lookup later if it is.
        if uri.port:
            port = uri.port
        # Check if the host part of the URI is a IP address, we can skip NAPTR/SRV lookup later if it is.
        if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", uri.host):
            ip = uri.host
        # Otherwise we can try NAPTR/SRV lookup.
        if port is None and ip is None:
            # Only do the NAPTR part if the transport was not specified as a URI parameter.
            if transport is None:
                try:
                    naptr_answers = resolver.query(uri.host, "NAPTR")
                except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers), e:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_sip_proxy', uri=uri, query_type='NAPTR', query_name=uri.host, answer=None, error=e))
                    error_type = e.__class__
                    # If NAPTR lookup fails for some reason, try SRV lookup for all supported transports.
                    # Only the transports of those lookups that succeed are supported by the server.
                    srv_candidates = [(transport, "%s.%s" % (self._transport_srv_service_map[transport], uri.host)) for transport in supported_transports]
                else:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_sip_proxy', uri=uri, query_type='NAPTR', query_name=uri.host, answer=naptr_answers, error=None))
                    # If NAPTR lookup succeeds, order those entries that are applicable for SIP based on server prefernce.
                    naptr_answers = [answer for answer in naptr_answers if answer.flags.lower() == "s" and answer.service.lower() in self._naptr_service_transport_map and self._naptr_service_transport_map[answer.service.lower()] in supported_transports]
                    naptr_answers.sort(key=lambda x: x.preference)
                    naptr_answers.sort(key=lambda x: x.order)
                    if len(naptr_answers) == 0:
                        notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="Could not find a suitable transport in NAPTR record of domain"))
                        return
                    srv_candidates = [(self._naptr_service_transport_map[answer.service.lower()], answer.replacement) for answer in naptr_answers]
            else:
                # Directly try the SRV record of the requested transport.
                srv_candidates = [(transport, "%s.%s" % (self._transport_srv_service_map[transport], uri.host))]
            for srv_transport, srv_qname in srv_candidates:
                try:
                    srv_answers = resolver.query(srv_qname, "SRV")
                except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers), e:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_sip_proxy', uri=uri, query_type='SRV', query_name=srv_qname, answer=None, error=e))
                    error_type = e.__class__
                    # If SRV lookup fails, try A record directly for a transport that was requested,
                    # otherwise UDP for a SIP URI, TLS for a SIPS URI.
                    if transport is None:
                        if (uri.secure and srv_transport == "tls") or (not uri.secure and srv_transport == "udp"):
                            a_candidates.append((srv_transport, uri.host, 5061 if srv_transport == "tls" else 5060))
                    else:
                        if transport == srv_transport:
                            a_candidates.append((transport, uri.host, 5061 if transport == "tls" else 5060))
                else:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_sip_proxy', uri=uri, query_type='SRV', query_name=srv_qname, answer=srv_answers, error=None))
                    # If SRV lookup succeeds, sort the resulting hosts based on server preference.
                    srv_answers = sorted(srv_answers, key=lambda x: x.priority)
                    srv_answers.sort(key=lambda x: x.weight, reverse=True)
                    for answer in srv_answers:
                        a_candidates.append((srv_transport, answer.target, answer.port))
        else:
            # If NAPT/SRV was skipped, fill in defaults for the other variables.
            if transport is None:
                if uri.secure:
                    transport = "tls"
                else:
                    if "udp" not in supported_transports:
                        notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="UDP transport is not supported, but NAPTR and SRV lookups for %s failed" % uri.host))
                        return
                    transport = "udp"
            if port is None:
                port = 5061 if uri.secure else 5060
            # For an IP address, return this immedeately, otherwise do a lookup for the requested hostname.
            if ip is None:
                a_candidates.append((transport, uri.host, port))
            else:
                notification_center.post_notification('DNSLookupDidSucceed', sender=self, data=TimestampedNotificationData(result=[Route(ip, port=port, transport=transport)]))
                return
        # Keep results in a dictionary so we don't do double A record lookups
        a_cache = {}
        for a_transport, a_qname, a_port in a_candidates:
            if a_qname in a_cache:
                a_answers = a_cache[a_qname]
            else:
                try:
                    a_answers = resolver.query(a_qname, "A")
                except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers), e:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_sip_proxy', uri=uri, query_type='A', query_name=a_qname, answer=None, error=e))
                    # If lookup fails then don't return this value
                    error_type = e.__class__
                    a_answers = []
                else:
                    notification_center.post_notification('DNSLookupTrace', sender=self, data=TimestampedNotificationData(context='lookup_sip_proxy', uri=uri, query_type='A', query_name=a_qname, answer=a_answers, error=None))
                    a_cache[a_qname] = a_answers
            for answer in a_answers:
                routes.append(Route(answer.address, port=a_port, transport=a_transport))
        if routes:
            notification_center.post_notification('DNSLookupDidSucceed', sender=self, data=TimestampedNotificationData(result=routes))
        else:
            notification_center.post_notification('DNSLookupDidFail', sender=self, data=TimestampedNotificationData(error="No routes found for SIP URI %s (%s)" % (uri, error_type.__name__)))


