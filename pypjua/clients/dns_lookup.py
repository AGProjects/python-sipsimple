import re
import random

import dns.resolver

from pypjua import Route

def lookup_srv(host, port, is_ip, default_port, service='_sip._udp'):
    if is_ip:
        return host, port or default_port
    else:
        if port is None:
            try:
                srv_answers = dns.resolver.query("%s.%s" % (service, host), "SRV")
                a_host = str(srv_answers[0].target).rstrip(".")
                port = srv_answers[0].port
                print 'Resolved DNS SRV record "%s.%s" --> %s:%d' % (service, host, a_host, port)
            except:
                print "Domain %s has no DNS SRV record, attempting DNS A record lookup" % host
                a_host = host
                port = default_port
        else:
            a_host = host
        try:
            a_answers = dns.resolver.query(a_host, "A")
            print 'Resolved DNS A record "%s" --> %s' % (a_host, ", ".join(a.address for a in a_answers))
        except:
            raise RuntimeError('Could not resolve "%s"' % a_host)
        return random.choice(a_answers).address, port

_service_srv_record_map = {"stun": ("_stun._udp", 3478, False),
                           "msrprelay": ("_msrps._tcp", 2855, True)}

def lookup_service_for_sip_uri(uri, service):
    try:
        service_prefix, service_port, service_fallback = _service_srv_record_map[service]
    except KeyError:
        raise RuntimeError("Unknown service: %s" % service)
    a_candidates = []
    servers = []
    try:
        srv_answers = dns.resolver.query("%s.%s" % (service_prefix, uri.host), "SRV")
    except:
        if service_fallback:
            a_candidates.append((uri.host, service_port))
    else:
        srv_answers = sorted(srv_answers, key=lambda x: x.priority)
        srv_answers.sort(key=lambda x: x.weight, reverse=True)
        a_candidates = [(srv_answer.target, srv_answer.port) for srv_answer in srv_answers]
    for a_host, a_port in a_candidates:
        try:
            a_answers = dns.resolver.query(a_host, "A")
        except:
            pass
        else:
            for a_answer in a_answers:
                servers.append((a_answer.address, a_port))
    return servers

_naptr_service_transport_map = {"sips+d2t": "tls",
                                "sip+d2t": "tcp",
                                "sip+d2u": "udp"}
_transport_srv_service_map = {"udp": "_sip._udp",
                              "tcp": "_sip._tcp",
                              "tls": "_sips._tls"}

def lookup_routes_for_sip_uri(uri, supported_transports):
    """This function preforms RFC 3263 compliant lookup of transport/ip/port
    combinations for a particular SIP URI. As arguments it takes a SIPURI object
    and a list of supported transports, in order of preference of the application.
    It returns a list of Route objects that can be used in order of preference."""
    if len(supported_transports) == 0:
        raise RuntimeError("No transports are supported")
    for supported_transport in supported_transports:
        if supported_transport not in _transport_srv_service_map:
            raise RuntimeError("Unsupported transport: %s" % supported_transport)
    supported_transports = [transport.lower() for transport in supported_transports]
    # If the URI is a SIPS URI, only a TLS transport can be returned.
    if uri.secure:
        if "tls" not in supported_transports:
            raise RuntimeError("Requested lookup for SIPS URI, but TLS transport is not supported")
        supported_transports = ["tls"]
    transport = None
    port = None
    ip = None
    srv_candidates = []
    a_candidates = []
    routes = []
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
                naptr_answers = dns.resolver.query(uri.host, "NAPTR")
            except:
                # If NAPTR lookup fails for some reason, try SRV lookup for all supported transports.
                # Only the transports of those lookups that succeed are supported by the server.
                srv_candidates = [(transport, "%s.%s" % (_transport_srv_service_map[transport], uri.host)) for transport in supported_transports]
            else:
                # If NAPTR lookup succeeds, order those entries that are applicable for SIP based on server prefernce.
                naptr_answers = [answer for answer in naptr_answers if answer.flags.lower() == "s" and answer.service.lower() in _naptr_service_transport_map and _naptr_service_transport_map[answer.service.lower()] in supported_transports]
                naptr_answers.sort(key=lambda x: x.preference)
                naptr_answers.sort(key=lambda x: x.order)
                if len(naptr_answers) == 0:
                    raise RuntimeError("Could find a suitable transport in NAPTR record of domain")
                srv_candidates = [(_naptr_service_transport_map[answer.service.lower()], answer.replacement) for answer in naptr_answers]
        else:
            # Directly try the SRV record of the requested transport.
            srv_candidates = [(transport, "%s.%s" % (_transport_srv_service_map[transport], uri.host))]
        for srv_transport, srv_qname in srv_candidates:
            try:
                srv_answers = dns.resolver.query(srv_qname, "SRV")
            except:
                # If SRV lookup fails, try A record directly for a transport that was requested,
                # otherwise UDP for a SIP URI, TLS for a SIPS URI.
                if transport is None:
                    if (uri.secure and srv_transport == "tls") or (not uri.secure and srv_transport == "udp"):
                        a_candidates.append((srv_transport, uri.host, 5061 if srv_transport == "tls" else 5060))
                else:
                    if transport == srv_transport:
                        a_candidates.append((transport, uri.host, 5061 if transport == "tls" else 5060))
            else:
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
                    raise RuntimeError("UDP transport is not suported")
                transport = "udp"
        if port is None:
            port = 5061 if uri.secure else 5060
        # For an IP address, return this immedeately, otherwise do a lookup for the requested hostname.
        if ip is None:
            a_candidates.append((transport, uri.host, port))
        else:
            return [Route(ip, port=port, transport=transport)]
    # Keep results in a dictionary so we don't do double A record lookups
    a_cache = {}
    for a_transport, a_qname, a_port in a_candidates:
        try:
            if a_qname in a_cache:
                a_answers = a_cache[a_qname]
            else:
                a_answers = dns.resolver.query(a_qname, "A")
                a_cache[a_qname] = a_answers
        except:
            # If lookup fails then don't return this value
            pass
        else:
            for answer in a_answers:
                routes.append(Route(answer.address, port=a_port, transport=a_transport))
    return routes

__all__ = ["lookup_srv", "lookup_service_for_sip_uri", "lookup_routes_for_sip_uri"]
