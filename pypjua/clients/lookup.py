import re
import random

import dns.resolver

from pypjua import Route, SIPURI

_re_host_port = re.compile("^((?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?P<host>[a-zA-Z0-9\-\.]+))(:(?P<port>\d+))?$")
class IPAddressOrHostname(tuple):
    def __new__(typ, value):
        match = _re_host_port.search(value)
        if match is None:
            raise ValueError("invalid hostname/port: %r" % value)
        if match.group("ip") is None:
            host = match.group("host")
            is_ip = False
        else:
            host = match.group("ip")
            is_ip = True
        if match.group("port") is None:
            port = None
        else:
            port = int(match.group("port"))
            if port > 65535:
                raise ValueError("port is out of range: %d" % port)
        return host, port, is_ip


class OutboundProxy(SIPURI):
    def __new__(type, value):
        if value.lower() == "none":
            return None
        parameters = {}
        host = None
        port = None
        splitval = value.split(":")
        if len(splitval) > 3:
            raise ValueError("Could not parse outbound proxy")
        elif len(splitval) == 3:
            parameters["transport"], host, port = splitval
        elif len(splitval) == 2:
            if splitval[1].isdigit():
                host, port = splitval
            else:
                parameters["transport"], host = splitval
        else:
            host = splitval[0]
        if port is not None:
            port = int(port)
            if port < 0 or port > 65535:
                raise ValueError("port is out of range: %d" % port)
        return SIPURI(host=host, port=port, parameters=parameters)


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

_naptr_service_transport_map = {"sips+d2t": "tls",
                                "sip+d2t": "tcp",
                                "sip+d2u": "udp"}
_transport_srv_service_map = {"udp": "_sip._udp",
                              "tcp": "_sip._tcp",
                              "tls": "_sips._tls"}

def lookup_routes_for_sip_uri(uri, supported_transports):
    if len(supported_transports) == 0:
        raise RuntimeError("No transports are supported")
    supported_transports = [transport.lower() for transport in supported_transports]
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
    if uri.parameters and "transport" in uri.parameters:
        transport = uri.parameters["transport"]
    if uri.port:
        port = uri.port
    if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", uri.host):
        ip = uri.host
    if port is None and ip is None:
        if transport is None:
            try:
                naptr_answers = dns.resolver.query(uri.host, "NAPTR")
            except:
                srv_candidates = [(transport, "%s.%s" % (_transport_srv_service_map[transport], uri.host)) for transport in supported_transports]
            else:
                naptr_answers = [answer for answer in naptr_answers if answer.flags.lower() == "s" and answer.service.lower() in _naptr_service_transport_map and _naptr_service_transport_map[answer.service.lower()] in supported_transports]
                naptr_answers.sort(key=lambda x: x.preference)
                naptr_answers.sort(key=lambda x: x.order)
                if len(naptr_answers) == 0:
                    raise RuntimeError("Could find a suitable transport in NAPTR record of domain")
                srv_candidates = [(_naptr_service_transport_map[answer.service.lower()], answer.replacement) for answer in naptr_answers]
        else:
            srv_candidates = [(transport, "%s.%s" % (_transport_srv_service_map[transport], uri.host))]
        for srv_transport, srv_qname in srv_candidates:
            try:
                srv_answers = dns.resolver.query(srv_qname, "SRV")
            except:
                if transport is None:
                    if (uri.secure and srv_transport == "tls") or (not uri.secure and srv_transport == "udp"):
                        a_candidates.append((srv_transport, uri.host, 5061 if srv_transport == "tls" else 5060))
                else:
                    if transport == srv_transport:
                        a_candidates.append((transport, uri.host, 5061 if transport == "tls" else 5060))
            else:
                srv_answers = sorted(srv_answers, key=lambda x: x.priority)
                srv_answers.sort(key=lambda x: x.weight, reverse=True)
                for answer in srv_answers:
                    a_candidates.append((srv_transport, answer.target, answer.port))
    else:
        if transport is None:
            if uri.secure:
                transport = "tls"
            else:
                if "udp" not in supported_transports:
                    raise RuntimeError("UDP transport is not suported")
                transport = "udp"
        if port is None:
            port = 5061 if uri.secure else 5060
        if ip is None:
            a_candidates.append((transport, uri.host, port))
        else:
            return [Route(ip, port=port, transport=transport)]
    a_cache = {}
    for a_transport, a_qname, a_port in a_candidates:
        try:
            if a_qname in a_cache:
                a_answers = a_cache[a_qname]
            else:
                a_answers = dns.resolver.query(a_qname, "A")
                a_cache[a_qname] = a_answers
        except:
            pass
        else:
            for answer in a_answers:
                routes.append(Route(answer.address, port=a_port, transport=a_transport))
    return routes

__all__ = ["IPAddressOrHostname", "OutboundProxy", "lookup_srv", "lookup_routes_for_sip_uri"]
