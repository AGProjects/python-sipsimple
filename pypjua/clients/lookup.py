import re
import random

import dns.resolver

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

def lookup_srv(host, port, is_ip, default_port):
    if is_ip:
        return host, port or default_port
    else:
        if port is None:
            try:
                srv_answers = dns.resolver.query("_sip._udp.%s" % host, "SRV")
                a_host = str(srv_answers[0].target).rstrip(".")
                port = srv_answers[0].port
                print 'Resolved DNS SRV record "_sip._udp.%s" --> %s:%d' % (host, a_host, port)
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

__all__ = ["IPAddressOrHostname", "lookup_srv"]