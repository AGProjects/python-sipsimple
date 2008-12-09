import re

from pypjua import SIPURI

_re_sipuri = re.compile(r'^\s*"?(?P<display>.+?)?"?\s*<?(?P<scheme>sip|sips):((?P<user>[^@:\s]*)(:(?P<password>[^@\s]*))?@)?(?P<host>[^:;?>\s]+?)(:(?P<port>[0-9]*))?(?P<parameters>(;[^=\s]*=[^;?\s>]*?)+)?(?P<headers>\?[^=\s]*=[^&>\s]*?(&[^=\s]*=[^&>\s]*)*)?>?\s*$')
_re_pstn_num = re.compile("^\+?[0-9\-]+$")

def parse_cmdline_uri(uri, default_domain):
    if "@" in uri:
        match = _re_sipuri.match(uri)
        if match is None:
            match = _re_sipuri.match("sip:%s" % uri)
            if match is None:
                raise ValueError("Not a valid SIP URI: %s" % uri)
        kwargs = match.groupdict()
        kwargs["secure"] = kwargs.pop("scheme") == "sips"
        kwargs["parameters"] = {} if not kwargs["parameters"] else dict(param.split("=") for param in kwargs["parameters"][1:].split(";"))
        kwargs["headers"] = {} if not kwargs["headers"] else dict(hdr.split("=") for hdr in kwargs["headers"][1:].split("&"))
        return SIPURI(**kwargs)
    else:
        if _re_pstn_num.match(uri):
            return SIPURI(user=uri.replace("-", ""), host=default_domain)
        else:
            return SIPURI(user=uri, host=default_domain)

__all__ = ["TransportPort", "parse_cmdline_uri"]