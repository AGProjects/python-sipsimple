import re

_re_pstn_num = re.compile("^\+?[0-9\-]+$")

def format_cmdline_uri(uri, default_domain):
    if "@" in uri:
        if "sip:" or "sips:" in uri:
            return uri
        else:
            return "sip:%s" % uri
    else:
        if _re_pstn_num.match(uri):
            username = uri.replace("-", "")
        else:
            username = uri
        return "sip:%s@%s" % (username, default_domain)

__all__ = ["format_cmdline_uri"]