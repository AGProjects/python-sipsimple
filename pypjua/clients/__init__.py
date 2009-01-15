import re

_pstn_num_sub_char = "[-() ]"
_re_pstn_num_sub = re.compile(_pstn_num_sub_char)
_re_pstn_num = re.compile("^\+?([0-9]|%s)+$" % _pstn_num_sub_char)

def format_cmdline_uri(uri, default_domain):
    if "@" not in uri:
        if _re_pstn_num.match(uri):
            username = _re_pstn_num_sub.sub("", uri)
        else:
            username = uri
        uri = "%s@%s" % (username, default_domain)
    if not uri.startswith("sip:") and not uri.startswith("sips:"):
        uri = "sip:%s" % uri
    return uri

__all__ = ["format_cmdline_uri"]