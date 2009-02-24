import re

cdef class GenericStringHeader:
    cdef pjsip_generic_string_hdr c_obj
    cdef readonly hname
    cdef readonly hvalue

    def __cinit__(self, hname, hvalue):
        cdef pj_str_t c_hname
        cdef pj_str_t c_hvalue
        self.hname = hname
        self.hvalue = hvalue
        str_to_pj_str(self.hname, &c_hname)
        str_to_pj_str(self.hvalue, &c_hvalue)
        pjsip_generic_string_hdr_init2(&self.c_obj, &c_hname, &c_hvalue)

    def __repr__(self):
        return '<GenericStringHeader "%s: %s">' % (self.hname, self.hvalue)

cdef class PJSTR:
    cdef pj_str_t pj_str
    cdef object str

    def __cinit__(self, str):
        self.str = str
        str_to_pj_str(str, &self.pj_str)

    def __str__(self):
        return self.str

cdef int str_to_pj_str(object string, pj_str_t *pj_str) except -1:
    pj_str.ptr = PyString_AsString(string)
    pj_str.slen = len(string)

cdef object pj_str_to_str(pj_str_t pj_str):
    return PyString_FromStringAndSize(pj_str.ptr, pj_str.slen)

cdef object pj_status_to_str(int status):
    cdef char buf[PJ_ERR_MSG_SIZE]
    return pj_str_to_str(pj_strerror(status, buf, PJ_ERR_MSG_SIZE))

cdef object pj_status_to_def(int status):
    return _re_pj_status_str_def.match(pj_status_to_str(status)).group(1)

cdef object c_retrieve_nameservers():
    nameservers = []
    IF UNAME_SYSNAME != "Windows":
        re_ip = re.compile(r"^nameserver\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$")
        try:
            for line in open("/etc/resolv.conf"):
                match = re_ip.match(line)
                if re_ip.match(line):
                    nameservers.append(match.group(1))
        except:
            raise SIPCoreError("Could not parse /etc/resolv.conf")
    ELSE:
        raise NotImplementedError("Nameserver lookup not yet implemented for windows")
    return nameservers

cdef dict c_pjsip_param_to_dict(pjsip_param *param_list):
    cdef pjsip_param *param
    cdef dict retval = {}
    param = <pjsip_param *> (<pj_list *> param_list).next
    while param != param_list:
        retval[pj_str_to_str(param.name)] = pj_str_to_str(param.value)
        param = <pjsip_param *> (<pj_list *> param).next
    return retval

cdef int c_rdata_info_to_dict(pjsip_rx_data *rdata, dict info_dict) except -1:
    cdef pjsip_msg_body *body
    cdef pjsip_hdr *hdr
    cdef object hdr_name
    cdef int i
    cdef pjsip_generic_array_hdr *array_hdr
    cdef pjsip_generic_string_hdr *string_hdr
    cdef pjsip_contact_hdr *contact_hdr
    cdef pjsip_clen_hdr *clen_hdr
    cdef pjsip_ctype_hdr *ctype_hdr
    cdef pjsip_cseq_hdr *cseq_hdr
    cdef pjsip_generic_int_hdr *int_hdr
    cdef pjsip_fromto_hdr *fromto_hdr
    cdef pjsip_routing_hdr *routing_hdr
    cdef pjsip_retry_after_hdr *retry_after_hdr
    cdef pjsip_via_hdr *via_hdr
    cdef object hdr_data, hdr_multi
    cdef dict headers = {}
    info_dict["headers"] = headers
    hdr = <pjsip_hdr *> (<pj_list *> &rdata.msg_info.msg.hdr).next
    while hdr != &rdata.msg_info.msg.hdr:
        hdr_data = None
        hdr_multi = False
        hdr_name = pj_str_to_str(hdr.name)
        if hdr_name in ["Accept", "Allow", "Require", "Supported", "Unsupported"]:
            array_hdr = <pjsip_generic_array_hdr *> hdr
            hdr_data = []
            for i from 0 <= i < array_hdr.count:
                hdr_data.append(pj_str_to_str(array_hdr.values[i]))
        elif hdr_name == "Contact":
            hdr_multi = True
            contact_hdr = <pjsip_contact_hdr *> hdr
            hdr_data = (contact_hdr.star and None or c_make_SIPURI(contact_hdr.uri, 1), c_pjsip_param_to_dict(&contact_hdr.other_param))
            if contact_hdr.q1000 != 0:
                hdr_data[1]["q"] = contact_hdr.q1000 / 1000.0
            if contact_hdr.expires != -1:
                hdr_data[1]["expires"] = contact_hdr.expires
        elif hdr_name == "Content-Length":
            clen_hdr = <pjsip_clen_hdr *> hdr
            hdr_data = clen_hdr.len
        elif hdr_name == "Content-Type":
            ctype_hdr = <pjsip_ctype_hdr *> hdr
            hdr_data = ("%s/%s" % (pj_str_to_str(ctype_hdr.media.type), pj_str_to_str(ctype_hdr.media.subtype)), pj_str_to_str(ctype_hdr.media.param))
        elif hdr_name == "CSeq":
            cseq_hdr = <pjsip_cseq_hdr *> hdr
            hdr_data = (cseq_hdr.cseq, pj_str_to_str(cseq_hdr.method.name))
        elif hdr_name in ["Expires", "Max-Forwards", "Min-Expires"]:
            int_hdr = <pjsip_generic_int_hdr *> hdr
            hdr_data = int_hdr.ivalue
        elif hdr_name in ["From", "To"]:
            fromto_hdr = <pjsip_fromto_hdr *> hdr
            hdr_data = (c_make_SIPURI(fromto_hdr.uri, 1), pj_str_to_str(fromto_hdr.tag), c_pjsip_param_to_dict(&fromto_hdr.other_param))
        elif hdr_name in ["Record-Route", "Route"]:
            hdr_multi = True
            routing_hdr = <pjsip_routing_hdr *> hdr
            hdr_data = (c_make_SIPURI(<pjsip_uri *> &routing_hdr.name_addr, 1), c_pjsip_param_to_dict(&routing_hdr.other_param))
        elif hdr_name == "Retry-After":
            retry_after_hdr = <pjsip_retry_after_hdr *> hdr
            hdr_data = (retry_after_hdr.ivalue, pj_str_to_str(retry_after_hdr.comment), c_pjsip_param_to_dict(&retry_after_hdr.param))
        elif hdr_name == "Via":
            hdr_multi = True
            via_hdr = <pjsip_via_hdr *> hdr
            hdr_data = (pj_str_to_str(via_hdr.transport), pj_str_to_str(via_hdr.sent_by.host), via_hdr.sent_by.port, pj_str_to_str(via_hdr.comment), c_pjsip_param_to_dict(&via_hdr.other_param))
            if via_hdr.ttl_param != -1:
                hdr_data[4]["ttl"] = via_hdr.ttl_param
            if via_hdr.rport_param != -1:
                hdr_data[4]["rport"] = via_hdr.rport_param
            if via_hdr.maddr_param.slen > 0:
                hdr_data[4]["maddr"] = pj_str_to_str(via_hdr.maddr_param)
            if via_hdr.recvd_param.slen > 0:
                hdr_data[4]["recvd"] = pj_str_to_str(via_hdr.recvd_param)
            if via_hdr.branch_param.slen > 0:
                hdr_data[4]["branch"] = pj_str_to_str(via_hdr.branch_param)
        elif hdr_name not in ["Authorization", "Proxy-Authenticate", "Proxy-Authorization", "WWW-Authenticate"]: # skip these
            string_hdr = <pjsip_generic_string_hdr *> hdr
            hdr_data = pj_str_to_str(string_hdr.hvalue)
            if hdr_name == "Warning":
                hdr_data = _re_warning_hdr.match(hdr_data)
                if hdr_data is not None:
                    hdr_data = hdr_data.groups()
                    hdr_data = (int(hdr_data[0]), hdr_data[1], hdr_data[2])
        if hdr_data is not None:
            if hdr_multi:
                headers.setdefault(hdr_name, []).append(hdr_data)
            else:
                if hdr_name not in headers:
                    headers[hdr_name] = hdr_data
        hdr = <pjsip_hdr *> (<pj_list *> hdr).next
    body = rdata.msg_info.msg.body
    if body == NULL:
        info_dict["body"] = None
    else:
        info_dict["body"] = PyString_FromStringAndSize(<char *> body.data, body.len)
    if rdata.msg_info.msg.type == PJSIP_REQUEST_MSG:
        info_dict["method"] = pj_str_to_str(rdata.msg_info.msg.line.req.method.name)
        info_dict["request_uri"] = c_make_SIPURI(rdata.msg_info.msg.line.req.uri, 0)
    else:
        info_dict["code"] = rdata.msg_info.msg.line.status.code
        info_dict["reason"] = pj_str_to_str(rdata.msg_info.msg.line.status.reason)
    return 0

cdef int c_is_valid_ip(int af, object ip) except -1:
    cdef char buf[16]
    cdef pj_str_t src
    cdef int status
    str_to_pj_str(ip, &src)
    status = pj_inet_pton(af, &src, buf)
    if status == 0:
        return 1
    else:
        return 0

cdef int c_get_ip_version(object ip) except -1:
    if c_is_valid_ip(pj_AF_INET(), ip):
        return pj_AF_INET()
    elif c_is_valid_ip(pj_AF_INET6(), ip):
        return pj_AF_INET()
    else:
        return 0

# globals

cdef object _re_pj_status_str_def = re.compile("^.*\((.*)\)$")
cdef object _re_warning_hdr = re.compile('([0-9]{3}) (.*?) "(.*?)"')