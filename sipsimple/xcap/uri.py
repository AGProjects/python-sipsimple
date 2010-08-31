# Copyright (C) 2007-2010 AG-Projects.
#

"""XCAP URI module parsing/building support"""

__all__ = ['AttributeSelector', 'ElementSelector', 'NamespaceSelector', 'NodeSelector', 'XCAPUser', 'DocumentSelector', 'XCAPURI']


import re
from copy import copy
from itertools import chain, count
from urllib import unquote
from xml.sax.saxutils import quoteattr

from lxml import _elementpath as ElementPath


class List(list):
    def get(self, index, default=None):
        try:
            return self[index]
        except LookupError:
            return default

class Op(str):
    tag = False


class Tag(str):
    tag = True


class XPathTokenizer(object):

    @classmethod
    def tokens(cls, selector):
        tokens = List()
        prev = None
        for op, tag in ElementPath.xpath_tokenizer(selector):
            if op:
                token = Op(cls.unquote_attribute(op) if prev=='=' else op)
            else:
                token = Tag(cls.unquote_attribute(tag) if prev=='=' else tag)
            tokens.append(token)
            prev = token
        return tokens

    @staticmethod
    def unquote_attribute(attribute):
        # FIXME: currently equivalent but differently encoded URIs won't be considered equal (&quot, etc.)
        if len(attribute) > 1 and attribute[0] == attribute[-1] and attribute[0] in '"\'':
            return attribute[1:-1]
        raise ValueError("illegal XPath expression")


# XPath parsing functions
#

def read_element_tag(lst, index, namespace, namespaces):
    if index == len(lst):
        raise ValueError("illegal XPath expression")
    elif lst[index] == '*':
        return '*', index+1
    elif lst.get(index+1) == ':':
        if not lst[index].tag:
            raise ValueError("illegal XPath expression")
        if not lst.get(index+2) or not lst.get(index+2).tag:
            raise ValueError("illegal XPath expression")
        try:
            namespaces[lst[index]]
        except LookupError:
            raise ValueError("illegal XPath expression")
        return (namespaces[lst[index]], lst[index+2]), index+3
    else:
        return (namespace, lst[index]), index+1


def read_position(lst, index):
    if lst.get(index) == '[' and lst.get(index+2) == ']':
        return int(lst[index+1]), index+3
    return None, index


# XML attributes don't belong to the same namespace as containing tag?
# because thats what I get in startElement/attrs.items - (None, 'tag')
# lxml's xpath works similar way too:
# doc.xpath('/default:rls-services/defaultg:service[@uri="sip:mybuddies@example.com"]',
#           namespaces = {'default':"urn:ietf:params:xml:ns:rls-services"})
# works, while 
# doc.xpath('/default:rls-services/defaultg:service[@default:uri="sip:mybuddies@example.com"]',
#           namespaces = {'default':"urn:ietf:params:xml:ns:rls-services"})
# does not
# that's why _namespace parameter is ignored and None is supplied in that case
def read_att_test(lst, index, _namespace, namespaces):
    if lst.get(index) == '[' and lst.get(index+1) == '@' and lst.get(index+3) == '=' and lst.get(index+5) == ']':
        return (None, lst[index+2]), lst[index+4], index+6
    elif lst.get(index) == '[' and lst.get(index+1) == '@' and lst.get(index+3) == ':' and lst.get(index+5) == '=' and lst.get(index+7) == ']':
        return (namespaces[lst[index+2]], lst[index+4]), lst[index+6], index+8
    return None, None, index


class Step(object):

    def __init__(self, name, position=None, att_name=None, att_value=None):
        self.name = name
        self.position = position
        self.att_name = att_name
        self.att_value = att_value

    def to_string(self, ns_prefix_mapping=dict()):
        try:
            namespace, name = self.name
        except ValueError:
            res = self.name
        else:
            prefix = ns_prefix_mapping[namespace]
            if prefix:
                res = prefix + ':' + name
            else:
                res = name
        if self.position is not None:
            res += '[%s]' % self.position
        if self.att_name is not None:
            namespace, name = self.att_name
            if namespace:
                prefix = ns_prefix_mapping[namespace]
            else:
                prefix = None
            if prefix:
                res += '[@%s:%s=%s]' % (prefix, name, quoteattr(self.att_value))
            else:
                res += '[@%s=%s]' % (name, quoteattr(self.att_value))
        return res

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        args = [self.name, self.position, self.att_name, self.att_value]
        while args and args[-1] is None:
            del args[-1]
        args = [repr(x) for x in args]
        return 'Step(%s)' % ', '.join(args)


def read_step(lst, index, namespace, namespaces):
    if lst.get(index) == '@':
        return AttributeSelector(lst[index+1]), index+2
    elif lst.get(index) == 'namespace' and lst.get(index+1) == '::' and lst.get(index+2) == '*':
        return NamespaceSelector(), index+3
    else:
        tag, index = read_element_tag(lst, index, namespace, namespaces)
        position, index = read_position(lst, index)
        att_name, att_value, index = read_att_test(lst, index, namespace, namespaces)
        return Step(tag, position, att_name, att_value), index


def read_slash(lst, index):
    if lst.get(index) == '/':
        return index+1
    raise ValueError("illegal XPath expression")


def read_node_selector(lst, namespace, namespaces):
    index = 0
    if lst.get(0) == '/':
        index = read_slash(lst, index)
    steps = []
    terminal_selector = None
    while True:
        step, index = read_step(lst, index, namespace, namespaces)
        if isinstance(step, TerminalSelector):
            if index != len(lst):
                raise ValueError("illegal XPath expression")
            terminal_selector = step
            break
        steps.append(step)
        if index == len(lst):
            break
        index = read_slash(lst, index)
    return ElementSelector(steps, namespace, namespaces), terminal_selector


def parse_node_selector(selector, namespace=None, namespaces=dict()):
    tokens = XPathTokenizer.tokens(selector)
    element_selector, terminal_selector = read_node_selector(tokens, namespace, namespaces)
    element_selector._original_selector = selector
    return element_selector, terminal_selector


# XPath selectors
#

class TerminalSelector(object):
    pass


class AttributeSelector(TerminalSelector):
    def __init__(self, attribute):
        self.attribute = attribute

    def __str__(self):
        return '@' + self.attribute

    def __repr__(self):
        return 'AttributeSelector(%r)' % self.attribute


class ElementSelector(list):
    xml_tag_re = re.compile('\s*<([^ >/]+)')

    def __init__(self, lst, namespace, namespaces):
        list.__init__(self, lst)
        self.namespace = namespace
        self.namespaces = namespaces

    def _parse_qname(self, qname):
        if qname == '*':
            return qname
        try:
            prefix, name = qname.split(':')
        except ValueError:
            return (self.namespace, qname)
        else:
            return (self.namespaces[prefix], name)

    def replace_default_prefix(self, ns_prefix_mapping):
        steps = []
        for step in self:
            try:
                namespace, name = step.name
            except ValueError:
                steps.append(str(step))
            else:
                steps.append(step.to_string(ns_prefix_mapping))
        return '/' + '/'.join(steps)

    def fix_star(self, element_body):
        if self and self[-1].name == '*' and self[-1].position is None:
            m = self.xml_tag_re.match(element_body)
            if m:
                (name, ) = m.groups()
                result = copy(self)
                result[-1].name = self._parse_qname(name)
                return result
        return self


class NamespaceSelector(TerminalSelector):
    def __str__(self):
        return "namespace::*"

    def __repr__(self):
        return 'NamespaceSelector()'


class NodeSelector(object):
    xmlns_re = re.compile("xmlns\((?P<nsdata>.*?)\)")

    def __init__(self, selector, default_namespace=None, default_prefix='default'):
        self.nsmap = {}
        xpath, _, xpointer = selector.partition('?')
        for match in self.xmlns_re.findall(xpointer):
            try:
                prefix, namespace = match.split('=', 1)
            except ValueError:
                continue
            else:
                self.nsmap[prefix] = namespace
        self.default_prefix = (prefix for prefix in chain([default_prefix], ('%s%03d' % (default_prefix, i) for i in count())) if prefix not in self.nsmap).next()
        self.nsmap[self.default_prefix] = default_namespace
        self.element_selector, self.terminal_selector = parse_node_selector(xpath, default_namespace, self.nsmap)

    @property
    def default_namespace(self):
        return self.element_selector.namespace

    @property
    def normalized(self):
        namespace2prefix = dict((v, k) for k, v in self.nsmap.iteritems())
        namespace2prefix[self.element_selector.namespace] = self.default_prefix
        result = self.element_selector.replace_default_prefix(namespace2prefix)
        if self.terminal_selector:
            result += '/' + str(self.terminal_selector)
        return result


class XCAPUser(object):

    def __init__(self, username, domain):
        self.username = username
        self.domain = domain

    @property
    def uri(self):
        return 'sip:%s@%s' % (self.username, self.domain)

    def __eq__(self, other):
        return isinstance(other, XCAPUser) and self.uri == other.uri

    def __ne__(self, other):
        return not self.__eq__(other)

    def __nonzero__(self):
        return bool(self.username) and bool(self.domain)

    def __str__(self):
        return "%s@%s" % (self.username, self.domain)

    def __repr__(self):
        return 'XCAPUser(%r, %r)' % (self.username, self.domain)

    @classmethod
    def parse(cls, user_id, default_domain=None):
        if user_id.startswith("sip:"):
            user_id = user_id[4:]
        _split = user_id.split('@', 1)
        username = _split[0]
        if len(_split) == 2:
            domain = _split[1]
        else:
            domain = default_domain
        return cls(username, domain)


class DocumentSelector(str):
    """
    Constructs a DocumentSelector containing the application_id, context, user_id
    and document from the given selector string.
    """

    def __init__(self, selector):
        if selector[:1] == '/':
            selector = selector[1:]
        else:
            raise ValueError("Document selector does not start with /")
        if selector[-1:] == '/':
            selector = selector[:-1]
        if not selector:
            raise ValueError("Document selector does not contain auid")
        segments  = selector.split('/')
        if len(segments) < 2:
            raise ValueError("Document selector does not contain context: %r" % selector)
        self.application_id = segments[0]
        self.context = segments[1]
        if self.context not in ("users", "global"):
            raise ValueError("Document selector context must be either 'users' or 'global', not %r: %r" % \
                                        (self.context, selector))
        if self.context == "users":
            try:
                self.user_id = segments[2]
            except IndexError:
                raise ValueError('Document selector does not contain user id: %r' % selector)
            segments = segments[3:]
        else:
            self.user_id = None
            segments = segments[2:]
        if not segments:
            raise ValueError("Document selector does not contain document's path: %r" % selector)
        self.document_path = '/'.join(segments)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, str.__repr__(self))


class XCAPURI(object):
    """An XCAP URI containing the XCAP root, document selector and node selector."""

    def __init__(self, xcap_root, resource_selector, namespaces):
        self.xcap_root = xcap_root
        self.resource_selector = unquote(resource_selector)

        # convention to get the realm if it's not contained in the user ID section
        # of the document selector (bad eyebeam)
        if self.resource_selector.startswith("@"):
            first_slash = self.resource_selector.find("/")
            default_realm = self.resource_selector[1:first_slash]
            self.resource_selector = self.resource_selector[first_slash:]
        else:
            default_realm = None

        document_selector, _, node_selector = self.resource_selector.partition('~~')

        self.document_selector = DocumentSelector(document_selector)
        self.application_id = self.document_selector.application_id
        self.node_selector = NodeSelector(node_selector, namespaces.get(self.application_id)) if node_selector else None
        self.user = XCAPUser.parse(self.document_selector.user_id, default_realm) if self.document_selector.user_id else None

    def __str__(self):
        return self.xcap_root + self.resource_selector


