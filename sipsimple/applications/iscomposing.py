# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

"""
Parses and produces isComposing messages according to RFC3994.

"""

__all__ = ['namespace', 'IsComposingApplication', 'State', 'LastActive', 'ContentType', 'Refresh', 'IsComposingMessage']

import datetime
from sipsimple.applications import util, XMLApplication, XMLRootElement, XMLElement, XMLStringElement, XMLElementChild
from sipsimple.applications.util import UnsignedLong, Timestamp


namespace = 'urn:ietf:params:xml:ns:im-iscomposing'


class IsComposingApplication(XMLApplication): pass
IsComposingApplication.register_namespace(namespace, prefix=None)


# Attribute value types
class StateValue(str):
    def __new__(cls, value):
        if value not in ('active', 'idle'):
            return 'idle'
        return value

class RefreshValue(int):
    def __new__(cls, value):
        if value <= 0:
            raise ValueError("illegal value form refresh element")
        return value


# Elements
class State(XMLStringElement):
    _xml_tag = 'state'
    _xml_namespace = namespace
    _xml_application = IsComposingApplication
    _xml_value_type = StateValue

class LastActive(XMLStringElement):
    _xml_tag = 'lastactive'
    _xml_namespace = namespace
    _xml_application = IsComposingApplication
    _xml_value_type = Timestamp

class ContentType(XMLStringElement):
    _xml_tag = 'contenttype'
    _xml_namespace = namespace
    _xml_application = IsComposingApplication

class Refresh(XMLStringElement):
    _xml_tag = 'refresh'
    _xml_namespace = namespace
    _xml_application = IsComposingApplication
    _xml_value_type = RefreshValue
    
class IsComposingMessage(XMLRootElement):
    content_type = "application/im-iscomposing+xml"

    _xml_tag = 'isComposing'
    _xml_namespace = namespace
    _xml_application = IsComposingApplication
    _xml_schema_file = 'im-iscomposing.xsd'
    _xml_children_order = {State.qname: 0,
                            LastActive.qname: 1,
                            ContentType.qname: 2,
                            Refresh.qname: 3,
                            None: 4}

    state = XMLElementChild('state', type=State, required=False, test_equal=True)
    last_active = XMLElementChild('last_active', type=LastActive, required=False, test_equal=True)
    contenttype = XMLElementChild('contenttype', type=ContentType, required=False, test_equal=True)
    refresh = XMLElementChild('refresh', type=Refresh, required=False, test_equal=True)
    
    def __init__(self, state=None, last_active=None, content_type=None, refresh=None):
        XMLRootElement.__init__(self)
        self.state = state
        self.last_active = last_active
        self.contenttype = content_type
        self.refresh = refresh

