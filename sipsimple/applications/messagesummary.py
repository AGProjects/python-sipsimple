# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

""" Message summary and Message Waiting Indication handling according to RFC3842

This module provides the ability to parse and generate Message Summary payloads.
"""

import re
from cStringIO import StringIO

from sipsimple.applications import ValidationError

class BooleanValue(object):
    def __new__(cls, value):
        if type(value) is str and value.lower() in ('yes', 'no'):
            return True if value == 'yes' else False
        raise ValueError("invalid value for boolean value")

class MessageSummary(object):

    message_context_class = ["voice-message", "fax-message", "pager-message", "multimedia-message", "text-message", "none"]

    def __init__(self, messages_waiting=False, message_account=None, summaries={}, optional_headers=[]):
        self.messages_waiting = messages_waiting
        self.message_account = message_account
        self.summaries = summaries
        self.optional_headers = optional_headers

    @staticmethod
    def parse(content):                                                                                                                                 
        message = StringIO(content)
        summary = MessageSummary()
        tmp_header = []
        for line in message:
            if line == '\r\n':
                if tmp_header:
                    summary.optional_headers.append(tmp_header)
                    tmp_header = []
                continue
            else:
                try:
                    field = line.split(":")[0].strip()
                    rest = "".join(line.split(":")[1:]).strip()
                except IndexError:
                    raise ValidationError("incorrect line format")

                if field.lower() == "messages-waiting":
                    summary.messages_waiting = BooleanValue(rest)
                    continue
                elif field.lower() == "message-account":
                    summary.message_account = rest
                    continue
                elif field.lower() in MessageSummary.message_context_class:
                    m = re.match("((\d)\/(\d))(\ \((\d)\/(\d)\))?", rest)
                    if m:
                        s = {}
                        s['new_messages'] = m.groups()[1]
                        s['old_messages'] = m.groups()[2]
                        s['new_urgent_messages'] = m.groups()[4] or 0
                        s['old_urgent_messages'] = m.groups()[5] or 0
                        summary.summaries[field.lower()] = s
                    else:
                        raise ValidationError("invalid message context class")
                    continue
                else:
                    tmp_header.append(line.strip())
        if tmp_header:
            summary.optional_headers.append(tmp_header)
            tmp_header = []
        return summary

    def to_string(self):
        data = ""
        data += "Messages-Waiting: %s\r\n" % 'yes' if self.messages_waiting else 'no'
        if self.message_account:
            data += "Message-Account: %s\r\n" % self.message_account
        if self.summaries:
            for k, v in self.summaries.iteritems():
                data += "%s: %s/%s (%s/%s)\r\n" % (k.capitalize(), v['new_messages'], v['old_messages'], v['new_urgent_messages'], v['old_urgent_messages'])
        if self.optional_headers:
            data += "\r\n"
            for headers in self.optional_headers:
                for h in headers:
                    data += "%s\r\n" % h
                data += "\r\n"
        return data

