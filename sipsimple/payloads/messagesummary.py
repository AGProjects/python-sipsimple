
"""
Message summary and Message Waiting Indication handling according to RFC3842
"""

import re

from cStringIO import StringIO
from application.configuration.datatypes import Boolean

from sipsimple.payloads import ValidationError


class MessageSummary(object):
    content_type = "application/simple-message-summary"

    def __init__(self, messages_waiting=False, message_account=None, summaries=None, optional_headers=None):
        self.messages_waiting = messages_waiting
        self.message_account = message_account
        self.summaries = summaries if summaries is not None else {}
        self.optional_headers = optional_headers if optional_headers is not None else []

    @classmethod
    def parse(cls, content):
        message = StringIO(content)
        summary = cls()
        tmp_headers = []
        for line in message:
            if line == '\r\n':
                if tmp_headers:
                    summary.optional_headers.append(tmp_headers)
                    tmp_headers = []
            else:
                field, sep, rest = line.partition(':')
                if not field and not rest:
                    raise ValidationError("incorrect line format")
                field = field.strip()
                rest = rest.strip()

                if field.lower() == "messages-waiting":
                    summary.messages_waiting = Boolean(rest)
                elif field.lower() == "message-account":
                    summary.message_account = rest
                elif field.lower() in set(["voice-message", "fax-message", "pager-message", "multimedia-message", "text-message", "none"]):
                    m = re.match("((\d+)/(\d+))( \((\d+)/(\d+)\))?", rest)
                    if m:
                        summary.summaries[field.lower()] = dict(new_messages=m.groups()[1], old_messages=m.groups()[2], new_urgent_messages=m.groups()[4] or 0, old_urgent_messages=m.groups()[5] or 0)
                    else:
                        raise ValidationError("invalid message context class")
                else:
                    tmp_headers.append(line.strip())
        if tmp_headers:
            summary.optional_headers.append(tmp_headers)
            tmp_headers = []
        return summary

    def to_string(self):
        data = "Messages-Waiting: %s\r\n" % 'yes' if self.messages_waiting else 'no'
        if self.message_account:
            data += "Message-Account: %s\r\n" % self.message_account
        if self.summaries:
            for k, v in self.summaries.iteritems():
                data += "%s: %s/%s (%s/%s)\r\n" % (k.title(), v['new_messages'], v['old_messages'], v['new_urgent_messages'], v['old_urgent_messages'])
        if self.optional_headers:
            data += "\r\n"
            for headers in self.optional_headers:
                for h in headers:
                    data += "%s\r\n" % h
                data += "\r\n"
        return data

