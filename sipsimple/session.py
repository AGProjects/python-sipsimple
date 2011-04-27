# Copyright (C) 2008-2011 AG Projects. See LICENSE for details.
#

"""
Implements an asynchronous notification based mechanism for
establishment, modification and termination of sessions using Session
Initiation Protocol (SIP) standardized in RFC3261.
"""

from __future__ import absolute_import, with_statement

__all__ = ['Session', 'SessionManager']

import random
import re

from datetime import datetime
from threading import RLock
from time import time

from application.notification import IObserver, Notification, NotificationCenter
from application.python.decorator import decorator, preserve_signature
from application.python.util import Singleton, Null
from application.system import host
from eventlet import api, coros, proc
from eventlet.coros import queue
from twisted.internet import reactor
from zope.interface import implements

from sipsimple.core import Engine, Invitation, Referral, Subscription, PJSIPError, SIPCoreError, SIPCoreInvalidStateError, SIPURI, sip_status_messages
from sipsimple.core import ContactHeader, FromHeader, ReasonHeader, ReferToHeader, RouteHeader, SubjectHeader, ToHeader, WarningHeader
from sipsimple.core import SDPConnection, SDPMediaStream, SDPSession

from sipsimple.account import AccountManager, BonjourAccount
from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.lookup import DNSLookup, DNSLookupError
from sipsimple.payloads import ValidationError
from sipsimple.payloads.conference import Conference
from sipsimple.streams import MediaStreamRegistry, InvalidStreamError, UnknownStreamError
from sipsimple.threading import run_in_twisted_thread
from sipsimple.threading.green import Command, run_in_green_thread
from sipsimple.util import TimestampedNotificationData, limit


class InvitationDidFailError(Exception):
    def __init__(self, invitation, data):
        self.invitation = invitation
        self.data = data

class MediaStreamDidFailError(Exception):
    def __init__(self, stream, data):
        self.stream = stream
        self.data = data

class SubscriptionError(Exception):
    def __init__(self, error, timeout, refresh_interval=None):
        self.error = error
        self.refresh_interval = refresh_interval
        self.timeout = timeout

class SIPSubscriptionDidFail(Exception):
    def __init__(self, data):
        self.data = data

class InterruptSubscription(Exception):
    pass

class TerminateSubscription(Exception):
    pass

class ReferralError(Exception):
    def __init__(self, error, code=0):
        self.error = error
        self.code = code

class TerminateReferral(Exception):
    pass

class SIPReferralDidFail(Exception):
    def __init__(self, data):
        self.data = data

class IllegalStateError(RuntimeError):
    pass


@decorator
def transition_state(required_state, new_state):
    def state_transitioner(func):
        @preserve_signature(func)
        def wrapper(obj, *args, **kwargs):
            with obj._lock:
                if obj.state != required_state:
                    raise IllegalStateError('cannot call %s in %s state' % (func.__name__, obj.state))
                obj.state = new_state
            return func(obj, *args, **kwargs)
        return wrapper
    return state_transitioner


@decorator
def check_state(required_states):
    def state_checker(func):
        @preserve_signature(func)
        def wrapper(obj, *args, **kwargs):
            if obj.state not in required_states:
                raise IllegalStateError('cannot call %s in %s state' % (func.__name__, obj.state))
            return func(obj, *args, **kwargs)
        return wrapper
    return state_checker


class AddParticipantOperation(object):
    pass

class RemoveParticipantOperation(object):
    pass

class ReferralHandler(object):
    implements(IObserver)

    sipfrag_re = re.compile(r'^SIP/2\.0 (?P<code>\d{3}) (?P<reason>.+)')

    def __init__(self, session, participant_uri, operation):
        self.session = session
        self.participant_uri = participant_uri
        self.operation = operation
        self.active = False
        self.route = None
        self._channel = coros.queue()
        self._referral = None
        self._wakeup_timer = None

    def start(self):
        notification_center = NotificationCenter()
        if not self.session.remote_focus:
            if self.operation is AddParticipantOperation:
                notification_center.post_notification('SIPConferenceDidNotAddParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=0, reason='remote endpoint is not a focus'))
            else:
                notification_center.post_notification('SIPConferenceDidNotRemoveParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=0, reason='remote endpoint is not a focus'))
            self.session = None
            return
        notification_center.add_observer(self, sender=self.session)
        notification_center.add_observer(self, name='DNSNameserversDidChange')
        notification_center.add_observer(self, name='SystemIPAddressDidChange')
        notification_center.add_observer(self, name='SystemDidWakeUpFromSleep')
        proc.spawn(self._run)

    def _run(self):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        try:
            # Lookup routes
            account = self.session.account
            if account is BonjourAccount():
                uri = SIPURI.new(self.session._invitation.remote_contact_header.uri)
            elif account.sip.outbound_proxy is not None:
                uri = SIPURI(host=account.sip.outbound_proxy.host,
                             port=account.sip.outbound_proxy.port,
                             parameters={'transport': account.sip.outbound_proxy.transport})
            elif account.sip.always_use_my_proxy:
                uri = SIPURI(host=account.id.domain)
            else:
                uri = SIPURI.new(self.session.remote_identity.uri)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()
            except DNSLookupError, e:
                timeout = random.uniform(15, 30)
                raise ReferralError(error='DNS lookup failed: %s' % e)

            target_uri = SIPURI.new(self.session.remote_identity.uri)

            timeout = time() + 30
            for route in routes:
                self.route = route
                remaining_time = timeout - time()
                if remaining_time > 0:
                    try:
                        contact_uri = account.contact[route]
                    except KeyError:
                        continue
                    refer_to_header = ReferToHeader(str(self.participant_uri))
                    refer_to_header.parameters['method'] = 'INVITE' if self.operation is AddParticipantOperation else 'BYE'
                    referral = Referral(target_uri, FromHeader(account.uri, account.display_name),
                                        ToHeader(target_uri),
                                        refer_to_header,
                                        ContactHeader(contact_uri),
                                        RouteHeader(route.get_uri()),
                                        account.credentials)
                    notification_center.add_observer(self, sender=referral)
                    try:
                        referral.send_refer(timeout=limit(remaining_time, min=1, max=5))
                    except SIPCoreError:
                        notification_center.remove_observer(self, sender=referral)
                        timeout = 5
                        raise ReferralError(error='Internal error')
                    self._referral = referral
                    try:
                        while True:
                            notification = self._channel.wait()
                            if notification.name == 'SIPReferralDidStart':
                                break
                    except SIPReferralDidFail, e:
                        notification_center.remove_observer(self, sender=referral)
                        self._referral = None
                        if e.data.code in (403, 405):
                            raise ReferralError(error=sip_status_messages[e.data.code], code=e.data.code)
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        break
            else:
                self.route = None
                raise ReferralError(error='No more routes to try')
            # At this point it is subscribed. Handle notifications and ending/failures.
            try:
                self.active = True
                while True:
                    notification = self._channel.wait()
                    if notification.name == 'SIPReferralGotNotify':
                        if notification.data.event == 'refer' and notification.data.body:
                            match = self.sipfrag_re.match(notification.data.body)
                            if match:
                                code = int(match.group('code'))
                                reason = match.group('reason')
                                if self.operation is AddParticipantOperation:
                                    notification_center.post_notification('SIPConferenceGotAddParticipantProgress', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=code, reason=reason))
                                else:
                                    notification_center.post_notification('SIPConferenceGotRemoveParticipantProgress', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=code, reason=reason))
                    elif notification.name == 'SIPReferralDidEnd':
                        break
            except SIPReferralDidFail, e:
                notification_center.remove_observer(self, sender=self._referral)
                raise ReferralError(error=e.data.reason, code=e.data.code)
            else:
                notification_center.remove_observer(self, sender=self._referral)
                if self.operation is AddParticipantOperation:
                    notification_center.post_notification('SIPConferenceDidAddParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri))
                else:
                    notification_center.post_notification('SIPConferenceDidRemoveParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri))
            finally:
                self.active = False
        except TerminateReferral:
            if self._referral is not None:
                try:
                    self._referral.end(timeout=2)
                except SIPCoreError:
                    pass
                else:
                    try:
                        while True:
                            notification = self._channel.wait()
                            if notification.name == 'SIPReferralDidEnd':
                                break
                    except SIPReferralDidFail:
                        pass
                finally:
                    notification_center.remove_observer(self, sender=self._referral)
            if self.operation is AddParticipantOperation:
                notification_center.post_notification('SIPConferenceDidNotAddParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=0, reason='error'))
            else:
                notification_center.post_notification('SIPConferenceDidNotRemoveParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=0, reason='error'))
        except ReferralError, e:
            if self.operation is AddParticipantOperation:
                notification_center.post_notification('SIPConferenceDidNotAddParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=e.code, reason=e.error))
            else:
                notification_center.post_notification('SIPConferenceDidNotRemoveParticipant', sender=self.session, data=TimestampedNotificationData(participant=self.participant_uri, code=e.code, reason=e.error))
        finally:
            if self._wakeup_timer is not None and self._wakeup_timer.active():
                self._wakeup_timer.cancel()
            self._wakeup_timer = None
            notification_center.remove_observer(self, sender=self.session)
            notification_center.remove_observer(self, name='DNSNameserversDidChange')
            notification_center.remove_observer(self, name='SystemIPAddressDidChange')
            notification_center.remove_observer(self, name='SystemDidWakeUpFromSleep')
            self.session = None
            self._referral = None

    def _refresh(self):
        try:
            contact_header = ContactHeader(self.session.account.contact[self.route])
        except KeyError:
            pass
        else:
            try:
                self._referral.refresh(contact_header=contact_header, timeout=2)
            except (SIPCoreError, SIPCoreInvalidStateError):
                pass

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPReferralDidStart(self, notification):
        self._channel.send(notification)

    def _NH_SIPReferralDidEnd(self, notification):
        self._channel.send(notification)

    def _NH_SIPReferralDidFail(self, notification):
        self._channel.send_exception(SIPReferralDidFail(notification.data))

    def _NH_SIPReferralGotNotify(self, notification):
        self._channel.send(notification)

    def _NH_SIPSessionDidFail(self, notification):
        if self._wakeup_timer is not None and self._wakeup_timer.active():
            self._wakeup_timer.cancel()
        self._wakeup_timer = None
        self._channel.send_exception(TerminateReferral())

    def _NH_SIPSessionWillEnd(self, notification):
        if self._wakeup_timer is not None and self._wakeup_timer.active():
            self._wakeup_timer.cancel()
        self._wakeup_timer = None
        self._channel.send_exception(TerminateReferral())

    def _NH_DNSNameserversDidChange(self, notification):
        if self.active:
            self._refresh()

    def _NH_SystemIPAddressDidChange(self, notification):
        if self.active:
            self._refresh()

    def _NH_SystemDidWakeUpFromSleep(self, notification):
        if self._wakeup_timer is None:
            def wakeup_action():
                if self.active:
                    self._refresh()
                self._wakeup_timer = None
            self._wakeup_timer = reactor.callLater(5, wakeup_action) # wait for system to stabilize


class ConferenceHandler(object):
    implements(IObserver)

    def __init__(self, session):
        self.session = session
        self.active = False
        self.subscribed = False
        self._command_proc = None
        self._command_channel = coros.queue()
        self._data_channel = coros.queue()
        self._subscription = None
        self._subscription_proc = None
        self._subscription_timer = None
        self._wakeup_timer = None
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=self.session)
        notification_center.add_observer(self, name='DNSNameserversDidChange')
        notification_center.add_observer(self, name='SystemIPAddressDidChange')
        notification_center.add_observer(self, name='SystemDidWakeUpFromSleep')
        self._command_proc = proc.spawn(self._run)

    @run_in_green_thread
    def add_participant(self, participant_uri):
        referral_handler = ReferralHandler(self.session, participant_uri, AddParticipantOperation)
        referral_handler.start()

    @run_in_green_thread
    def remove_participant(self, participant_uri):
        referral_handler = ReferralHandler(self.session, participant_uri, RemoveParticipantOperation)
        referral_handler.start()

    def _run(self):
        while True:
            command = self._command_channel.wait()
            handler = getattr(self, '_CH_%s' % command.name)
            handler(command)

    def _activate(self):
        self.active = True
        command = Command('subscribe')
        self._command_channel.send(command)
        return command

    def _deactivate(self):
        self.active = False
        command = Command('unsubscribe')
        self._command_channel.send(command)
        return command

    def _resubscribe(self):
        command = Command('subscribe')
        self._command_channel.send(command)
        return command

    def _terminate(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=self.session)
        notification_center.remove_observer(self, name='DNSNameserversDidChange')
        notification_center.remove_observer(self, name='SystemIPAddressDidChange')
        notification_center.remove_observer(self, name='SystemDidWakeUpFromSleep')
        self._deactivate().wait()
        self._command_proc.kill()
        self.session = None

    def _CH_subscribe(self, command):
        if self._subscription_timer is not None and self._subscription_timer.active():
            self._subscription_timer.cancel()
        self._subscription_timer = None
        if self._subscription_proc is not None:
            subscription_proc = self._subscription_proc
            subscription_proc.kill(InterruptSubscription)
            subscription_proc.wait()
        self._subscription_proc = proc.spawn(self._subscription_handler, command)

    def _CH_unsubscribe(self, command):
        # Cancel any timer which would restart the subscription process
        if self._subscription_timer is not None and self._subscription_timer.active():
            self._subscription_timer.cancel()
        self._subscription_timer = None
        if self._wakeup_timer is not None and self._wakeup_timer.active():
            self._wakeup_timer.cancel()
        self._wakeup_timer = None
        if self._subscription_proc is not None:
            subscription_proc = self._subscription_proc
            subscription_proc.kill(TerminateSubscription)
            subscription_proc.wait()
            self._subscription_proc = None
        command.signal()

    def _subscription_handler(self, command):
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        try:
            # Lookup routes
            account = self.session.account
            if account is BonjourAccount():
                uri = SIPURI.new(self.session._invitation.remote_contact_header.uri)
            elif account.sip.outbound_proxy is not None:
                uri = SIPURI(host=account.sip.outbound_proxy.host,
                             port=account.sip.outbound_proxy.port,
                             parameters={'transport': account.sip.outbound_proxy.transport})
            elif account.sip.always_use_my_proxy:
                uri = SIPURI(host=account.id.domain)
            else:
                uri = SIPURI.new(self.session.remote_identity.uri)
            lookup = DNSLookup()
            try:
                routes = lookup.lookup_sip_proxy(uri, settings.sip.transport_list).wait()
            except DNSLookupError, e:
                timeout = random.uniform(15, 30)
                raise SubscriptionError(error='DNS lookup failed: %s' % e, timeout=timeout)

            target_uri = SIPURI.new(self.session.remote_identity.uri)

            timeout = time() + 30
            for route in routes:
                remaining_time = timeout - time()
                if remaining_time > 0:
                    try:
                        contact_uri = account.contact[route]
                    except KeyError:
                        continue
                    subscription = Subscription(target_uri, FromHeader(account.uri, account.display_name),
                                                ToHeader(target_uri),
                                                ContactHeader(contact_uri),
                                                'conference',
                                                RouteHeader(route.get_uri()),
                                                credentials=account.credentials,
                                                refresh=3600)
                    notification_center.add_observer(self, sender=subscription)
                    try:
                        subscription.subscribe(timeout=limit(remaining_time, min=1, max=5))
                    except (PJSIPError, SIPCoreError):
                        notification_center.remove_observer(self, sender=subscription)
                        timeout = 5
                        raise SubscriptionError(error='Internal error', timeout=timeout)
                    self._subscription = subscription
                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.sender is subscription and notification.name == 'SIPSubscriptionDidStart':
                                break
                    except SIPSubscriptionDidFail, e:
                        notification_center.remove_observer(self, sender=subscription)
                        self._subscription = None
                        if e.data.code == 407:
                            # Authentication failed, so retry the subscription in some time
                            timeout = random.uniform(60, 120)
                            raise SubscriptionError(error='Authentication failed', timeout=timeout)
                        elif e.data.code == 423:
                            # Get the value of the Min-Expires header
                            timeout = random.uniform(60, 120)
                            if e.data.min_expires is not None and e.data.min_expires > account.sip.subscribe_interval:
                                raise SubscriptionError(error='Interval too short', timeout=timeout, refresh_interval=e.data.min_expires)
                            else:
                                raise SubscriptionError(error='Interval too short', timeout=timeout)
                        elif e.data.code in (405, 406, 489):
                            command.signal(e)
                            return
                        else:
                            # Otherwise just try the next route
                            continue
                    else:
                        self.subscribed = True
                        command.signal()
                        break
            else:
                # There are no more routes to try, reschedule the subscription
                timeout = random.uniform(60, 180)
                raise SubscriptionError(error='No more routes to try', timeout=timeout)
            # At this point it is subscribed. Handle notifications and ending/failures.
            try:
                while True:
                    notification = self._data_channel.wait()
                    if notification.sender is not self._subscription:
                        continue
                    if notification.name == 'SIPSubscriptionGotNotify':
                        if notification.data.event == 'conference' and notification.data.body:
                            try:
                                conference_info = Conference.parse(notification.data.body)
                            except ValidationError:
                                pass
                            else:
                                notification_center.post_notification('SIPSessionGotConferenceInfo', sender=self.session, data=TimestampedNotificationData(conference_info=conference_info))
                    elif notification.name == 'SIPSubscriptionDidEnd':
                        break
            except SIPSubscriptionDidFail:
                self._command_channel.send(Command('subscribe'))
            notification_center.remove_observer(self, sender=self._subscription)
        except InterruptSubscription, e:
            if not self.subscribed:
                command.signal(e)
            if self._subscription is not None:
                notification_center.remove_observer(self, sender=self._subscription)
                try:
                    self._subscription.end(timeout=2)
                except SIPCoreError:
                    pass
        except TerminateSubscription, e:
            if not self.subscribed:
                command.signal(e)
            if self._subscription is not None:
                try:
                    self._subscription.end(timeout=2)
                except SIPCoreError:
                    pass
                else:
                    try:
                        while True:
                            notification = self._data_channel.wait()
                            if notification.sender is self._subscription and notification.name == 'SIPSubscriptionDidEnd':
                                break
                    except SIPSubscriptionDidFail:
                        pass
                finally:
                    notification_center.remove_observer(self, sender=self._subscription)
        except SubscriptionError, e:
            self._subscription_timer = reactor.callLater(e.timeout, self._command_channel.send, Command('subscribe', command.event, refresh_interval=e.refresh_interval))
        finally:
            self.subscribed = False
            self._subscription = None
            self._subscription_proc = None

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, Null)
        handler(notification)

    def _NH_SIPSubscriptionDidStart(self, notification):
        self._data_channel.send(notification)

    def _NH_SIPSubscriptionDidEnd(self, notification):
        self._data_channel.send(notification)

    def _NH_SIPSubscriptionDidFail(self, notification):
        self._data_channel.send_exception(SIPSubscriptionDidFail(notification.data))

    def _NH_SIPSubscriptionGotNotify(self, notification):
        self._data_channel.send(notification)

    def _NH_SIPSessionDidStart(self, notification):
        if self.session.remote_focus:
            self._activate()

    @run_in_green_thread
    def _NH_SIPSessionDidFail(self, notification):
        self._terminate()

    @run_in_green_thread
    def _NH_SIPSessionWillEnd(self, notification):
        self._terminate()

    def _NH_SIPSessionDidRenegotiateStreams(self, notification):
        if self.session.remote_focus and not self.active:
            self._activate()
        elif not self.session.remote_focus and self.active:
            self._deactivate()

    def _NH_DNSNameserversDidChange(self, notification):
        if self.active:
            self._resubscribe()

    def _NH_SystemIPAddressDidChange(self, notification):
        if self.active:
            self._resubscribe()

    def _NH_SystemDidWakeUpFromSleep(self, notification):
        if self._wakeup_timer is None:
            def wakeup_action():
                if self.active:
                    self._resubscribe()
                self._wakeup_timer = None
            self._wakeup_timer = reactor.callLater(5, wakeup_action) # wait for system to stabilize


class Session(object):
    implements(IObserver)

    media_stream_timeout = 15

    def __init__(self, account):
        self.account = account
        self.direction = None
        self.end_time = None
        self.on_hold = False
        self.proposed_streams = None
        self.route = None
        self.state = None
        self.start_time = None
        self.streams = None
        self.transport = None
        self.local_focus = False
        self.remote_focus = False
        self.greenlet = None
        self.conference = None
        self._channel = queue()
        self._hold_in_progress = False
        self._invitation = None
        self._local_identity = None
        self._remote_identity = None
        self._lock = RLock()
        self.__dict__['subject'] = None

    def init_incoming(self, invitation, data):
        notification_center = NotificationCenter()
        remote_sdp = invitation.sdp.proposed_remote
        self.proposed_streams = []
        if remote_sdp:
            for index, media_stream in enumerate(remote_sdp.media):
                if media_stream.port != 0:
                    for stream_type in MediaStreamRegistry():
                        try:
                            stream = stream_type.new_from_sdp(self.account, remote_sdp, index)
                        except InvalidStreamError:
                            break
                        except UnknownStreamError:
                            continue
                        else:
                            stream.index = index
                            self.proposed_streams.append(stream)
                            break
        if self.proposed_streams:
            self.direction = 'incoming'
            self.state = 'incoming'
            self.transport = invitation.transport
            self._invitation = invitation
            self.conference = ConferenceHandler(self)
            if 'isfocus' in invitation.remote_contact_header.parameters:
                self.remote_focus = True
            try:
                self.__dict__['subject'] = data.headers['Subject'].subject
            except KeyError:
                pass
            notification_center.add_observer(self, sender=invitation)
            notification_center.post_notification('SIPSessionNewIncoming', self, TimestampedNotificationData(streams=self.proposed_streams))
        else:
            invitation.send_response(488)

    @transition_state(None, 'connecting')
    @run_in_green_thread
    def connect(self, to_header, routes, streams, is_focus=False, subject=None):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        connected = False
        received_code = 0
        received_reason = None
        unhandled_notifications = []

        self.direction = 'outgoing'
        self.proposed_streams = streams
        self.route = routes[0]
        self.transport = self.route.transport
        self.local_focus = is_focus
        self._invitation = Invitation()
        self._local_identity = FromHeader(self.account.uri, self.account.display_name)
        self._remote_identity = to_header
        self.conference = ConferenceHandler(self)
        self.__dict__['subject'] = subject
        notification_center.add_observer(self, sender=self._invitation)
        notification_center.post_notification('SIPSessionNewOutgoing', self, TimestampedNotificationData(streams=streams))
        for stream in self.proposed_streams:
            notification_center.add_observer(self, sender=stream)
            stream.initialize(self, direction='outgoing')

        try:
            wait_count = len(self.proposed_streams)
            while wait_count > 0:
                notification = self._channel.wait()
                if notification.name == 'MediaStreamDidInitialize':
                    wait_count -= 1
            try:
                contact_uri = self.account.contact[self.route]
            except KeyError, e:
                for stream in self.proposed_streams:
                    notification_center.remove_observer(self, sender=stream)
                    stream.deactivate()
                    stream.end()
                self._fail(originator='local', code=480, reason=sip_status_messages[480], error=str(e))
                return
            local_ip = contact_uri.host
            local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip), name=settings.user_agent)
            stun_addresses = []
            for index, stream in enumerate(self.proposed_streams):
                stream.index = index
                media = stream.get_local_media(for_offer=True)
                local_sdp.media.append(media)
                stun_addresses.extend((value.split(' ', 5)[4] for value in media.attributes.getall('candidate') if value.startswith('S ')))
            if stun_addresses:
                local_sdp.connection.address = stun_addresses[0]
            from_header = FromHeader(self.account.uri, self.account.display_name)
            route_header = RouteHeader(self.route.get_uri())
            contact_header = ContactHeader(contact_uri)
            if is_focus:
                contact_header.parameters['isfocus'] = None
            extra_headers = []
            if self.subject is not None:
                extra_headers.append(SubjectHeader(self.subject))
            self._invitation.send_invite(to_header.uri, from_header, to_header, route_header, contact_header, local_sdp, self.account.credentials, extra_headers)
            try:
                with api.timeout(settings.sip.invite_timeout):
                    while True:
                        notification = self._channel.wait()
                        if notification.name == 'SIPInvitationGotSDPUpdate':
                            if notification.data.succeeded:
                                local_sdp = notification.data.local_sdp
                                remote_sdp = notification.data.remote_sdp
                                break
                            else:
                                for stream in self.proposed_streams:
                                    notification_center.remove_observer(self, sender=stream)
                                    stream.deactivate()
                                    stream.end()
                                self._fail(originator='remote', code=0, reason=None, error='SDP negotiation failed: %s' % notification.data.error)
                                return
                        elif notification.name == 'SIPInvitationChangedState':
                            if notification.data.state == 'early':
                                if notification.data.code == 180:
                                    notification_center.post_notification('SIPSessionGotRingIndication', self, TimestampedNotificationData())
                                notification_center.post_notification('SIPSessionGotProvisionalResponse', self, TimestampedNotificationData(code=notification.data.code, reason=notification.data.reason))
                            elif notification.data.state == 'connecting':
                                received_code = notification.data.code
                                received_reason = notification.data.reason
                            elif notification.data.state == 'connected':
                                if not connected:
                                    connected = True
                                    notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                                          TimestampedNotificationData(originator='local', method='INVITE', code=received_code, reason=received_reason))
                                else:
                                    unhandled_notifications.append(notification)
                            elif notification.data.state == 'disconnected':
                                raise InvitationDidFailError(notification.sender, notification.data)
            except api.TimeoutError:
                self.greenlet = None
                self.end()
                return

            notification_center.post_notification('SIPSessionWillStart', self, TimestampedNotificationData())
            stream_map = dict((stream.index, stream) for stream in self.proposed_streams)
            for index, local_media in enumerate(local_sdp.media):
                remote_media = remote_sdp.media[index]
                stream = stream_map[index]
                if remote_media.port:
                    stream.start(local_sdp, remote_sdp, index)
                else:
                    notification_center.remove_observer(self, sender=stream)
                    self.proposed_streams.remove(stream)
                    del stream_map[stream.index]
                    stream.deactivate()
                    stream.end()
            removed_streams = [stream for stream in self.proposed_streams if stream.index >= len(local_sdp.media)]
            for stream in removed_streams:
                notification_center.remove_observer(self, sender=stream)
                self.proposed_streams.remove(stream)
                del stream_map[stream.index]
                stream.deactivate()
                stream.end()
            invitation_notifications = []
            with api.timeout(self.media_stream_timeout):
                wait_count = len(self.proposed_streams)
                while wait_count > 0:
                    notification = self._channel.wait()
                    if notification.name == 'MediaStreamDidStart':
                        wait_count -= 1
                    elif notification.name == 'SIPInvitationChangedState':
                        invitation_notifications.append(notification)
            [self._channel.send(notification) for notification in invitation_notifications]
            while not connected or self._channel:
                notification = self._channel.wait()
                if notification.name == 'SIPInvitationChangedState':
                    if notification.data.state == 'early':
                        if notification.data.code == 180:
                            notification_center.post_notification('SIPSessionGotRingIndication', self, TimestampedNotificationData())
                        notification_center.post_notification('SIPSessionGotProvisionalResponse', self, TimestampedNotificationData(code=notification.data.code, reason=notification.data.reason))
                    elif notification.data.state == 'connecting':
                        received_code = notification.data.code
                        received_reason = notification.data.reason
                    elif notification.data.state == 'connected':
                        if not connected:
                            connected = True
                            notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                                  TimestampedNotificationData(originator='local', method='INVITE', code=received_code, reason=received_reason))
                        else:
                            unhandled_notifications.append(notification)
                    elif notification.data.state == 'disconnected':
                        raise InvitationDidFailError(notification.sender, notification.data)
        except (MediaStreamDidFailError, api.TimeoutError), e:
            for stream in self.proposed_streams:
                notification_center.remove_observer(self, sender=stream)
                stream.deactivate()
                stream.end()
            if isinstance(e, api.TimeoutError):
                error = 'media stream timed out while starting'
            else:
                error = 'media stream failed: %s' % e.data.reason
            self._fail(originator='local', code=0, reason=None, error=error)
        except InvitationDidFailError, e:
            notification_center.remove_observer(self, sender=self._invitation)
            for stream in self.proposed_streams:
                notification_center.remove_observer(self, sender=stream)
                stream.deactivate()
                stream.end()
            self.state = 'terminated'
            # As it weird as it may sound, PJSIP accepts a BYE even without receiving a final response to the INVITE
            if e.data.prev_state in ('connecting', 'connected') or getattr(e.data, 'method', None) == 'BYE':
                notification_center.post_notification('SIPSessionWillEnd', self, TimestampedNotificationData(originator=e.data.originator))
                if e.data.originator == 'remote':
                    notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method=e.data.method, code=200, reason=sip_status_messages[200]))
                self.end_time = datetime.now()
                notification_center.post_notification('SIPSessionDidEnd', self, TimestampedNotificationData(originator=e.data.originator, end_reason=e.data.disconnect_reason))
            else:
                if e.data.originator == 'remote':
                    notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', method='INVITE', code=e.data.code, reason=e.data.reason))
                if e.data.originator == 'remote':
                    code = e.data.code
                    reason = e.data.reason
                elif e.data.disconnect_reason == 'timeout':
                    code = 408
                    reason = 'timeout'
                else:
                    code = 0
                    reason = None
                if e.data.originator == 'remote' and code // 100 == 3:
                    redirect_identities = e.data.headers.get('Contact', [])
                else:
                    redirect_identities = None
                notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator=e.data.originator, code=code, reason=reason, failure_reason=e.data.disconnect_reason, redirect_identities=redirect_identities))
            self.greenlet = None
        except SIPCoreError, e:
            for stream in self.proposed_streams:
                notification_center.remove_observer(self, sender=stream)
                stream.deactivate()
                stream.end()
            self._fail(originator='local', code=0, reason=None, error='SIP core error: %s' % str(e))
        else:
            self.greenlet = None
            self.state = 'connected'
            self.streams = self.proposed_streams
            self.proposed_streams = None
            self.start_time = datetime.now()
            notification_center.post_notification('SIPSessionDidStart', self, TimestampedNotificationData(streams=self.streams))
            for notification in unhandled_notifications:
                self.handle_notification(notification)
            if self._hold_in_progress:
                self._send_hold()

    @check_state(['incoming', 'received_proposal'])
    @run_in_green_thread
    def send_ring_indication(self):
        try:
            self._invitation.send_response(180)
        except SIPCoreInvalidStateError:
            pass # The INVITE session might have already been cancelled; ignore the error

    @transition_state('incoming', 'accepting')
    @run_in_green_thread
    def accept(self, streams, is_focus=False):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        self.local_focus = is_focus
        connected = False
        unhandled_notifications = []

        if self.proposed_streams:
            for stream in self.proposed_streams:
                if stream in streams:
                    notification_center.add_observer(self, sender=stream)
                    stream.initialize(self, direction='incoming')
        else:
            for index, stream in enumerate(streams):
                notification_center.add_observer(self, sender=stream)
                stream.index = index
                stream.initialize(self, direction='outgoing')
        self.proposed_streams = streams

        try:
            wait_count = len(self.proposed_streams)
            while wait_count > 0:
                notification = self._channel.wait()
                if notification.name == 'MediaStreamDidInitialize':
                    wait_count -= 1

            sdp_connection = self._invitation.sdp.proposed_remote.connection or (media.connection for media in self._invitation.sdp.proposed_remote.media if media.connection is not None).next()
            local_ip = host.outgoing_ip_for(sdp_connection.address)
            if local_ip is None:
                for stream in self.proposed_streams:
                    notification_center.remove_observer(self, sender=stream)
                    stream.deactivate()
                    stream.end()
                self._fail(originator='local', code=500, reason=sip_status_messages[500], error='could not get local IP address')
                return
            local_sdp = SDPSession(local_ip, connection=SDPConnection(local_ip), name=settings.user_agent)
            stun_addresses = []
            if self._invitation.sdp.proposed_remote:
                stream_map = dict((stream.index, stream) for stream in self.proposed_streams)
                for index, media in enumerate(self._invitation.sdp.proposed_remote.media):
                    stream = stream_map.get(index, None)
                    if stream is not None:
                        media = stream.get_local_media(for_offer=False)
                        local_sdp.media.append(media)
                        stun_addresses.extend((value.split(' ', 5)[4] for value in media.attributes.getall('candidate') if value.startswith('S ')))
                    else:
                        media = SDPMediaStream.new(media)
                        media.port = 0
                        media.attributes = []
                        local_sdp.media.append(media)
            else:
                for stream in self.proposed_streams:
                    media = stream.get_local_media(for_offer=True)
                    local_sdp.media.append(media)
                    stun_addresses.extend((value.split(' ', 5)[4] for value in media.attributes.getall('candidate') if value.startswith('S ')))
            if stun_addresses:
                local_sdp.connection.address = stun_addresses[0]
            if is_focus:
                contact_header = ContactHeader.new(self._invitation.local_contact_header)
                contact_header.parameters['isfocus'] = None
                self._invitation.send_response(200, contact_header=contact_header, sdp=local_sdp)
            else:
                self._invitation.send_response(200, sdp=local_sdp)
            notification_center.post_notification('SIPSessionWillStart', self, TimestampedNotificationData())
            # Local and remote SDPs will be set after the 200 OK is sent
            while True:
                notification = self._channel.wait()
                if notification.name == 'SIPInvitationGotSDPUpdate':
                    if notification.data.succeeded:
                        local_sdp = notification.data.local_sdp
                        remote_sdp = notification.data.remote_sdp
                        break
                    else:
                        if not connected:
                            # we could not have got a SIPInvitationGotSDPUpdate if we did not get an ACK
                            connected = True
                            notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                                  TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason=sip_status_messages[200], ack_received=True))
                        for stream in self.proposed_streams:
                            notification_center.remove_observer(self, sender=stream)
                            stream.deactivate()
                            stream.end()
                        self._fail(originator='remote', code=0, reason=None, error='SDP negotiation failed: %s' % notification.data.error)
                        return
                elif notification.name == 'SIPInvitationChangedState':
                    if notification.data.state == 'connected':
                        if not connected:
                            connected = True
                            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason=sip_status_messages[200], ack_received=True))
                        elif notification.data.prev_state == 'connected':
                            unhandled_notifications.append(notification)
                    elif notification.data.state == 'disconnected':
                        raise InvitationDidFailError(notification.sender, notification.data)
            wait_count = 0
            stream_map = dict((stream.index, stream) for stream in self.proposed_streams)
            for index, local_media in enumerate(local_sdp.media):
                remote_media = remote_sdp.media[index]
                stream = stream_map.get(index, None)
                if stream is not None:
                    if remote_media.port:
                        wait_count += 1
                        stream.start(local_sdp, remote_sdp, index)
                    else:
                        notification_center.remove_observer(self, sender=stream)
                        self.proposed_streams.remove(stream)
                        del stream_map[stream.index]
                        stream.deactivate()
                        stream.end()
            removed_streams = [stream for stream in self.proposed_streams if stream.index >= len(local_sdp.media)]
            for stream in removed_streams:
                notification_center.remove_observer(self, sender=stream)
                self.proposed_streams.remove(stream)
                del stream_map[stream.index]
                stream.deactivate()
                stream.end()
            with api.timeout(self.media_stream_timeout):
                while wait_count > 0 or not connected or self._channel:
                    notification = self._channel.wait()
                    if notification.name == 'MediaStreamDidStart':
                        wait_count -= 1
                    elif notification.name == 'SIPInvitationChangedState':
                        if notification.data.state == 'connected':
                            if not connected:
                                connected = True
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason='OK', ack_received=True))
                            elif notification.data.prev_state == 'connected':
                                unhandled_notifications.append(notification)
                        elif notification.data.state == 'disconnected':
                            raise InvitationDidFailError(notification.sender, notification.data)
                    else:
                        unhandled_notifications.append(notification)
        except (MediaStreamDidFailError, api.TimeoutError), e:
            if self._invitation.state == 'connecting':
                ack_received = False if isinstance(e, api.TimeoutError) and wait_count == 0 else 'unknown'
                # pjsip's invite session object does not inform us whether the ACK was received or not
                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason='OK', ack_received=ack_received))
            elif self._invitation.state == 'connected' and not connected:
                # we didn't yet get to process the SIPInvitationChangedState (state -> connected) notification
                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason='OK', ack_received=True))
            for stream in self.proposed_streams:
                notification_center.remove_observer(self, sender=stream)
                stream.deactivate()
                stream.end()
            reason_header = None
            if isinstance(e, api.TimeoutError) and wait_count > 0:
                error = 'media stream timed out while starting'
            elif isinstance(e, api.TimeoutError) and wait_count == 0:
                error = 'No ACK received'
                reason_header = ReasonHeader('SIP')
                reason_header.cause = 500
                reason_header.text = 'Missing ACK'
            else:
                error = 'media stream failed: %s' % e.data.reason
                reason_header = ReasonHeader('SIP')
                reason_header.cause = 500
                reason_header.text = 'media stream failed to start'
            self.start_time = datetime.now()
            if self._invitation.state in ('incoming', 'early'):
                self._fail(originator='local', code=500, reason=sip_status_messages[500], error=error, reason_header=reason_header)
            else:
                self._fail(originator='local', code=0, reason=None, error=error, reason_header=reason_header)
        except InvitationDidFailError, e:
            notification_center.remove_observer(self, sender=self._invitation)
            for stream in self.proposed_streams:
                notification_center.remove_observer(self, sender=stream)
                stream.deactivate()
                stream.end()
            self.state = 'terminated'
            if e.data.prev_state in ('incoming', 'early'):
                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=487, reason='Session Cancelled', ack_received='unknown'))
                notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='remote', code=487, reason='Session Cancelled', failure_reason=e.data.disconnect_reason, redirect_identities=None))
            elif e.data.prev_state == 'connecting' and e.data.disconnect_reason == 'missing ACK':
                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason='OK', ack_received=False))
                notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='local', code=200, reason=sip_status_messages[200], failure_reason=e.data.disconnect_reason, redirect_identities=None))
            else:
                notification_center.post_notification('SIPSessionWillEnd', self, TimestampedNotificationData(originator='remote'))
                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method=e.data.method, code=200, reason='OK'))
                self.end_time = datetime.now()
                notification_center.post_notification('SIPSessionDidEnd', self, TimestampedNotificationData(originator='remote', end_reason=e.data.disconnect_reason))
            self.greenlet = None
        except SIPCoreInvalidStateError:
            # the only reason for which this error can be thrown is if invitation.send_response was called after the INVITE session was cancelled by the remote party
            notification_center.remove_observer(self, sender=self._invitation)
            for stream in self.proposed_streams:
                notification_center.remove_observer(self, sender=stream)
                stream.deactivate()
                stream.end()
            self.greenlet = None
            self.state = 'terminated'
            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=487, reason='Session Cancelled', ack_received='unknown'))
            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='remote', code=487, reason='Session Cancelled', failure_reason='user request', redirect_identities=None))
        except SIPCoreError, e:
            for stream in self.proposed_streams:
                notification_center.remove_observer(self, sender=stream)
                stream.deactivate()
                stream.end()
            self._fail(originator='local', code=500, reason=sip_status_messages[500], error='SIP core error: %s' % str(e))
        else:
            self.greenlet = None
            self.state = 'connected'
            self.streams = self.proposed_streams
            self.proposed_streams = None
            self.start_time = datetime.now()
            notification_center.post_notification('SIPSessionDidStart', self, TimestampedNotificationData(streams=self.streams))
            for notification in unhandled_notifications:
                self.handle_notification(notification)
            if self._hold_in_progress:
                self._send_hold()

    @transition_state('incoming', 'terminating')
    @run_in_green_thread
    def reject(self, code=603, reason=None):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()

        try:
            self._invitation.send_response(code, reason)
            with api.timeout(1):
                while True:
                    notification = self._channel.wait()
                    if notification.name == 'SIPInvitationChangedState':
                        if notification.data.state == 'disconnected':
                            ack_received = notification.data.disconnect_reason != 'missing ACK'
                            notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                                  TimestampedNotificationData(originator='remote', method='INVITE', code=code, reason=sip_status_messages[code], ack_received=ack_received))
                            break
        except SIPCoreInvalidStateError:
            # the only reason for which this error can be thrown is if invitation.send_response was called after the INVITE session was cancelled by the remote party
            notification_center.remove_observer(self, sender=self._invitation)
            self.greenlet = None
            self.state = 'terminated'
            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=487, reason='Session Cancelled', ack_received='unknown'))
            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='remote', code=487, reason='Session Cancelled', failure_reason='user request', redirect_identities=None))
        except SIPCoreError, e:
            self._fail(originator='local', code=500, reason=sip_status_messages[500], error='SIP core error: %s' % str(e))
        except api.TimeoutError:
            notification_center.remove_observer(self, sender=self._invitation)
            self.greenlet = None
            self.state = 'terminated'
            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=code, reason=sip_status_messages[code], ack_received=False))
            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='local', code=code, reason=sip_status_messages[code], failure_reason='timeout', redirect_identities=None))
        else:
            notification_center.remove_observer(self, sender=self._invitation)
            self.greenlet = None
            self.state = 'terminated'
            self.proposed_streams = None
            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='local', code=code, reason=sip_status_messages[code], failure_reason='error', redirect_identities=None))

    @transition_state('received_proposal', 'accepting_proposal')
    @run_in_green_thread
    def accept_proposal(self, streams):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()

        unhandled_notifications = []

        streams = [stream for stream in streams if stream in self.proposed_streams]
        for stream in self.proposed_streams:
            if stream in streams:
                notification_center.add_observer(self, sender=stream)
                stream.initialize(self, direction='incoming')

        try:
            wait_count = len(streams)
            while wait_count > 0:
                notification = self._channel.wait()
                if notification.name == 'MediaStreamDidInitialize':
                    wait_count -= 1

            local_sdp = SDPSession.new(self._invitation.sdp.active_local)
            local_sdp.version += 1
            stream_map = dict((stream.index, stream) for stream in streams)
            for index, media in enumerate(self._invitation.sdp.proposed_remote.media):
                stream = stream_map.get(index, None)
                if stream is not None:
                    if index < len(local_sdp.media):
                        local_sdp.media[index] = stream.get_local_media(for_offer=False)
                    else:
                        local_sdp.media.append(stream.get_local_media(for_offer=False))
                elif index >= len(local_sdp.media): # actually == is sufficient
                    media = SDPMediaStream.new(media)
                    media.port = 0
                    media.attributes = []
                    local_sdp.media.append(media)
            self._invitation.send_response(200, sdp=local_sdp)

            prev_on_hold_streams = set(stream for stream in self.streams if stream.hold_supported and stream.on_hold_by_remote)

            received_invitation_state = False
            received_sdp_update = False
            while not received_invitation_state or not received_sdp_update:
                notification = self._channel.wait()
                if notification.name == 'SIPInvitationGotSDPUpdate':
                    received_sdp_update = True
                    if notification.data.succeeded:
                        local_sdp = notification.data.local_sdp
                        remote_sdp = notification.data.remote_sdp
                        for stream in self.streams:
                            stream.update(local_sdp, remote_sdp, stream.index)
                    else:
                        self._fail_proposal(originator='remote', error='SDP negotiation failed: %s' % notification.data.error)
                        return
                elif notification.name == 'SIPInvitationChangedState':
                    if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason=sip_status_messages[200], ack_received='unknown'))
                        received_invitation_state = True
                    elif notification.data.state == 'disconnected':
                        raise InvitationDidFailError(notification.sender, notification.data)

            on_hold_streams = set(stream for stream in self.streams if stream.hold_supported and stream.on_hold_by_remote)
            if on_hold_streams != prev_on_hold_streams:
                hold_supported_streams = (stream for stream in self.streams if stream.hold_supported)
                notification_center.post_notification('SIPSessionDidChangeHoldState', self, TimestampedNotificationData(originator='remote', on_hold=bool(on_hold_streams),
                                                      partial=bool(on_hold_streams) and any(not stream.on_hold_by_remote for stream in hold_supported_streams)))

            for stream in streams:
                stream.start(local_sdp, remote_sdp, stream.index)
            with api.timeout(self.media_stream_timeout):
                wait_count = len(streams)
                while wait_count > 0 or self._channel:
                    notification = self._channel.wait()
                    if notification.name == 'MediaStreamDidStart':
                        wait_count -= 1
                    else:
                        unhandled_notifications.append(notification)
        except (MediaStreamDidFailError, api.TimeoutError), e:
            if isinstance(e, api.TimeoutError):
                error = 'media stream timed out while starting'
            else:
                error = 'media stream failed: %s' % e.data.reason
            self._fail_proposal(originator='remote', error=error)
        except InvitationDidFailError, e:
            self._fail_proposal(originator='remote', error='session ended')
            self.handle_notification(Notification('SIPInvitationChangedState', e.invitation, e.data))
        except SIPCoreError, e:
            self._fail_proposal(originator='remote', error='SIP core error: %s' % str(e))
        else:
            self.greenlet = None
            self.state = 'connected'
            notification_center.post_notification('SIPSessionGotAcceptProposal', self, TimestampedNotificationData(originator='remote', streams=streams, proposed_streams=self.proposed_streams))
            self.streams = self.streams + streams
            self.proposed_streams = None
            notification_center.post_notification('SIPSessionDidRenegotiateStreams', self, TimestampedNotificationData(originator='remote', action='add', streams=streams))
            for notification in unhandled_notifications:
                self.handle_notification(notification)
            if self._hold_in_progress:
                self._send_hold()

    @transition_state('received_proposal', 'rejecting_proposal')
    @run_in_green_thread
    def reject_proposal(self, code=488, reason=None):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()

        try:
            self._invitation.send_response(code, reason)
            with api.timeout(1, None):
                while True:
                    notification = self._channel.wait()
                    if notification.name == 'SIPInvitationChangedState':
                        if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=code, reason=sip_status_messages[code], ack_received='unknown'))
        except SIPCoreError, e:
            self._fail_proposal(originator='remote', error='SIP core error: %s' % str(e))
        else:
            self.greenlet = None
            self.state = 'connected'
            notification_center.post_notification('SIPSessionGotRejectProposal', self, TimestampedNotificationData(originator='remote', code=code, reason=sip_status_messages[code], streams=self.proposed_streams))
            self.proposed_streams = None
            if self._hold_in_progress:
                self._send_hold()

    @transition_state('connected', 'sending_proposal')
    @run_in_green_thread
    def add_stream(self, stream):
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        settings = SIPSimpleSettings()

        received_code = None
        received_reason = None
        unhandled_notifications = []

        self.proposed_streams = [stream]
        notification_center.add_observer(self, sender=stream)
        stream.initialize(self, direction='outgoing')

        try:
            while True:
                notification = self._channel.wait()
                if notification.name == 'MediaStreamDidInitialize':
                    break
                elif notification.name == 'SIPInvitationChangedState':
                    # This is actually the only reason for which this notification could be received
                    if notification.data.state == 'connected' and notification.data.sub_state == 'received_proposal':
                        self._fail_proposal(originator='local', error='received stream proposal')
                        self.handle_notification(notification)
                        return

            local_sdp = SDPSession.new(self._invitation.sdp.active_local)
            local_sdp.version += 1
            stream.index = len(local_sdp.media)
            local_sdp.media.append(stream.get_local_media(for_offer=True))
            self._invitation.send_reinvite(sdp=local_sdp)
            notification_center.post_notification('SIPSessionGotProposal', self, TimestampedNotificationData(originator='local', streams=self.proposed_streams))

            received_invitation_state = False
            received_sdp_update = False
            try:
                with api.timeout(settings.sip.invite_timeout):
                    while not received_invitation_state or not received_sdp_update:
                        notification = self._channel.wait()
                        if notification.name == 'SIPInvitationGotSDPUpdate':
                            received_sdp_update = True
                            if notification.data.succeeded:
                                local_sdp = notification.data.local_sdp
                                remote_sdp = notification.data.remote_sdp
                                for s in self.streams:
                                    s.update(local_sdp, remote_sdp, s.index)
                            else:
                                self._fail_proposal(originator='local', error='SDP negotiation failed: %s' % notification.data.error)
                                return
                        elif notification.name == 'SIPInvitationChangedState':
                            if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                                received_invitation_state = True
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', method='INVITE', code=notification.data.code, reason=notification.data.reason))
                                if 200 <= notification.data.code < 300:
                                    received_code = notification.data.code
                                    received_reason = notification.data.reason
                                else:
                                    notification_center.remove_observer(self, sender=stream)
                                    stream.deactivate()
                                    stream.end()
                                    notification_center.post_notification('SIPSessionGotRejectProposal', self, TimestampedNotificationData(originator='local', code=notification.data.code, reason=notification.data.reason, streams=self.proposed_streams))
                                    self.state = 'connected'
                                    self.proposed_streams = None
                                    self.greenlet = None
                                    return
                            elif notification.data.state == 'disconnected':
                                raise InvitationDidFailError(notification.sender, notification.data)
            except api.TimeoutError:
                self.greenlet = None
                self.cancel_proposal()
                return

            try:
                remote_media = remote_sdp.media[stream.index]
            except IndexError:
                self._fail_proposal(originator='local', error='SDP media missing in answer')
                return
            else:
                if remote_media.port:
                    stream.start(local_sdp, remote_sdp, stream.index)
                else:
                    notification_center.remove_observer(self, sender=stream)
                    stream.deactivate()
                    stream.end()
                    notification_center.post_notification('SIPSessionGotRejectProposal', self, TimestampedNotificationData(originator='local', code=received_code, reason=received_reason, streams=self.proposed_streams))
                    self.state = 'connected'
                    self.proposed_streams = None
                    self.greenlet = None
                    return

            with api.timeout(self.media_stream_timeout):
                wait_count = 1
                while wait_count > 0 or self._channel:
                    notification = self._channel.wait()
                    if notification.name == 'MediaStreamDidStart':
                        wait_count -= 1
        except (MediaStreamDidFailError, api.TimeoutError), e:
            if isinstance(e, api.TimeoutError):
                error = 'media stream timed out while starting'
            else:
                error = 'media stream failed: %s' % e.data.reason
            self._fail_proposal(originator='local', error=error)
        except InvitationDidFailError, e:
            self._fail_proposal(originator='local', error='session ended')
            self.handle_notification(Notification('SIPInvitationChangedState', e.invitation, e.data))
        except SIPCoreError, e:
            self._fail_proposal(originator='local', error='SIP core error: %s' % str(e))
        else:
            self.greenlet = None
            self.state = 'connected'
            notification_center.post_notification('SIPSessionGotAcceptProposal', self, TimestampedNotificationData(originator='local', streams=self.proposed_streams, proposed_streams=self.proposed_streams))
            self.streams = self.streams + self.proposed_streams
            proposed_streams = self.proposed_streams
            self.proposed_streams = None
            notification_center.post_notification('SIPSessionDidRenegotiateStreams', self, TimestampedNotificationData(originator='local', action='add', streams=proposed_streams))
            for notification in unhandled_notifications:
                self.handle_notification(notification)
            if self._hold_in_progress:
                self._send_hold()

    @transition_state('connected', 'sending_proposal')
    @run_in_green_thread
    def remove_stream(self, stream):
        if stream not in self.streams:
            self.state = 'connected'
            return
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()

        unhandled_notifications = []

        try:
            notification_center.remove_observer(self, sender=stream)
            stream.deactivate()
            self.streams.remove(stream)

            local_sdp = SDPSession.new(self._invitation.sdp.active_local)
            local_sdp.version += 1
            local_sdp.media[stream.index].port = 0
            local_sdp.media[stream.index].attributes = []
            self._invitation.send_reinvite(sdp=local_sdp)

            received_invitation_state = False
            received_sdp_update = False
            while not received_invitation_state or not received_sdp_update:
                notification = self._channel.wait()
                if notification.name == 'SIPInvitationGotSDPUpdate':
                    received_sdp_update = True
                elif notification.name == 'SIPInvitationChangedState':
                    if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                        received_invitation_state = True
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', method='INVITE', code=notification.data.code, reason=notification.data.reason))
                    elif notification.data.state == 'disconnected':
                        raise InvitationDidFailError(notification.sender, notification.data)
        except InvitationDidFailError, e:
            self.greenlet = None
            self.handle_notification(Notification('SIPInvitationChangedState', e.invitation, e.data))
        except SIPCoreError:
            raise #FIXME
        else:
            stream.end()
            self.greenlet = None
            self.state = 'connected'
            notification_center.post_notification('SIPSessionDidRenegotiateStreams', self, TimestampedNotificationData(originator='local', action='remove', streams=[stream]))
            for notification in unhandled_notifications:
                self.handle_notification(notification)
            if self._hold_in_progress:
                self._send_hold()

    @transition_state('sending_proposal', 'cancelling_proposal')
    @run_in_green_thread
    def cancel_proposal(self):
        if self.greenlet is not None:
            api.kill(self.greenlet, api.GreenletExit())
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        try:
            self._invitation.cancel_reinvite()
            while True:
                try:
                    notification = self._channel.wait()
                except MediaStreamDidFailError:
                    continue
                if notification.name == 'SIPInvitationChangedState':
                    if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=notification.data.code, reason=notification.data.reason))
                        if notification.data.code == 487:
                            for stream in self.proposed_streams:
                                stream.deactivate()
                                stream.end()
                            notification_center.post_notification('SIPSessionGotRejectProposal', self, TimestampedNotificationData(originator='remote', code=notification.data.code, reason=notification.data.reason, streams=self.proposed_streams))
                        elif notification.data.code == 200:
                            self.end()
                    elif notification.data.state == 'disconnected':
                        raise InvitationDidFailError(notification.sender, notification.data)
                    break
        except SIPCoreError, e:
            for stream in self.proposed_streams:
                stream.deactivate()
                stream.end()
            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', code=0, reason=None, failure_reason='SIP core error: %s' % str(e), redirect_identities=None))
            notification_center.post_notification('SIPSessionGotRejectProposal', self, TimestampedNotificationData(originator='local', code=0, reason='SIP core error: %s' % str(e), streams=self.proposed_streams))
            self.proposed_streams = None
            self.greenlet = None
            self.state = 'connected'
        except InvitationDidFailError, e:
            self.proposed_streams = None
            self.greenlet = None
            self.handle_notification(Notification('SIPInvitationChangedState', e.invitation, e.data))
        else:
            self.proposed_streams = None
            self.greenlet = None
            self.state = 'connected'
        finally:
            if self._hold_in_progress:
                self._send_hold()

    @run_in_green_thread
    def hold(self):
        if self.on_hold or self._hold_in_progress:
            return
        self._hold_in_progress = True
        streams = self.streams if self.streams is not None else self.proposed_streams
        if not streams:
            return
        for stream in streams:
            stream.hold()
        if self.state == 'connected':
            self._send_hold()

    @run_in_green_thread
    def unhold(self):
        if not self.on_hold and not self._hold_in_progress:
            return
        self._hold_in_progress = False
        streams = self.streams if self.streams is not None else self.proposed_streams
        if not streams:
            return
        for stream in streams:
            stream.unhold()
        if self.state == 'connected':
            self._send_unhold()

    @run_in_green_thread
    def end(self):
        if self.state is None:
            return
        if self.greenlet is not None:
            api.kill(self.greenlet, api.GreenletExit())
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()
        if self._invitation is None or self._invitation.state is None:
            # The invitation was not yet constructed
            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='local', code=487, reason='Session Cancelled', failure_reason='user request', redirect_identities=None))
            return
        if self._invitation.state in ('disconnecting', 'disconnected'):
            return
        self.state = 'terminating'
        if self._invitation.state == 'connected':
            notification_center.post_notification('SIPSessionWillEnd', self, TimestampedNotificationData(originator='local'))
        streams = (self.streams or []) + (self.proposed_streams or [])
        for stream in streams[:]:
            try:
                notification_center.remove_observer(self, sender=stream)
            except KeyError:
                streams.remove(stream)
            else:
                stream.deactivate()
        cancelling = self._invitation.state != 'connected' and self.direction == 'outgoing'
        try:
            self._invitation.end(timeout=1)
            while True:
                try:
                    notification = self._channel.wait()
                except MediaStreamDidFailError:
                    continue
                if notification.name == 'SIPInvitationChangedState' and notification.data.state == 'disconnected':
                    if notification.data.disconnect_reason in ('internal error', 'missing ACK'):
                        pass
                    elif notification.data.disconnect_reason == 'timeout':
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                              TimestampedNotificationData(originator='local' if self.direction=='outgoing' else 'remote', method='INVITE', code=408, reason='Timeout'))
                    elif cancelling:
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                              TimestampedNotificationData(originator='local', method='INVITE', code=notification.data.code, reason=notification.data.reason))
                    elif hasattr(notification.data, 'method'):
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                              TimestampedNotificationData(originator='remote', method=notification.data.method, code=200, reason=sip_status_messages[200]))
                    elif notification.data.disconnect_reason == 'user request':
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self,
                                                              TimestampedNotificationData(originator='local', method='BYE', code=notification.data.code, reason=notification.data.reason))
                    break
        except SIPCoreError, e:
            if cancelling:
                notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='local', code=0, reason=None, failure_reason='SIP core error: %s' % str(e), redirect_identities=None))
            else:
                self.end_time = datetime.now()
                notification_center.post_notification('SIPSessionDidEnd', self, TimestampedNotificationData(originator='local', end_reason='SIP core error: %s' % str(e)))
            return
        finally:
            for stream in streams:
                stream.end()
            notification_center.remove_observer(self, sender=self._invitation)
        self.greenlet = None
        self.state = 'terminated'
        if cancelling:
            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='local', code=487, reason='Session Cancelled', failure_reason='user request', redirect_identities=None))
        else:
            self.end_time = datetime.now()
            notification_center.post_notification('SIPSessionDidEnd', self, TimestampedNotificationData(originator='local', end_reason='user request'))

    @property
    def local_identity(self):
        if self._invitation is not None and self._invitation.local_identity is not None:
            return self._invitation.local_identity
        else:
            return self._local_identity

    @property
    def peer_address(self):
        return self._invitation.peer_address if self._invitation is not None else None

    @property
    def remote_identity(self):
        if self._invitation is not None and self._invitation.remote_identity is not None:
            return self._invitation.remote_identity
        else:
            return self._remote_identity

    @property
    def remote_user_agent(self):
        return self._invitation.remote_user_agent if self._invitation is not None else None

    @property
    def subject(self):
        return self.__dict__['subject']

    def _send_hold(self):
        self.state = 'sending_proposal'
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()

        unhandled_notifications = []

        try:
            local_sdp = SDPSession.new(self._invitation.sdp.active_local)
            local_sdp.version += 1
            for stream in self.streams:
                local_sdp.media[stream.index] = stream.get_local_media(for_offer=True)
            self._invitation.send_reinvite(sdp=local_sdp)

            received_invitation_state = False
            received_sdp_update = False
            while not received_invitation_state or not received_sdp_update:
                notification = self._channel.wait()
                if notification.name == 'SIPInvitationGotSDPUpdate':
                    received_sdp_update = True
                    if notification.data.succeeded:
                        local_sdp = notification.data.local_sdp
                        remote_sdp = notification.data.remote_sdp

                        for stream in self.streams:
                            stream.update(local_sdp, remote_sdp, stream.index)
                elif notification.name == 'SIPInvitationChangedState':
                    if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                        received_invitation_state = True
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', method='INVITE', code=notification.data.code, reason=notification.data.reason))
                    elif notification.data.state == 'disconnected':
                        raise InvitationDidFailError(notification.sender, notification.data)
        except InvitationDidFailError, e:
            self.greenlet = None
            self.handle_notification(Notification('SIPInvitationChangedState', e.invitation, e.data))
        except SIPCoreError, e:
            raise #FIXME
        else:
            self.greenlet = None
            self.on_hold = True
            self.state = 'connected'
            hold_supported_streams = (stream for stream in self.streams if stream.hold_supported)
            notification_center.post_notification('SIPSessionDidChangeHoldState', self, TimestampedNotificationData(originator='local', on_hold=True, partial=any(not stream.on_hold_by_local for stream in hold_supported_streams)))
            for notification in unhandled_notifications:
                self.handle_notification(notification)
            if not self._hold_in_progress:
                for stream in self.streams:
                    stream.unhold()
                self._send_unhold()
            else:
                self._hold_in_progress = False

    def _send_unhold(self):
        self.state = 'sending_proposal'
        self.greenlet = api.getcurrent()
        notification_center = NotificationCenter()

        unhandled_notifications = []

        try:
            local_sdp = SDPSession.new(self._invitation.sdp.active_local)
            local_sdp.version += 1
            for stream in self.streams:
                local_sdp.media[stream.index] = stream.get_local_media(for_offer=True)
            self._invitation.send_reinvite(sdp=local_sdp)

            received_invitation_state = False
            received_sdp_update = False
            while not received_invitation_state or not received_sdp_update:
                notification = self._channel.wait()
                if notification.name == 'SIPInvitationGotSDPUpdate':
                    received_sdp_update = True
                    if notification.data.succeeded:
                        local_sdp = notification.data.local_sdp
                        remote_sdp = notification.data.remote_sdp

                        for stream in self.streams:
                            stream.update(local_sdp, remote_sdp, stream.index)
                elif notification.name == 'SIPInvitationChangedState':
                    if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                        received_invitation_state = True
                        notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', method='INVITE', code=notification.data.code, reason=notification.data.reason))
                    elif notification.data.state == 'disconnected':
                        raise InvitationDidFailError(notification.sender, notification.data)
        except InvitationDidFailError, e:
            self.greenlet = None
            self.handle_notification(Notification('SIPInvitationChangedState', e.invitation, e.data))
        except SIPCoreError, e:
            raise #FIXME
        else:
            self.greenlet = None
            self.on_hold = False
            self.state = 'connected'
            notification_center.post_notification('SIPSessionDidChangeHoldState', self, TimestampedNotificationData(originator='local', on_hold=False, partial=False))
            for notification in unhandled_notifications:
                self.handle_notification(notification)
            if self._hold_in_progress:
                for stream in self.streams:
                    stream.hold()
                self._send_hold()

    def _fail(self, originator, code, reason, error, reason_header=None):
        notification_center = NotificationCenter()
        prev_inv_state = self._invitation.state
        self.state = 'terminating'
        if prev_inv_state not in (None, 'incoming', 'outgoing', 'early', 'connecting'):
            notification_center.post_notification('SIPSessionWillEnd', self, TimestampedNotificationData(originator=originator))
        if self._invitation.state not in (None, 'disconnecting', 'disconnected'):
            try:
                if self._invitation.direction == 'incoming' and self._invitation.state in ('incoming', 'early'):
                    if 400<=code<=699 and reason is not None:
                        self._invitation.send_response(code, extra_headers=[reason_header] if reason_header is not None else [])
                else:
                    self._invitation.end(extra_headers=[reason_header] if reason_header is not None else [])
                with api.timeout(1):
                    while True:
                        notification = self._channel.wait()
                        if notification.name == 'SIPInvitationChangedState' and notification.data.state == 'disconnected':
                            if prev_inv_state in ('connecting', 'connected'):
                                if notification.data.disconnect_reason in ('timeout', 'missing ACK'):
                                    sip_code = 200
                                    sip_reason = 'OK'
                                    originator = 'local'
                                elif hasattr(notification.data, 'method'):
                                    sip_code = 200
                                    sip_reason = 'OK'
                                    originator = 'remote'
                                else:
                                    sip_code = notification.data.code
                                    sip_reason = notification.data.reason
                                    originator = 'local'
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator=originator, method='BYE', code=sip_code, reason=sip_reason))
                            elif self._invitation.direction == 'incoming' and prev_inv_state in ('incoming', 'early'):
                                ack_received = notification.data.disconnect_reason != 'missing ACK'
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=code, reason=reason, ack_received=ack_received))
                            elif self._invitation.direction == 'outgoing' and prev_inv_state in ('outgoing', 'early'):
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', method='INVITE', code=487, reason='Session Cancelled'))
                            break
            except SIPCoreError:
                pass
            except api.TimeoutError:
                if prev_inv_state in ('connecting', 'connected'):
                    notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='local', method='BYE', code=408, reason=sip_status_messages[408]))
        notification_center.remove_observer(self, sender=self._invitation)
        self.state = 'terminated'
        notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator=originator, code=code, reason=reason, failure_reason=error, redirect_identities=None))
        self.greenlet = None

    def _fail_proposal(self, originator, error):
        notification_center = NotificationCenter()
        for stream in self.proposed_streams:
            try:
                notification_center.remove_observer(self, sender=stream)
            except KeyError:
                # _fail_proposal can be called from reject_proposal, which means the stream will
                # not have been initialized or the session registered as an observer for it.
                pass
            else:
                stream.deactivate()
                stream.end()
        if originator == 'remote' and self._invitation.sub_state == 'received_proposal':
            try:
                self._invitation.send_response(500)
            except SIPCoreError:
                pass
            else:
                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=500, reason=sip_status_messages[500], ack_received='unknown'))
        notification_center.post_notification('SIPSessionHadProposalFailure', self, TimestampedNotificationData(originator=originator, failure_reason=error, streams=self.proposed_streams))
        self.state = 'connected'
        self.proposed_streams = None
        self.greenlet = None

    @run_in_green_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_SIPInvitationChangedState(self, notification):
        if self.state == 'terminated':
            return
        if notification.data.originator == 'remote' and notification.data.state not in ('disconnecting', 'disconnected'):
            contact_header = notification.data.headers.get('Contact', None)
            if contact_header and 'isfocus' in contact_header[0].parameters:
                self.remote_focus = True
        if self.greenlet is not None:
            if notification.data.state == 'disconnected' and notification.data.prev_state != 'disconnecting':
                self._channel.send_exception(InvitationDidFailError(notification.sender, notification.data))
            else:
                self._channel.send(notification)
        else:
            notification_center = NotificationCenter()
            self.greenlet = api.getcurrent()
            try:
                if notification.data.state == 'connected' and notification.data.sub_state == 'received_proposal':
                    self.state = 'received_proposal'
                    try:
                        proposed_remote_sdp = self._invitation.sdp.proposed_remote
                        active_remote_sdp = self._invitation.sdp.active_remote
                        for stream in self.streams:
                            if not stream.validate_update(proposed_remote_sdp, stream.index):
                                engine = Engine()
                                self._invitation.send_response(488, extra_headers=[WarningHeader(399, engine.user_agent, 'Failed to update media stream index %d' % stream.index)])
                                self.state = 'connected'
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=488, reason=sip_status_messages[488], ack_received='unknown'))
                                return
                        # These tests are here because some ALGs mess up the SDP and the behaviour
                        # of pjsip in these situations is unexpected (eg. loss of audio). -Luci
                        for attr in ('user', 'net_type', 'address_type'):
                            if getattr(proposed_remote_sdp, attr) != getattr(active_remote_sdp, attr):
                                engine = Engine()
                                self._invitation.send_response(488, extra_headers=[WarningHeader(399, engine.user_agent, 'Difference in contents of o= line')])
                                self.state = 'connected'
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=488, reason=sip_status_messages[488], ack_received='unknown'))
                                return
                        added_media_indexes = set()
                        removed_media_indexes = set()
                        for index, media_stream in enumerate(proposed_remote_sdp.media):
                            if index >= len(active_remote_sdp.media):
                                added_media_indexes.add(index)
                            elif media_stream.media != active_remote_sdp.media[index].media:
                                added_media_indexes.add(index)
                                removed_media_indexes.add(index)
                            elif not media_stream.port and active_remote_sdp.media[index].port:
                                removed_media_indexes.add(index)
                        removed_media_indexes.update(xrange(len(proposed_remote_sdp.media), len(active_remote_sdp.media)))
                        if added_media_indexes and removed_media_indexes:
                            engine = Engine()
                            self._invitation.send_response(488, extra_headers=[WarningHeader(399, engine.user_agent, 'Both removing AND adding a media stream is currently not supported')])
                            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=488, reason=sip_status_messages[488], ack_received='unknown'))
                        elif added_media_indexes:
                            self.proposed_streams = []
                            for index in added_media_indexes:
                                media_stream = proposed_remote_sdp.media[index]
                                if media_stream.port != 0:
                                    for stream_type in MediaStreamRegistry():
                                        try:
                                            stream = stream_type.new_from_sdp(self.account, proposed_remote_sdp, index)
                                        except InvalidStreamError:
                                            break
                                        except UnknownStreamError:
                                            continue
                                        else:
                                            stream.index = index
                                            self.proposed_streams.append(stream)
                                            break
                            if self.proposed_streams:
                                self._invitation.send_response(100)
                                notification_center.post_notification('SIPSessionGotProposal', sender=self, data=TimestampedNotificationData(originator='remote', streams=self.proposed_streams))
                                return
                            else:
                                self._invitation.send_response(488)
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=488, reason=sip_status_messages[488], ack_received='unknown'))
                        else:
                            local_sdp = SDPSession.new(self._invitation.sdp.active_local)
                            local_sdp.version += 1
                            removed_streams = [stream for stream in self.streams if stream.index in removed_media_indexes]
                            prev_on_hold_streams = set(stream for stream in self.streams if stream.hold_supported and stream.on_hold_by_remote)
                            for stream in removed_streams:
                                notification_center.remove_observer(self, sender=stream)
                                stream.deactivate()
                                local_sdp.media[stream.index].port = 0
                                local_sdp.media[stream.index].attributes = []
                            for stream in self.streams:
                                local_sdp.media[stream.index] = stream.get_local_media(for_offer=False)
                            try:
                                self._invitation.send_response(200, sdp=local_sdp)
                            except PJSIPError, e:
                                if 'PJMEDIA_SDPNEG' in str(e):
                                    engine = Engine()
                                    self._invitation.send_response(488, extra_headers=[WarningHeader(399, engine.user_agent, 'Changing the codec of an audio stream is currently not supported')])
                                    self.state = 'connected'
                                    notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=488, reason=sip_status_messages[488], ack_received='unknown'))
                                    return
                                else:
                                    raise
                            else:
                                for stream in removed_streams:
                                    self.streams.remove(stream)
                                    stream.end()
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=200, reason=sip_status_messages[200], ack_received='unknown'))

                                received_invitation_state = False
                                received_sdp_update = False
                                while not received_sdp_update or not received_invitation_state:
                                    notification = self._channel.wait()
                                    if notification.name == 'SIPInvitationGotSDPUpdate':
                                        received_sdp_update = True
                                        if notification.data.succeeded:
                                            local_sdp = notification.data.local_sdp
                                            remote_sdp = notification.data.remote_sdp
                                            for stream in self.streams:
                                                stream.update(local_sdp, remote_sdp, stream.index)
                                    elif notification.name == 'SIPInvitationChangedState':
                                        if notification.data.state == 'connected' and notification.data.sub_state == 'normal':
                                            received_invitation_state = True
                                on_hold_streams = set(stream for stream in self.streams if stream.hold_supported and stream.on_hold_by_remote)
                                if on_hold_streams != prev_on_hold_streams:
                                    hold_supported_streams = (stream for stream in self.streams if stream.hold_supported)
                                    notification_center.post_notification('SIPSessionDidChangeHoldState', self, TimestampedNotificationData(originator='remote', on_hold=bool(on_hold_streams),
                                                                          partial=bool(on_hold_streams) and any(not stream.on_hold_by_remote for stream in hold_supported_streams)))
                                if removed_media_indexes:
                                    notification_center.post_notification('SIPSessionDidRenegotiateStreams', self, TimestampedNotificationData(originator='remote', action='remove', streams=removed_streams))
                    except InvitationDidFailError, e:
                        self.greenlet = None
                        self.state == 'connected'
                        self.handle_notification(Notification('SIPInvitationChangedState', e.invitation, e.data))
                    except SIPCoreError:
                        raise #FIXME
                    else:
                        self.state = 'connected'
                elif notification.data.state == 'connected' and notification.data.sub_state == 'normal' and notification.data.prev_sub_state == 'received_proposal':
                    if notification.data.originator == 'local' and notification.data.code == 487:
                        self.state = 'connected'
                        notification_center.post_notification('SIPSessionGotRejectProposal', self, TimestampedNotificationData(originator='remote', code=notification.data.code, reason=notification.data.reason, streams=self.proposed_streams))
                        self.proposed_streams = None
                        if self._hold_in_progress:
                            self._send_hold()
                elif notification.data.state == 'disconnected':
                    if self.state == 'incoming':
                        self.state = 'terminated'
                        if notification.data.originator == 'remote':
                            notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator='remote', method='INVITE', code=487, reason='Session Cancelled', ack_received='unknown'))
                            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='remote', code=487, reason='Session Cancelled', failure_reason=notification.data.disconnect_reason, redirect_identities=None))
                        else:
                            # There must have been an error involved
                            notification_center.post_notification('SIPSessionDidFail', self, TimestampedNotificationData(originator='local', code=0, reason=None, failure_reason=notification.data.disconnect_reason, redirect_identities=None))
                    else:
                        notification_center.post_notification('SIPSessionWillEnd', self, TimestampedNotificationData(originator=notification.data.originator))
                        for stream in self.streams:
                            notification_center.remove_observer(self, sender=stream)
                            stream.deactivate()
                            stream.end()
                        self.state = 'terminated'
                        if notification.data.originator == 'remote':
                            if hasattr(notification.data, 'method'):
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator=notification.data.originator, method=notification.data.method, code=200, reason=sip_status_messages[200]))
                            else:
                                notification_center.post_notification('SIPSessionDidProcessTransaction', self, TimestampedNotificationData(originator=notification.data.originator, method='INVITE', code=notification.data.code, reason=notification.data.reason))
                        self.end_time = datetime.now()
                        notification_center.post_notification('SIPSessionDidEnd', self, TimestampedNotificationData(originator=notification.data.originator, end_reason=notification.data.disconnect_reason))
                    notification_center.remove_observer(self, sender=self._invitation)
            finally:
                self.greenlet = None

    def _NH_SIPInvitationGotSDPUpdate(self, notification):
        if self.greenlet is not None:
            self._channel.send(notification)

    def _NH_MediaStreamDidInitialize(self, notification):
        if self.greenlet is not None:
            self._channel.send(notification)

    def _NH_MediaStreamDidStart(self, notification):
        if self.greenlet is not None:
            self._channel.send(notification)

    def _NH_MediaStreamDidFail(self, notification):
        if self.greenlet is not None:
            if self.state not in ('terminating', 'terminated'):
                self._channel.send_exception(MediaStreamDidFailError(notification.sender, notification.data))
        else:
            stream = notification.sender
            if self.streams == [stream]:
                self.greenlet = None
                self.end()
            else:
                try:
                    self.remove_stream(stream)
                except IllegalStateError:
                    notification_center = NotificationCenter()
                    notification_center.remove_observer(self, sender=stream)
                    self.streams.remove(stream)
                    notification_center.post_notification('SIPSessionDidRenegotiateStreams', self, TimestampedNotificationData(originator='remote', action='remove', streams=[stream]))


class SessionManager(object):
    __metaclass__ = Singleton
    implements(IObserver)

    def __init__(self):
        self.sessions = []
        self.state = None
        self._channel = coros.queue()

    def start(self):
        self.state = 'starting'
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPSessionManagerWillStart', self, TimestampedNotificationData())
        notification_center.add_observer(self, 'SIPInvitationChangedState')
        notification_center.add_observer(self, 'SIPSessionNewIncoming')
        notification_center.add_observer(self, 'SIPSessionNewOutgoing')
        notification_center.add_observer(self, 'SIPSessionDidFail')
        notification_center.add_observer(self, 'SIPSessionDidEnd')
        self.state = 'started'
        notification_center.post_notification('SIPSessionManagerDidStart', self, TimestampedNotificationData())

    def stop(self):
        self.state = 'stopping'
        notification_center = NotificationCenter()
        notification_center.post_notification('SIPSessionManagerWillEnd', self, TimestampedNotificationData())
        for session in self.sessions:
            session.end()
        while self.sessions:
            self._channel.wait()
        notification_center.remove_observer(self, 'SIPInvitationChangedState')
        notification_center.remove_observer(self, 'SIPSessionNewIncoming')
        notification_center.remove_observer(self, 'SIPSessionNewOutgoing')
        notification_center.remove_observer(self, 'SIPSessionDidFail')
        notification_center.remove_observer(self, 'SIPSessionDidEnd')
        self.state = 'stopped'
        notification_center.post_notification('SIPSessionManagerDidEnd', self, TimestampedNotificationData())

    @run_in_twisted_thread
    def handle_notification(self, notification):
        if notification.name == 'SIPInvitationChangedState' and notification.data.state == 'incoming':
            account_manager = AccountManager()
            account = account_manager.find_account(notification.data.request_uri)
            if account is None:
                notification.sender.send_response(404)
                return
            notification.sender.send_response(100)
            session = Session(account)
            session.init_incoming(notification.sender, notification.data)
        elif notification.name in ('SIPSessionNewIncoming', 'SIPSessionNewOutgoing'):
            self.sessions.append(notification.sender)
        elif notification.name in ('SIPSessionDidFail', 'SIPSessionDidEnd'):
            self.sessions.remove(notification.sender)
            if self.state == 'stopping':
                self._channel.send(notification)


