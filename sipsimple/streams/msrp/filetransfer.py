
"""
This module provides classes to parse and generate SDP related to SIP sessions that negotiate File Transfer.
"""

__all__ = ['FileTransferStream', 'FileSelector']

import cPickle as pickle
import hashlib
import mimetypes
import os
import random
import re
import time
import uuid

from abc import ABCMeta, abstractmethod
from application.notification import NotificationCenter, NotificationData, IObserver
from application.python.threadpool import ThreadPool, run_in_threadpool
from application.python.types import MarkerType
from application.system import FileExistsError, makedirs, openfile, unlink
from itertools import count
from msrplib.protocol import MSRPHeader, FailureReportHeader, SuccessReportHeader, ContentTypeHeader
from msrplib.session import MSRPSession
from msrplib.transport import make_response
from Queue import Queue
from threading import Event, Lock
from zope.interface import implements

from sipsimple.configuration.settings import SIPSimpleSettings
from sipsimple.core import SDPAttribute
from sipsimple.storage import ISIPSimpleApplicationDataStorage
from sipsimple.streams import InvalidStreamError, UnknownStreamError
from sipsimple.streams.msrp import MSRPStreamBase
from sipsimple.threading import run_in_twisted_thread, run_in_thread
from sipsimple.util import sha1


HASH = type(hashlib.sha1())


class RandomID: __metaclass__ = MarkerType


class FileSelectorHash(str):
    _hash_re = re.compile('^sha-1(:[0-9A-F]{2}){20}$')
    _byte_re = re.compile('..')

    def __new__(cls, value):
        if isinstance(value, str):
            if value.startswith('sha1:'):  # backward compatibility hack (sort of).
                value = 'sha-1' + value[len('sha1'):]
            if not cls._hash_re.match(value):
                raise ValueError("Invalid hash value: {!r}".format(value))
            return super(FileSelectorHash, cls).__new__(cls, value)
        elif isinstance(value, (HASH, sha1)):
            return super(FileSelectorHash, cls).__new__(cls, cls.encode_hash(value))
        else:
            raise ValueError("Invalid hash value: {!r}".format(value))

    def __eq__(self, other):
        if isinstance(other, str):
            return super(FileSelectorHash, self).__eq__(other)
        elif isinstance(other, (HASH, sha1)) and other.name.lower() == 'sha1':
            return super(FileSelectorHash, self).__eq__(self.encode_hash(other))
        else:
            return NotImplemented

    def __ne__(self, other):
        return not (self == other)

    @classmethod
    def encode_hash(cls, hash_instance):
        if hash_instance.name.lower() != 'sha1':
            raise TypeError("Invalid hash type: {.name} (only sha1 hashes are supported).".format(hash_instance))
        # unexpected as it may be, using a regular expression is the fastest method to do this
        return 'sha-1:' + ':'.join(cls._byte_re.findall(hash_instance.hexdigest().upper()))


class FileSelector(object):
    _name_re = re.compile('name:"([^"]+)"')
    _size_re = re.compile('size:(\d+)')
    _type_re = re.compile('type:([^ ]+)')
    _hash_re = re.compile('hash:([^ ]+)')

    def __init__(self, name=None, type=None, size=None, hash=None, fd=None):
        # If present, hash should be a sha1 object or a string in the form: sha-1:72:24:5F:E8:65:3D:DA:F3:71:36:2F:86:D4:71:91:3E:E4:A2:CE:2E
        # According to the specification, only sha1 is supported ATM.
        self.name = name
        self.type = type
        self.size = size
        self.hash = hash
        self.fd = fd

    def _get_hash(self):
        return self.__dict__['hash']

    def _set_hash(self, value):
        self.__dict__['hash'] = None if value is None else FileSelectorHash(value)

    hash = property(_get_hash, _set_hash)
    del _get_hash, _set_hash

    @classmethod
    def parse(cls, string):
        name_match = cls._name_re.search(string)
        size_match = cls._size_re.search(string)
        type_match = cls._type_re.search(string)
        hash_match = cls._hash_re.search(string)
        name = name_match and name_match.group(1).decode('utf-8')
        size = size_match and int(size_match.group(1))
        type = type_match and type_match.group(1)
        hash = hash_match and hash_match.group(1)
        return cls(name, type, size, hash)

    @classmethod
    def for_file(cls, path, type=None, hash=None):
        name = unicode(path)
        fd = open(name, 'rb')
        size = os.fstat(fd.fileno()).st_size
        if type is None:
            mime_type, encoding = mimetypes.guess_type(name)
            if encoding is not None:
                type = 'application/x-%s' % encoding
            elif mime_type is not None:
                type = mime_type
            else:
                type = 'application/octet-stream'
        return cls(name, type, size, hash, fd)

    @property
    def sdp_repr(self):
        items = [('name', self.name and '"%s"' % os.path.basename(self.name).encode('utf-8')), ('type', self.type), ('size', self.size), ('hash', self.hash)]
        return ' '.join('%s:%s' % (name, value) for name, value in items if value is not None)


class UniqueFilenameGenerator(object):
    @classmethod
    def generate(cls, name):
        yield name
        prefix, extension = os.path.splitext(name)
        for x in count(1):
            yield "%s-%d%s" % (prefix, x, extension)


class FileMetadataEntry(object):
    def __init__(self, hash, filename, partial_hash=None):
        self.hash = hash
        self.filename = filename
        self.mtime = os.path.getmtime(self.filename)
        self.partial_hash = partial_hash

    @classmethod
    def from_selector(cls, file_selector):
        return cls(file_selector.hash.lower(), file_selector.name)


class FileTransfersMetadata(object):
    __filename__ = 'transfer_metadata'
    __lifetime__ = 60*60*24*7

    def __init__(self):
        self.data = {}
        self.lock = Lock()
        self.loaded = False
        self.directory = None

    def _load(self):
        if self.loaded:
            return
        from sipsimple.application import SIPApplication
        if ISIPSimpleApplicationDataStorage.providedBy(SIPApplication.storage):
            self.directory = SIPApplication.storage.directory
        if self.directory is not None:
            try:
                with open(os.path.join(self.directory, self.__filename__), 'rb') as f:
                    data = pickle.loads(f.read())
            except Exception:
                data = {}
            now = time.time()
            for hash, entry in data.items():
                try:
                    mtime = os.path.getmtime(entry.filename)
                except OSError:
                    data.pop(hash)
                else:
                    if mtime != entry.mtime or now - mtime > self.__lifetime__:
                        data.pop(hash)
            self.data.update(data)
        self.loaded = True

    @run_in_thread('file-io')
    def _save(self, data):
        if self.directory is not None:
            with open(os.path.join(self.directory, self.__filename__), 'wb') as f:
                f.write(data)

    def __enter__(self):
        self.lock.acquire()
        self._load()
        return self.data

    def __exit__(self, exc_type, exc_val, exc_tb):
        if None is exc_type is exc_val is exc_tb:
            self._save(pickle.dumps(self.data))
        self.lock.release()


class FileTransferHandler(object):
    __metaclass__ = ABCMeta

    implements(IObserver)

    threadpool = ThreadPool(name='FileTransfers', min_threads=0, max_threads=100)
    threadpool.start()

    def __init__(self):
        self.stream = None
        self.session = None
        self._started = False
        self._session_started = False
        self._initialize_done = False
        self._initialize_successful = False

    def initialize(self, stream, session):
        self.stream = stream
        self.session = session
        notification_center = NotificationCenter()
        notification_center.add_observer(self, sender=stream)
        notification_center.add_observer(self, sender=session)
        notification_center.add_observer(self, sender=self)

    @property
    def filename(self):
        return self.stream.file_selector.name if self.stream is not None else None

    @abstractmethod
    def start(self):
        raise NotImplementedError

    @abstractmethod
    def end(self):
        raise NotImplementedError

    @abstractmethod
    def process_chunk(self, chunk):
        raise NotImplementedError

    def __terminate(self):
        notification_center = NotificationCenter()
        notification_center.remove_observer(self, sender=self.stream)
        notification_center.remove_observer(self, sender=self.session)
        notification_center.remove_observer(self, sender=self)
        try:
            self.stream.file_selector.fd.close()
        except AttributeError:  # when self.stream.file_selector.fd is None
            pass
        except IOError:         # we can get this if we try to close while another thread is reading from it
            pass
        self.stream = None
        self.session = None

    @run_in_twisted_thread
    def handle_notification(self, notification):
        handler = getattr(self, '_NH_%s' % notification.name, None)
        if handler is not None:
            handler(notification)

    def _NH_MediaStreamDidNotInitialize(self, notification):
        if not self._initialize_done:
            self.end()
        self.__terminate()

    def _NH_MediaStreamDidStart(self, notification):
        self._started = True
        self.start()

    def _NH_MediaStreamWillEnd(self, notification):
        if self._started:
            self.end()
        elif self._session_started:
            notification.center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='Refused'))

    def _NH_SIPSessionWillStart(self, notification):
        self._session_started = True

    def _NH_SIPSessionDidFail(self, notification):
        if not self._session_started and self._initialize_successful:
            if notification.data.code == 487:
                reason = 'Cancelled'
            else:
                reason = notification.data.reason or 'Failed'
            notification.center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason=reason))

    def _NH_FileTransferHandlerDidInitialize(self, notification):
        self._initialize_done = True
        self._initialize_successful = True

    def _NH_FileTransferHandlerDidNotInitialize(self, notification):
        self._initialize_done = True
        self._initialize_successful = False

    def _NH_FileTransferHandlerDidEnd(self, notification):
        self.__terminate()


class EndTransfer: __metaclass__ = MarkerType


class IncomingFileTransferHandler(FileTransferHandler):
    metadata = FileTransfersMetadata()

    def __init__(self):
        super(IncomingFileTransferHandler, self).__init__()
        self.hash = sha1()
        self.queue = Queue()
        self.offset = 0
        self.received_chunks = 0

    def _get_save_directory(self):
        return self.__dict__.get('save_directory')

    def _set_save_directory(self, value):
        if self.stream is not None:
            raise AttributeError('cannot set save_directory, transfer is in progress')
        self.__dict__['save_directory'] = value

    save_directory = property(_get_save_directory, _set_save_directory)
    del _get_save_directory, _set_save_directory

    def initialize(self, stream, session):
        super(IncomingFileTransferHandler, self).initialize(stream, session)
        try:
            directory = self.save_directory or SIPSimpleSettings().file_transfer.directory.normalized
            makedirs(directory)
            with self.metadata as metadata:
                try:
                    prev_file = metadata.pop(stream.file_selector.hash.lower())
                    mtime = os.path.getmtime(prev_file.filename)
                    if mtime != prev_file.mtime:
                        raise ValueError('file was modified')
                    filename = os.path.join(directory, os.path.basename(stream.file_selector.name))
                    try:
                        os.link(prev_file.filename, filename)
                    except (AttributeError, OSError):
                        stream.file_selector.name = prev_file.filename
                    else:
                        stream.file_selector.name = filename
                        unlink(prev_file.filename)
                    stream.file_selector.fd = openfile(stream.file_selector.name, 'ab')  # open doesn't seek to END in append mode on win32 until first write, but openfile does
                    self.offset = stream.file_selector.fd.tell()
                    self.hash = prev_file.partial_hash
                except (KeyError, EnvironmentError, ValueError):
                    for name in UniqueFilenameGenerator.generate(os.path.join(directory, os.path.basename(stream.file_selector.name))):
                        try:
                            stream.file_selector.fd = openfile(name, 'xb')
                        except FileExistsError:
                            continue
                        else:
                            stream.file_selector.name = name
                            break
        except Exception, e:
            NotificationCenter().post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason=str(e)))
        else:
            NotificationCenter().post_notification('FileTransferHandlerDidInitialize', sender=self)

    def end(self):
        self.queue.put(EndTransfer)

    def process_chunk(self, chunk):
        if chunk.method == 'SEND':
            if not self.received_chunks and chunk.byte_range[0] == 1:
                self.stream.file_selector.fd.truncate(0)
                self.stream.file_selector.fd.seek(0)
                self.hash = sha1()
                self.offset = 0
            self.received_chunks += 1
            self.queue.put(chunk)
        elif chunk.method == 'FILE_OFFSET':
            if self.received_chunks > 0:
                response = make_response(chunk, 413, 'Unwanted message')
            else:
                offset = self.stream.file_selector.fd.tell()
                response = make_response(chunk, 200, 'OK')
                response.headers['Offset'] = MSRPHeader('Offset', offset)
            self.stream.msrp_session.send_chunk(response)

    @run_in_threadpool(FileTransferHandler.threadpool)
    def start(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('FileTransferHandlerDidStart', sender=self)
        file_selector = self.stream.file_selector
        fd = file_selector.fd

        while True:
            chunk = self.queue.get()
            if chunk is EndTransfer:
                break
            try:
                fd.write(chunk.data)
            except EnvironmentError, e:
                fd.close()
                notification_center.post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=str(e)))
                notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason=str(e)))
                return
            self.hash.update(chunk.data)
            self.offset += chunk.size
            transferred_bytes = chunk.byte_range[0] + chunk.size - 1
            total_bytes = file_selector.size = chunk.byte_range[2]
            notification_center.post_notification('FileTransferHandlerProgress', sender=self, data=NotificationData(transferred_bytes=transferred_bytes, total_bytes=total_bytes))
            if transferred_bytes == total_bytes:
                break

        fd.close()

        # Transfer is finished

        if self.offset != self.stream.file_selector.size:
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='Incomplete file'))
            return
        if self.hash != self.stream.file_selector.hash:
            unlink(self.filename)  # something got corrupted, better delete the file
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='File hash mismatch'))
            return

        notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=False, reason=None))

    def _NH_MediaStreamDidNotInitialize(self, notification):
        if self.stream.file_selector.fd is not None:
            position = self.stream.file_selector.fd.tell()
            self.stream.file_selector.fd.close()
            if position == 0:
                unlink(self.stream.file_selector.name)
        super(IncomingFileTransferHandler, self)._NH_MediaStreamDidNotInitialize(notification)

    def _NH_FileTransferHandlerDidEnd(self, notification):
        if notification.data.error and self.stream.file_selector.hash is not None:
            if os.path.getsize(self.stream.file_selector.name) == 0:
                unlink(self.stream.file_selector.name)
            else:
                with self.metadata as metadata:
                    entry = FileMetadataEntry.from_selector(self.stream.file_selector)
                    entry.partial_hash = self.hash
                    metadata[entry.hash] = entry
        super(IncomingFileTransferHandler, self)._NH_FileTransferHandlerDidEnd(notification)


class OutgoingFileTransferHandler(FileTransferHandler):
    file_part_size = 64*1024

    def __init__(self):
        super(OutgoingFileTransferHandler, self).__init__()
        self.stop_event = Event()
        self.finished_event = Event()
        self.file_offset_event = Event()
        self.message_id = '%x' % random.getrandbits(64)
        self.offset = 0
        self.headers = {}

    def initialize(self, stream, session):
        super(OutgoingFileTransferHandler, self).initialize(stream, session)
        if stream.file_selector.fd is None:
            NotificationCenter().post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason='file descriptor not specified'))
            return
        if stream.file_selector.size == 0:
            NotificationCenter().post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason='file is empty'))
            return

        self.headers[ContentTypeHeader.name] = ContentTypeHeader(stream.file_selector.type)
        self.headers[SuccessReportHeader.name] = SuccessReportHeader('yes')
        self.headers[FailureReportHeader.name] = FailureReportHeader('yes')

        if stream.file_selector.hash is None:
            self._calculate_file_hash()
        else:
            NotificationCenter().post_notification('FileTransferHandlerDidInitialize', sender=self)

    @run_in_threadpool(FileTransferHandler.threadpool)
    def _calculate_file_hash(self):
        file_hash = hashlib.sha1()
        processed = 0

        notification_center = NotificationCenter()
        notification_center.post_notification('FileTransferHandlerHashProgress', sender=self, data=NotificationData(processed=0, total=self.stream.file_selector.size))

        file_selector = self.stream.file_selector
        fd = file_selector.fd
        while not self.stop_event.is_set():
            try:
                content = fd.read(self.file_part_size)
            except EnvironmentError, e:
                fd.close()
                notification_center.post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason=str(e)))
                return
            if not content:
                file_selector.hash = file_hash
                notification_center.post_notification('FileTransferHandlerDidInitialize', sender=self)
                break
            file_hash.update(content)
            processed += len(content)
            notification_center.post_notification('FileTransferHandlerHashProgress', sender=self, data=NotificationData(processed=processed, total=file_selector.size))
        else:
            fd.close()
            notification_center.post_notification('FileTransferHandlerDidNotInitialize', sender=self, data=NotificationData(reason='Interrupted transfer'))

    def end(self):
        self.stop_event.set()
        self.file_offset_event.set()    # in case we are busy waiting on it

    @run_in_threadpool(FileTransferHandler.threadpool)
    def start(self):
        notification_center = NotificationCenter()
        notification_center.post_notification('FileTransferHandlerDidStart', sender=self)

        if self.stream.file_offset_supported:
            self._send_file_offset_chunk()
            self.file_offset_event.wait()

        finished = False
        failure_reason = None
        fd = self.stream.file_selector.fd
        fd.seek(self.offset)

        try:
            while not self.stop_event.is_set():
                try:
                    data = fd.read(self.file_part_size)
                except EnvironmentError, e:
                    failure_reason = str(e)
                    break
                if not data:
                    finished = True
                    break
                self._send_chunk(data)
        finally:
            fd.close()

        if not finished:
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason=failure_reason or 'Interrupted transfer'))
            return

        # Wait until the stream ends or we get all reports
        self.stop_event.wait()
        if self.finished_event.is_set():
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=False, reason=None))
        else:
            notification_center.post_notification('FileTransferHandlerDidEnd', sender=self, data=NotificationData(error=True, reason='Incomplete transfer'))

    def _on_transaction_response(self, response):
        if self.stop_event.is_set():
            return
        if response.code != 200:
            NotificationCenter().post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=response.comment))
            self.end()

    @run_in_twisted_thread
    def _send_chunk(self, data):
        if self.stop_event.is_set():
            return
        data_len = len(data)
        chunk = self.stream.msrp.make_send_request(message_id=self.message_id,
                                                   data=data,
                                                   start=self.offset+1,
                                                   end=self.offset+data_len,
                                                   length=self.stream.file_selector.size)
        chunk.headers.update(self.headers)
        try:
            self.stream.msrp_session.send_chunk(chunk, response_cb=self._on_transaction_response)
        except Exception, e:
            NotificationCenter().post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=str(e)))
        else:
            self.offset += data_len

    @run_in_twisted_thread
    def _send_file_offset_chunk(self):
        def response_cb(response):
            if not self.stop_event.is_set() and response.code == 200:
                try:
                    offset = int(response.headers['Offset'].decoded)
                except (KeyError, ValueError):
                    offset = 0
                self.offset = offset
            self.file_offset_event.set()

        if self.stop_event.is_set():
            self.file_offset_event.set()
            return

        chunk = self.stream.msrp.make_request('FILE_OFFSET')
        try:
            self.stream.msrp_session.send_chunk(chunk, response_cb=response_cb)
        except Exception, e:
            NotificationCenter().post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=str(e)))

    def process_chunk(self, chunk):
        # here we process the REPORT chunks
        notification_center = NotificationCenter()
        if chunk.status.code == 200:
            transferred_bytes = chunk.byte_range[1]
            total_bytes = chunk.byte_range[2]
            notification_center.post_notification('FileTransferHandlerProgress', sender=self, data=NotificationData(transferred_bytes=transferred_bytes, total_bytes=total_bytes))
            if transferred_bytes == total_bytes:
                self.finished_event.set()
                self.end()
        else:
            notification_center.post_notification('FileTransferHandlerError', sender=self, data=NotificationData(error=chunk.status.comment))
            self.end()


class FileTransferMSRPSession(MSRPSession):
    def _handle_incoming_FILE_OFFSET(self, chunk):
        self._on_incoming_cb(chunk)


class FileTransferStream(MSRPStreamBase):
    type = 'file-transfer'
    priority = 10
    msrp_session_class = FileTransferMSRPSession

    media_type = 'message'
    accept_types = ['*']
    accept_wrapped_types = None

    IncomingTransferHandler = IncomingFileTransferHandler
    OutgoingTransferHandler = OutgoingFileTransferHandler

    def __init__(self, file_selector, direction, transfer_id=RandomID):
        if direction not in ('sendonly', 'recvonly'):
            raise ValueError("direction must be one of 'sendonly' or 'recvonly'")
        super(FileTransferStream, self).__init__(direction=direction)
        self.file_selector = file_selector
        self.transfer_id = transfer_id if transfer_id is not RandomID else str(uuid.uuid4())
        if direction == 'sendonly':
            self.handler = self.OutgoingTransferHandler()
        else:
            self.handler = self.IncomingTransferHandler()

    @classmethod
    def new_from_sdp(cls, session, remote_sdp, stream_index):
        remote_stream = remote_sdp.media[stream_index]
        if remote_stream.media != 'message' or 'file-selector' not in remote_stream.attributes:
            raise UnknownStreamError
        expected_transport = 'TCP/TLS/MSRP' if session.account.msrp.transport == 'tls' else 'TCP/MSRP'
        if remote_stream.transport != expected_transport:
            raise InvalidStreamError("expected %s transport in file transfer stream, got %s" % (expected_transport, remote_stream.transport))
        if remote_stream.formats != ['*']:
            raise InvalidStreamError("wrong format list specified")
        try:
            file_selector = FileSelector.parse(remote_stream.attributes.getfirst('file-selector'))
        except Exception as e:
            raise InvalidStreamError("error parsing file-selector: {}".format(e))
        transfer_id = remote_stream.attributes.getfirst('file-transfer-id', None)
        if remote_stream.direction == 'sendonly':
            stream = cls(file_selector, 'recvonly', transfer_id)
        elif remote_stream.direction == 'recvonly':
            stream = cls(file_selector, 'sendonly', transfer_id)
        else:
            raise InvalidStreamError("wrong stream direction specified")
        stream.remote_role = remote_stream.attributes.getfirst('setup', 'active')
        return stream

    def initialize(self, session, direction):
        self._initialize_args = session, direction
        NotificationCenter().add_observer(self, sender=self.handler)
        self.handler.initialize(self, session)

    def _create_local_media(self, uri_path):
        local_media = super(FileTransferStream, self)._create_local_media(uri_path)
        local_media.attributes.append(SDPAttribute('file-selector', self.file_selector.sdp_repr))
        local_media.attributes.append(SDPAttribute('x-file-offset', ''))
        if self.transfer_id is not None:
            local_media.attributes.append(SDPAttribute('file-transfer-id', self.transfer_id))
        return local_media

    @property
    def file_offset_supported(self):
        try:
            return 'x-file-offset' in self.remote_media.attributes
        except AttributeError:
            return False

    @run_in_twisted_thread
    def _NH_FileTransferHandlerDidInitialize(self, notification):
        session, direction = self._initialize_args
        del self._initialize_args
        if not self._done:
            super(FileTransferStream, self).initialize(session, direction)

    @run_in_twisted_thread
    def _NH_FileTransferHandlerDidNotInitialize(self, notification):
        del self._initialize_args
        if not self._done:
            notification.center.post_notification('MediaStreamDidNotInitialize', sender=self, data=notification.data)

    @run_in_twisted_thread
    def _NH_FileTransferHandlerError(self, notification):
        self._failure_reason = notification.data.error
        notification.center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='transferring', reason=self._failure_reason))

    def _NH_MediaStreamDidNotInitialize(self, notification):
        notification.center.remove_observer(self, sender=self.handler)

    def _NH_MediaStreamWillEnd(self, notification):
        notification.center.remove_observer(self, sender=self.handler)

    def _handle_REPORT(self, chunk):
        # in theory, REPORT can come with Byte-Range which would limit the scope of the REPORT to the part of the message.
        self.handler.process_chunk(chunk)

    def _handle_SEND(self, chunk):
        notification_center = NotificationCenter()
        if chunk.size == 0:
            # keep-alive
            self.msrp_session.send_report(chunk, 200, 'OK')
            return
        if self.direction=='sendonly':
            self.msrp_session.send_report(chunk, 413, 'Unwanted Message')
            return
        if chunk.content_type.lower() == 'message/cpim':
            # In order to properly support the CPIM wrapper, msrplib needs to be refactored. -Luci
            self.msrp_session.send_report(chunk, 415, 'Invalid Content-Type')
            self._failure_reason = "CPIM wrapper is not supported"
            notification_center.post_notification('MediaStreamDidFail', sender=self, data=NotificationData(context='reading', reason=self._failure_reason))
            return
        try:
            self.msrp_session.send_report(chunk, 200, 'OK')
        except Exception:
            pass    # Best effort approach: even if we couldn't send the REPORT keep writing the chunks, we might have them all -Saul
        self.handler.process_chunk(chunk)

    def _handle_FILE_OFFSET(self, chunk):
        if self.direction != 'recvonly':
            response = make_response(chunk, 413, 'Unwanted message')
            self.msrp_session.send_chunk(response)
            return
        self.handler.process_chunk(chunk)

