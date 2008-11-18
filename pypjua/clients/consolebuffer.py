from __future__ import with_statement
import sys
import termios
import tty
import time
from contextlib import contextmanager
from twisted.internet.error import ConnectionDone
from twisted.internet import stdio
from pypjua.clients.console import Console, ServerProtocol, CTRL_C, CTRL_D, CTRL_BACKSLASH, terminal_initialize
from eventlet.channel import channel as Channel
from eventlet.api import spawn, sleep, GreenletExit
from eventlet.green.thread import allocate_lock

class ChannelProxy:

    def __init__(self):
        self.source = Channel()
        self.output = Channel()
        self.gthread = spawn(self._run)
        self.lock = allocate_lock()
        self.ex = None
        self.throw_away = False

    def receive(self):
        return self.output.receive()

    def send(self, x):
        return self.source.send(x)

    def send_exception(self, ex):
        self.ex = ex
        return self.source.send_exception(ex)

    def _run(self):
        while True:
            try:
                res = self.source.receive()
            except BaseException, ex:
                if not self.throw_away:
                    spawn(self.output.send_exception, ex)
            else:
                if not self.throw_away:
                    spawn(self.output.send, res)

    def switch_output(self, new_output=None):
        old_output = self.output
        if new_output is None:
            new_output = Channel()
        self.output = new_output
        if self.ex is not None:
            spawn(self.output.send_exception, self.ex)
        return old_output

    @contextmanager
    def locked_output(self, new_output=None):
        with self.lock:
            old = self.switch_output(new_output)
            try:
                yield
            finally:
                self.switch_output(old)

class _Console(Console):

    channel = ChannelProxy()
    always_enabled = [CTRL_C, CTRL_D, CTRL_BACKSLASH]
    recv_char = False
    last_keypress_time = time.time()

    def keystrokeReceived(self, keyID, modifier):
        self.last_keypress_time = time.time()
        if keyID in self.always_enabled or not self.recv_char:
            Console.keystrokeReceived(self, keyID, modifier)
        else:
            spawn(self.channel.send, ('key', (keyID, modifier)))

    def lineReceived(self, line):
        Console.lineReceived(self, line)
        spawn(self.channel.send, ('line', line))

    def connectionLost(self, reason):
        spawn(self.channel.send_exception, reason.value)

    @contextmanager
    def new_prompt(self, new_ps):
        self.terminal.eraseLine()
        self.cursorToBOL()
        lineBuffer = self.lineBuffer[:]
        lineBufferIndex = self.lineBufferIndex
        ps = self.ps[0]
        self.lineBuffer = []
        self.lineBufferIndex = 0
        try:
            self.set_ps(new_ps)
            self.drawInputLine()
            yield
        finally:
            if self._needsNewline():
                self.terminal.nextLine()
            self.lineBuffer = lineBuffer
            self.lineBufferIndex = lineBufferIndex
            self.set_ps(ps)
            self.drawInputLine()

    def barrier(self, seconds=1):
        since_last_keypress = time.time()-self.last_keypress_time
        if since_last_keypress<seconds:
            self.channel.throw_away = True
            try:
                sleep(seconds-since_last_keypress)
            finally:
                self.channel.throw_away = False

    def cursorToBOL(self):
        pos = len(self.lineBuffer) + len(self.ps[self.pn])
        if pos>0:
            self.terminal.cursorBackward(pos)

    def clearInputLine(self):
        self.terminal.eraseLine()
        self.cursorToBOL()
        self.lineBuffer = []
        self.drawInputLine()

class ConsoleBuffer:

    last_header = None

    def __init__(self):
        self.writecount = 0

    @property
    def terminalProtocol(self):
        return self.protocol.terminalProtocol

    def recv(self):
        return self.channel.receive()

    @contextmanager
    def new_prompt(self, prompt):
        if self.terminalProtocol is None:
            raise ConnectionDone
        if self.terminalProtocol.lineBuffer:
            self.terminalProtocol.terminal.nextLine()
        with self.terminalProtocol.new_prompt(prompt):
            yield

    def recv_char(self, allowed=None):
        if self.terminalProtocol is None:
            raise ConnectionDone
        self.terminalProtocol.clearInputLine()
        self.terminalProtocol.recv_char = True
        # because it's like a modal dialog box that steals focus, wait for at least 1 second
        # since the last keypress to avoid accidental input
        self.terminalProtocol.barrier()
        try:
            while True:
                type, value = self.channel.receive()
                if type == 'key':
                    key = value[0]
                    if allowed is None or key in allowed:
                        self.terminalProtocol.lineBuffer.append(str(key))
                        self.terminalProtocol.terminal.write(str(key))
                        return type, value
                else:
                    return type, value
        finally:
            if self.terminalProtocol is not None:
                self.terminalProtocol.recv_char = False

    def ask_question(self, question, allowed, help=None, help_keys='hH?'):
        with self.channel.locked_output():
            with self.new_prompt(question):
                if help is not None and '?' not in allowed:
                    allowed += help_keys
                while True:
                    try:
                        type, value = self.recv_char(allowed)
                        if type=='key':
                            value = value[0]
                            if help is not None and value in help_keys:
                                self.write(help)
                            else:
                                return value
                        else:
                            break
                    except ConnectionDone:
                        raise GreenletExit

    def write(self, msg):
        self.writecount += 1
        if self.terminalProtocol:
            self.terminalProtocol.addOutput(msg, async=True)
            sleep(0.01) # this flushes stdout
        else:
            if not msg.endswith('\n'):
                msg += '\n'
            msg = msg.replace('\n', '\r\n')
            __original_sys_stderr__.write(msg)

    def set_ps(self, ps, draw=True):
        if self.terminalProtocol:
            self.terminalProtocol.set_ps(ps, draw)

    def __iter__(self):
        return self

    def next(self):
        try:
            return self.recv()
        except ConnectionDone:
            raise StopIteration

class TrafficLogger:

    def __init__(self, console, is_enabled_func=lambda: True):
        self.console = console
        self.is_enabled = is_enabled_func
        self.last_header = None
        self.last_writecount = None

    def write_traffic(self, msg, header, reset_header=False):
        if not self.is_enabled():
            return
        if header is not None:
            if header != self.last_header or self.last_writecount != self.console.writecount:
                self.console.write('\n')
                self.console.write(header)
        self.console.write(msg)
        self.last_writecount = self.console.writecount
        if reset_header:
            self.last_header = None
        else:
            self.last_header = header

def get_console():
    buffer = ConsoleBuffer()
    buffer.channel = _Console.channel
    p = ServerProtocol(_Console)
    stdio.StandardIO(p)
    buffer.protocol = p
    return buffer

__original_sys_stderr__ = sys.stderr
__original_sys_stdout__ = sys.stdout

class _WriteProxy(object):

    def __init__(self, original, console):
        self.original = original
        self.console = console
        self.state = None

    def __getattr__(self, item):
        return getattr(self.original, item)

    def write(self, data):
        if data=='\n' and self.state=='after write':
            self.state = 'skipped'
            return
        else:
            self.state = 'after write'
            return self.console.write(data)

def hook_std_output(console):
    sys.stderr = _WriteProxy(__original_sys_stderr__, console)
    sys.stdout = _WriteProxy(__original_sys_stdout__, console)

def restore_std_output():
    sys.stdout = __original_sys_stdout__
    sys.stderr = __original_sys_stderr__

@contextmanager
def setup_console():
    fd = sys.__stdin__.fileno()
    oldSettings = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    try:
        console = get_console()
        hook_std_output(console)
        try:
            yield console
        finally:
            restore_std_output()
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, oldSettings)
        terminal_initialize(fd)


def main():
    from twisted.internet import reactor
    from eventlet.api import sleep

    def write_traffic():
        t = TrafficLogger(console)
        t.write_traffic('data1', '10.1.1.1:222 -> 10.2.2.2:111')
        t.write_traffic('data2', '10.1.1.1:222 -> 10.2.2.2:111')
        sleep(2)
        t.write_traffic('data3', '10.1.1.1:222 -> 10.2.2.2:111')
        t.write_traffic('data4', '10.1.1.1:222 -> 10.2.2.2:111')

    def incoming():
        import random
        from_ = random.randint(1, 10**10)
        q = 'Accept incoming session from %s@example.com? y/n/h ' % from_
        response = console.ask_question(q, 'ynYN', help='y - yes\nn - no')
        if response is not None:
            console.write('You said %s' % response)

    with setup_console() as console:
        for type, value in console:
            if (type, value) != ('line', ''):
                console.write('.........................[%s %r]\n' % (type, value))
            if type=='line':
                if value=='1/0':
                    1/0 # sync stacktrace
                elif value=='sleep':
                    sleep(3)
                elif value=='yesno':
                    res = console.ask_question('Yes or no? [yn]', 'ynYN\n')
                    console.write('You typed %r' % (res, ))
                elif value=='in':
                    reactor.callLater(2, spawn, incoming)
                elif value=='a':
                    reactor.callLater(1, lambda : sys.stdout.write('Async output\n-------\n'))
                elif value=='ax':
                    reactor.callLater(1, lambda : 2/0) # async stacktrace
                elif value=='at':
                    reactor.callLater(1, spawn, write_traffic)
                elif value.startswith('ps '):
                    reactor.callLater(1, console.set_ps, value[3:])
                elif value=='exit':
                    sys.exit('system exit')
    print 'clean exit'

if __name__ == '__main__':
    main()
