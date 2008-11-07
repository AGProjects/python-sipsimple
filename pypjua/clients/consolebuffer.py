import sys
import os
import termios
import tty
from twisted.internet.error import ConnectionDone
from twisted.internet import stdio
from pypjua.clients.console import Console, ServerProtocol, CTRL_C, CTRL_D, CTRL_BACKSLASH
from eventlet.channel import channel as Channel
from eventlet.api import spawn

class _Console(Console):

    channel = Channel()
    send_keys = [CTRL_C, CTRL_D, CTRL_BACKSLASH]

    def keystrokeReceived(self, keyID, modifier):
        Console.keystrokeReceived(self, keyID, modifier)
        if keyID in self.send_keys:
            spawn(self.channel.send, ('key', keyID))

    def lineReceived(self, line):
        Console.lineReceived(self, line)
        spawn(self.channel.send, ('line', line))

    def connectionLost(self, reason):
        spawn(self.channel.send_exception, reason.value)

class ConsoleBuffer:

    def recv(self):
        res = self.channel.receive()
        return res

    def write(self, msg):
        if self.protocol.terminalProtocol:
            self.protocol.terminalProtocol.addOutput(msg, async=True)
        else:
            __original_sys_stderr__.write('\r%s\n' % msg)

    def write_(self, msg):
        if msg.endswith('\n'):
            msg = msg[:-1]
        return self.write(msg)

    def __iter__(self):
        return self

    def next(self):
        try:
            return self.recv()
        except ConnectionDone:
            raise StopIteration

def get_console():
    buffer = ConsoleBuffer()
    buffer.channel = _Console.channel
    p = ServerProtocol(_Console)
    stdio.StandardIO(p)
    buffer.protocol = p
    return buffer

__original_sys_stderr__ = sys.stderr
__original_sys_stdout__ = sys.stdout

class FileProxy(object):

    def __init__(self, original, new_write):
        self.original = original
        self.write = new_write

    def __getattr__(self, item):
        return getattr(self.original, item)

def hook_std_output(console):
    sys.stdout = FileProxy(sys.stdout, console.write_)
    sys.stderr = FileProxy(sys.stderr, console.write_)

def restore_std_output():
    sys.stdout = __original_sys_stdout__
    sys.stderr = __original_sys_stderr__

if __name__ == '__main__':
    from twisted.internet import reactor
    reactor.callLater(2, lambda : sys.stdout.write('Async output\n-------\n'))
    reactor.callLater(4, lambda : 1/0)
    fd = sys.__stdin__.fileno()
    oldSettings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        console = get_console()
        hook_std_output(console)
        for type, value in console:
            console.write('%s %r' % (type, value))
    finally:
        restore_std_output()
        termios.tcsetattr(fd, termios.TCSANOW, oldSettings)
        os.write(fd, "\r")
        os.system('setterm -initialize')

