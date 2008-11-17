import os
import tty
import sys
import termios
from twisted.internet import reactor, stdio
from twisted.conch.insults import insults
from twisted.conch import recvline

CTRL_C = '\x03'
CTRL_D = '\x04'
CTRL_BACKSLASH = '\x1c'
CTRL_L = '\x0c'

SETTERM_INITIALIZE = '\x1b[!p\x1b[?3;4l\x1b[4l\x1b>'

class Console(recvline.HistoricRecvLine):
    #Copied from twisted.conch.manhole.Manhole but removed interpreter-related stuff
    ps = ['>>> ', '... ']

    def initializeScreen(self):
        self.terminal.write(self.ps[self.pn])
        self.setInsertMode()

    def connectionMade(self):
        super(Console, self).connectionMade()
        self.keyHandlers[CTRL_C] = self.handle_INT
        self.keyHandlers[CTRL_D] = self.handle_EOF
        self.keyHandlers[CTRL_L] = self.handle_FF
        self.keyHandlers[CTRL_BACKSLASH] = self.handle_QUIT

    def handle_INT(self):
        if self.lineBuffer:
            self.pn = 0
            self.lineBuffer = []
            self.lineBufferIndex = 0
            self.terminal.nextLine()
            self.terminal.write(self.ps[self.pn])
        else:
            self.terminal.loseConnection()

    def handle_EOF(self):
        self.terminal.loseConnection()
        #if self.lineBuffer:
            #self.terminal.write('\a')

    def handle_FF(self):
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()

    def handle_QUIT(self):
        self.terminal.loseConnection()

    def _needsNewline(self):
        w = self.terminal.lastWrite
        return not w.endswith('\n') and not w.endswith('\x1bE')

    def addOutput(self, bytes, async=False):
        if async:
            self.terminal.eraseLine()
            self.terminal.cursorBackward(len(self.lineBuffer) + len(self.ps[self.pn]))

        self.terminal.write(bytes)

        if async:
            if self._needsNewline():
                self.terminal.nextLine()

            self.terminal.write(self.ps[self.pn])

            if self.lineBuffer:
                oldBuffer = self.lineBuffer
                self.lineBuffer = []
                self.lineBufferIndex = 0

                self._deliverBuffer(oldBuffer)

    def lineReceived(self, line):
        #more = self.interpreter.push(line)
        self.pn = 0 # bool(more)
        if self._needsNewline():
            self.terminal.nextLine()
        self.terminal.write(self.ps[self.pn])

    def set_ps(self, ps, draw=False):
        self.ps[0] = ps
        if draw:
            self.terminal.eraseLine()
            self.terminal.cursorBackward(len(self.lineBuffer) + len(self.ps[self.pn]))
            self.drawInputLine()

class ServerProtocol(insults.ServerProtocol):

    def reset(self):
        self.cursorPos.x = self.cursorPos.y = 0
        try:
            del self._savedCursorPos
        except AttributeError:
            pass
        self.write('\n')

def terminal_initialize(fd):
    # the same effect as calling setterm -initialize
    # QQQ is the sequence is valid for all terminals?
    os.write(fd, '\r' + SETTERM_INITIALIZE)

if __name__ == '__main__':

    class MyConsole(Console):
        def handle_EOF(self):
            self.terminal.loseConnection()
            reactor.callLater(0, reactor.stop)

    #log.startLogging(file('child.log', 'w'))
    fd = sys.__stdin__.fileno()
    oldSettings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        p = ServerProtocol(MyConsole)
        stdio.StandardIO(p)
        reactor.run()
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, oldSettings)
        terminal_initialize(fd)

