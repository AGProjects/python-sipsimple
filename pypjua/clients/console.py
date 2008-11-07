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

class Console(recvline.HistoricRecvLine):
    #Copied from twisted.conch.manhole.Manhole but removed interpreter-related stuff

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
        self.pn = 0
        self.lineBuffer = []
        self.lineBufferIndex = 0

        self.terminal.nextLine()
        self.terminal.write("KeyboardInterrupt")
        self.terminal.nextLine()
        self.terminal.write(self.ps[self.pn])

    def handle_EOF(self):
        #print 'EOF', `self.lineBuffer`
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

class ServerProtocol(insults.ServerProtocol):

    def reset(self):
        self.cursorPos.x = self.cursorPos.y = 0
        try:
            del self._savedCursorPos
        except AttributeError:
            pass
        self.write('\n')


if __name__ == '__main__':
    #log.startLogging(file('child.log', 'w'))
    fd = sys.__stdin__.fileno()
    oldSettings = termios.tcgetattr(fd)
    tty.setraw(fd)
    try:
        p = ServerProtocol(Console)
        stdio.StandardIO(p)
        reactor.run()
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, oldSettings)
        #os.write(fd, "\r\x1bc\r")
        os.write(fd, '\r')
        os.system('setterm -initialize 2> /dev/null')

