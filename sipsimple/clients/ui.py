# Copyright (C) 2008-2009 AG Projects. See LICENSE for details.
#

from __future__ import with_statement

import atexit
import fcntl
import os
import re
import select
import signal
import struct
import sys
import termios

from application.python.decorator import decorator, preserve_signature
from application.python.util import Singleton
from application.notification import NotificationCenter, NotificationData
from collections import deque
from eventlet.green.threading import RLock
from threading import Thread


@decorator
def synchronized(func):
    @preserve_signature(func)
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return func(self, *args, **kwargs)
    return wrapper


class RichText(object):
    colors = {'default': 9,
              'red': 61,
              'darkred': 1,
              'lightgreen': 62,
              'darkgreen': 2,
              'yellow': 63,
              'darkyellow': 3,
              'cyan': 66,
              'lightblue': 6,
              'blue': 64,
              'darkblue': 4,
              'magenta': 65,
              'purple': 5,
              'white': 67,
              'lightgrey': 7,
              'darkgrey': 60,
              'black': 0}
    def __init__(self, text, foreground='default', background='default', bold=False, underline=False, blink=False):
        self.text = text
        self.foreground = foreground
        self.background = background
        self.bold = bold
        self.underline = underline
        self.blink = blink

    def __str__(self):
        return '\x1b[%sm%s\x1b[0m' % (self.mode, self.text)

    def __len__(self):
        return len(self.text)

    def __getitem__(self, index):
        return self.__class__(self.text.__getitem__(index), foreground=self.foreground, background=self.background, bold=self.bold, underline=self.underline, blink=self.blink)

    def __add__(self, other):
        return CompoundRichText([self, other])

    @property
    def mode(self):
        attributes = [str(30+self.colors.get(self.foreground)),
                      str(40+self.colors.get(self.background)),
                      '1' if self.bold else '22',
                      '4' if self.underline else '24',
                      '5' if self.blink else '25']
        return ';'.join(attributes)


class CompoundRichText(RichText):
    def __init__(self, text_list):
        self.text_list = text_list

    def __str__(self):
        return ''.join(str(text) for text in self.text_list)

    def __len__(self):
        return sum(len(text) for text in self.text_list)

    def __add__(self, other):
        if isinstance(other, CompoundRichText):
            return CompoundRichText(self.text_list+other.text_list)
        else:
            return CompoundRichText(self.text_list+[other])

    def __iadd__(self, other):
        self.text_list.append(other)
        return self


class Prompt(RichText):
    def __str__(self):
        return '\x1b[%sm%s>\x1b[0m ' % (self.mode, self.text)

    def __len__(self):
        return len(self.text)+2


class Question(RichText):
    def __init__(self, text, answers, *args, **kwargs):
        RichText.__init__(self, text, *args, **kwargs)
        self.answers = answers

    def __getitem__(self, index):
        return self.__class__(self.text.__getitem__(index), answers=self.answers, foreground=self.foreground, background=self.background, bold=self.bold, underline=self.underline, blink=self.blink)


class Input(object):
    def __init__(self):
        self.lines = []
        self.current_line_index = None
        self.cursor_position = None

    def _get_current_line(self):
        if self.current_line_index is None:
            raise RuntimeError('no current line available')
        return self.lines[self.current_line_index]
    def _set_current_line(self, value):
        if value is None:
            self.current_line_index = None
            return
        if self.current_line_index is None:
            raise RuntimeError('no current line available')
        self.lines[self.current_line_index] = value
    current_line = property(_get_current_line, _set_current_line)
    del _get_current_line, _set_current_line

    def add_line(self, text=''):
        self.lines.append(text)
        self.current_line_index = len(self.lines)-1
        self.cursor_position = len(text)

    def copy_current_line(self):
        if self.current_line_index != len(self.lines) - 1:
            self.lines[-1] = self.current_line

    def line_up(self, count=1):
        if self.current_line_index is None:
            raise RuntimeError('no current line available')
        if self.current_line_index - count < 0:
            raise KeyError('too many lines up')
        self.current_line_index -= count
        self.cursor_position = len(self.current_line)

    def line_down(self, count=1):
        if self.current_line_index is None:
            raise RuntimeError('no current line available')
        if self.current_line_index + count >= len(self.lines):
            raise KeyError('too many lines down')
        self.current_line_index += count
        self.cursor_position = len(self.current_line)


class TTYFileWrapper(object):
    def __init__(self, file):
        if not file.isatty():
            raise RuntimeError('TTYFileWrapper is supposed to wrap a tty file')
        self.file = file
        self.buffer = ''
        self.lock = RLock()
    # no-ops / simple ops
    def close(self): pass
    def fileno(self): return self.file.fileno()
    def isatty(self): return True
    def tell(self): return self.file.tell()

    @synchronized
    def write(self, str):
        if not str:
            return
        ui = UI()
        if ui.stopping:
            self.file.write(str)
        else:
            lines = re.split(r'\r\n|\r|\n', str)
            lines[0] = self.buffer + lines[0]
            self.buffer = lines[-1]
            ui.writelines(lines[:-1])

    @synchronized
    def writelines(self, sequence):
        for text in sequence:
            self.write(text)

    @synchronized
    def flush(self):
        if self.buffer:
            ui = UI()
            ui.writelines([self.buffer])
            self.buffer = ''

    def send_to_file(self):
        if self.buffer:
            self.file.write(self.buffer)


class UI(Thread):
    __metaclass__ = Singleton

    control_chars = {'\x01': 'home',
                     '\x04': 'eof',
                     '\x05': 'end',
                     '\x0a': 'newline',
                     '\x0d': 'newline',
                     '\x1b[A': 'cursorup',
                     '\x1b[B': 'cursordown',
                     '\x1b[C': 'cursorright',
                     '\x1b[D': 'cursorleft',
                     '\x1b[F': 'end',
                     '\x1b[H': 'home',
                     '\x7f': 'delete'}

    # public functions
    #

    def __init__(self):
        Thread.__init__(self, target=self._run, name='UI-Thread')
        self.setDaemon(True)

        self.__dict__['prompt'] = Prompt('')
        self.__dict__['status'] = None
        self.command_sequence = '/'
        self.application_control_char = '\x18' # ctrl-X
        self.application_control_bindings = {}
        self.display_commands = True
        self.display_text = True

        self.cursor_x = None
        self.cursor_y = None
        self.displaying_question = False
        self.input = Input()
        self.last_window_size = None
        self.lock = RLock()
        self.prompt_y = None
        self.questions = deque()
        self.stopping = False

    @synchronized
    def start(self, prompt='', command_sequence='/', control_char='\x18', control_bindings={}, display_commands=True, display_text=True):
        if self.isAlive():
            raise RuntimeError('UI already active')
        if not sys.stdin.isatty():
            raise RuntimeError('UI cannot be used on a non-TTY')
        if not sys.stdout.isatty():
            raise RuntimeError('UI cannot be used on a non-TTY')
        stdin_fd = sys.stdin.fileno()

        self.command_sequence = command_sequence
        self.application_control_char = control_char
        self.application_control_bindings = control_bindings
        self.display_commands = display_commands
        self.display_text = display_text

        # wrap sys.stdout
        sys.stdout = TTYFileWrapper(sys.stdout)
        # and possibly sys.stderr
        if sys.stderr.isatty():
            sys.stderr = TTYFileWrapper(sys.stderr)

        # change input to character-mode
        old_settings = termios.tcgetattr(stdin_fd)
        new_settings = termios.tcgetattr(stdin_fd)
        new_settings[3] &= ~termios.ECHO & ~termios.ICANON
        new_settings[6][termios.VMIN] = '\000'
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, new_settings)
        atexit.register(termios.tcsetattr, stdin_fd, termios.TCSADRAIN, old_settings)

        # find out cursor position in terminal
        self._raw_write('\x1b[6n')
        if select.select([stdin_fd], [], [], None)[0]:
            line, col = os.read(stdin_fd, 10)[2:-1].split(';')
            line = int(line)
            col = int(col)

        # scroll down the terminal until everything goes up
        self._scroll_up(line-1)
        # move the cursor to the upper left side corner
        self._raw_write('\x1b[H')
        self.cursor_x = 1
        self.cursor_y = 1
        # display the prompt
        self.prompt_y = 1
        self.input.add_line()
        self._update_prompt()
        # make sure we know when the window gets resized
        self.last_window_size = self.window_size
        signal.signal(signal.SIGWINCH, lambda signum, frame: self._window_resized())

        Thread.start(self)

        # this will trigger the update of the prompt
        self.prompt = prompt

    @synchronized
    def stop(self):
        self.stopping = True
        self.status = None
        sys.stdout.send_to_file()
        if isinstance(sys.stderr, TTYFileWrapper):
            sys.stderr.send_to_file()
        self._raw_write('\n\x1b[2K')

    def write(self, text):
        self.writelines([text])

    @synchronized
    def writelines(self, text_lines):
        if not text_lines:
            return
        # go to beginning of prompt line
        self._raw_write('\x1b[%d;%dH' % (self.prompt_y, 1))
        # erase everything beneath it
        self._raw_write('\x1b[0J')
        # start writing lines
        window_size = self.window_size
        for text in text_lines:
            # write the line
            self._raw_write('%s\n' % text)
            # calculate the number of lines the text will produce
            text_lines = (len(text)-1)/window_size.x + 1
            # calculate how much the text will automatically scroll the window
            window_height = struct.unpack('HHHH', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))[0]
            auto_scroll_amount = max(0, (self.prompt_y+text_lines-1) - (window_height-1))
            # calculate the new position of the prompt
            self.prompt_y += text_lines - auto_scroll_amount
            # we might need to scroll up to make the prompt position visible again
            scroll_up = self.prompt_y - window_height
            if scroll_up > 0:
                self.prompt_y -= scroll_up
                self._scroll_up(scroll_up)
        # redraw the prompt
        self._update_prompt()

    @synchronized
    def add_question(self, question):
        self.questions.append(question)
        if len(self.questions) == 1:
            self._update_prompt()

    @synchronized
    def remove_question(self, question):
        first_question = (question == self.questions[0])
        self.questions.remove(question)
        if not self.questions or first_question:
            self.displaying_question = False
            self._update_prompt()

    # properties
    #

    @property
    def window_size(self):
        class WindowSize(tuple):
            def __init__(ws_self, (y, x)):
                ws_self.x = x
                ws_self.y = y if self.status is None else y-1
        return WindowSize(struct.unpack('HHHH', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))[:2])

    def _get_prompt(self):
        return self.__dict__['prompt']
    @synchronized
    def _set_prompt(self, value):
        if not isinstance(value, Prompt):
            value = Prompt(value)
        self.__dict__['prompt'] = value
        self._update_prompt()
    prompt = property(_get_prompt, _set_prompt)
    del _get_prompt, _set_prompt

    def _get_status(self):
        return self.__dict__['status']
    @synchronized
    def _set_status(self, status):
        try:
            old_status = self.__dict__['status']
        except KeyError:
            self.__dict__['status'] = status
        else:
            self.__dict__['status'] = status
            if old_status is not None and status is None:
                status_y, window_length = struct.unpack('HHHH', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))[:2]
                # save current cursor position
                self._raw_write('\x1b[s')
                # goto line status_y
                self._raw_write('\x1b[%d;%dH' % (status_y, 1))
                # erase it
                self._raw_write('\x1b[2K')
                # restore the cursor position
                self._raw_write('\x1b[u')
            else:
                self._update_prompt()
    status = property(_get_status, _set_status)
    del _get_status, _set_status


    # private functions
    #

    def _run(self):
        wait_control_char = False
        while True:
            stdin_fd = sys.__stdin__.fileno()
            if select.select([stdin_fd], [], [], None)[0]:
                chars = list(os.read(stdin_fd, 4096))
                while chars:
                    if self.stopping:
                        return
                    with self.lock:
                        char = chars.pop(0)
                        if ord(char) < 32 or ord(char) == 127:
                            if char == '\x1b':
                                if chars and chars[0] == '[':
                                    char += chars.pop(0)
                                    while chars and not chars[0].isalpha():
                                        char += chars.pop(0)
                                    if chars:
                                        char += chars.pop(0)
                            if self.questions:
                                pass
                            elif char == self.application_control_char:
                                wait_control_char = not wait_control_char
                            elif not self.questions:
                                wait_control_char = False
                                handler = getattr(self, '_CH_%s' % self.control_chars.get(char, 'default'))
                                handler(char)
                        elif wait_control_char:
                            wait_control_char = False
                            if char in self.application_control_bindings:
                                notification_center = NotificationCenter()
                                words = [word for word in re.split(r'\s+', self.application_control_bindings[char]) if word]
                                notification_center.post_notification('UIInputGotCommand', sender=self, data=NotificationData(command=words[0], args=words[1:]))
                        elif self.questions:
                            question = self.questions[0]
                            if char in question.answers:
                                self._raw_write(char)
                                self.displaying_question = False
                                self.remove_question(question)
                                notification_center = NotificationCenter()
                                notification_center.post_notification('UIQuestionGotAnswer', sender=question, data=NotificationData(answer=char))
                        else:
                            # insert char in input.current_line at input.cursor_position and advance cursor
                            self.input.current_line = self.input.current_line[:self.input.cursor_position] + char + self.input.current_line[self.input.cursor_position:]
                            self.input.cursor_position += 1
                            self._update_prompt()

    def _raw_write(self, text):
        sys.__stdout__.write(str(text))
        sys.__stdout__.flush()

    def _window_resized(self):
        pass

    def _update_prompt(self):
        # The (X-1)/window_size.x+1 are because the position in the terminal is
        # a 1-based index; the + 1 when calculating the indexes are because the
        # positions we keep are 0-based.
        if self.displaying_question or self.stopping:
            return
        if self.questions:
            window_size = self.window_size
            question = self.questions[0]
            # we also want to leave a space after the question and we need an
            # extra position for the cursor
            text_len = len(question) + 2
            # calculate how much we need to scroll up
            text_lines = (text_len-1)/window_size.x + 1
            scroll_up = text_lines - (window_size.y - self.prompt_y + 1)
            if scroll_up > 0:
                self._scroll_up(scroll_up)
                self.prompt_y -= scroll_up
            # go to the position where the question will be rendered
            self._raw_write('\x1b[%d;%dH' % (self.prompt_y, 1))
            # erase everything beneath it
            self._raw_write('\x1b[0J')
            # might need to draw the status
            self._draw_status()
            # draw the question
            self._raw_write(question)
            # and a space
            self._raw_write(' ')
            # calculate the cursor position
            self.cursor_y = (text_len-1)/window_size.x + self.prompt_y # no need to add 1 since we had to subtract 1
            self.cursor_x = (text_len-1)%window_size.x + 1
            # the new prompt will now be just under the question
            self.prompt_y += text_lines
            self.displaying_question = True
        else:
            window_size = self.window_size
            text_len = len(self.prompt) + len(self.input.current_line)
            # we also need a position for the cursor if it's at the end of the line
            if self.input.cursor_position == len(self.input.current_line):
                text_len += 1
            # calculate how much we need to scroll up
            text_lines = (text_len-1)/window_size.x + 1
            scroll_up = text_lines - (window_size.y - self.prompt_y + 1)
            if scroll_up > 0:
                self._scroll_up(scroll_up)
                self.prompt_y -= scroll_up
            # goto the position of the new prompt
            self._raw_write('\x1b[%d;%dH' % (self.prompt_y, 1))
            # erase everything beneath it
            self._raw_write('\x1b[0J')
            # might need to draw the status
            self._draw_status()
            # force going to the new prompt position
            self._raw_write('\x1b[%d;%dH' % (self.prompt_y, 1))
            # draw the prompt and the text
            self._raw_write(self.prompt)
            self._raw_write(self.input.current_line)
            # move the cursor to it's correct position
            cursor_position = len(self.prompt) + self.input.cursor_position + 1
            self.cursor_y = (cursor_position-1)/window_size.x + self.prompt_y # no need to add 1 since we had to subtract 1
            self.cursor_x = (cursor_position-1)%window_size.x + 1
            self._raw_write('\x1b[%d;%dH' % (self.cursor_y, self.cursor_x))

    def _draw_status(self):
        status = self.status
        if status is not None:
            status_y, window_length = struct.unpack('HHHH', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))[:2]
            # save current cursor position
            self._raw_write('\x1b[s')
            # goto line status_y
            self._raw_write('\x1b[%d;%dH' % (status_y, 1))
            # erase it
            self._raw_write('\x1b[2K')
            # display the status
            if len(status) > window_length:
                status = status[:window_length]
            self._raw_write(status)
            # restore the cursor position
            self._raw_write('\x1b[u')

    def _scroll_up(self, lines):
        window_height = struct.unpack('HHHH', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))[0]
        self._raw_write('\x1b[s\x1b[%d;1H' % window_height + '\x1bD' * lines + '\x1b[u')

    # control character handlers
    #

    def _CH_default(self, char):
        print 'Got control char %s' % ''.join('%02X' % ord(c) for c in char)

    def _CH_home(self, char):
        if self.input.cursor_position > 0:
            self.input.cursor_position = 0
            self._update_prompt()

    def _CH_eof(self, char):
        notification_center = NotificationCenter()
        notification_center.post_notification('UIInputGotCommand', sender=self, data=NotificationData(command='eof', args=[]))

    def _CH_end(self, char):
        if self.input.cursor_position < len(self.input.current_line):
            self.input.cursor_position = len(self.input.current_line)
            self._update_prompt()

    def _CH_newline(self, char):
        if self.input.current_line:
            # copy the current line to the last line
            self.input.copy_current_line()
            window_size = self.window_size
            # calculate the length of the line just entered
            text_len = len(self.prompt) + len(self.input.current_line)
            text_lines = (text_len-1)/window_size.x + 1
            # save the current line and add a new input line
            current_line = self.input.current_line
            self.input.add_line()
            # see if it's a command or plain text
            notification_center = NotificationCenter()
            if current_line.startswith(self.command_sequence):
                # calculate the new position of the prompt
                if self.display_commands:
                    self.prompt_y += text_lines
                    # we need to scroll if the new prompt position is below the window margin, otherwise
                    # some text might go over it
                    scroll_up = self.prompt_y - window_size.y
                    if scroll_up > 0:
                        self.prompt_y -= scroll_up
                        self._scroll_up(scroll_up)
                # send a notification about the new input
                words = [word for word in re.split(r'\s+', current_line[len(self.command_sequence):]) if word]
                notification_center.post_notification('UIInputGotCommand', sender=self, data=NotificationData(command=words[0], args=words[1:]))
            else:
                # calculate the new position of the prompt
                if self.display_text:
                    self.prompt_y += text_lines
                    # we need to scroll if the new prompt position is below the window margin, otherwise
                    # some text might go over it
                    scroll_up = self.prompt_y - window_size.y
                    if scroll_up > 0:
                        self.prompt_y -= scroll_up
                        self._scroll_up(scroll_up)
                # send a notification about the new input
                notification_center.post_notification('UIInputGotText', sender=self, data=NotificationData(text=current_line))
            # redisplay the prompt
            self._update_prompt()

    def _CH_cursorup(self, char):
        try:
            self.input.line_up()
        except KeyError:
            pass
        else:
            self._update_prompt()

    def _CH_cursordown(self, char):
        try:
            self.input.line_down()
        except KeyError:
            pass
        else:
            self._update_prompt()

    def _CH_cursorright(self, char):
        if self.input.cursor_position < len(self.input.current_line):
            self.input.cursor_position += 1
            self._update_prompt()

    def _CH_cursorleft(self, char):
        if self.input.cursor_position > 0:
            self.input.cursor_position -= 1
            self._update_prompt()

    def _CH_delete(self, char):
        # delete the character in input.current_line at input.cursor_position
        if self.input.cursor_position > 0:
            self.input.current_line = self.input.current_line[:self.input.cursor_position-1]+self.input.current_line[self.input.cursor_position:]
            self.input.cursor_position -= 1
            self._update_prompt()


