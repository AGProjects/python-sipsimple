#!/usr/bin/python

from distutils.core import setup, Extension
from distutils import sysconfig
import sys
import re
import os

version = "0.1"

title = "PyPJUA - A PJSIP based SIP UA"
description = "A SIP UA implementation using PJSIP"

def filter_cmdline(line, prefix):
    return [arg.split(prefix, 1)[1] for arg in line.split() if arg.startswith(prefix)]

build_mak_file = "pjsip/build.mak"
sysconfig._variable_rx = re.compile("(?:.*\s+)?([a-zA-Z][a-zA-Z0-9_]+)\s*:?=\s*(.*)")
build_mak = sysconfig.parse_makefile(build_mak_file)

includes = filter_cmdline(build_mak["APP_CFLAGS"], "-I")
lib_dirs = filter_cmdline(build_mak["APP_LDFLAGS"], "-L")
macros = [tuple(define.split("=", 1)) for define in filter_cmdline(build_mak["APP_CFLAGS"], "-D")]
libs = filter_cmdline(build_mak["APP_LDLIBS"], "-l")
extras = sum((build_mak["APP_LDLIBS"].split()[index:index+2] for index, value in enumerate(build_mak["APP_LDLIBS"].split()) if value == "-framework"), [])

re_conditionals = re.compile(r"ifneq \((.*),(.*)\)\nAPP_THIRD_PARTY_LIBS\s\+=\s-l(.*?)-\$\(TARGET_NAME\)")
re_findstring = re.compile(r"\$\(findstring\s(.*),(.*)\)")
for left, right, lib in re_conditionals.findall(open(build_mak_file).read()):
    match = re_findstring.match(left)
    if match:
        to_find, find_in = match.groups()
        if to_find in find_in:
            left = "1"
        else:
            left = ""
    if left != right:
        libs.append("%s-%s" % (lib, build_mak["TARGET_NAME"]))

sysconfig._variable_rx = re.compile("([a-zA-Z][a-zA-Z0-9_]+)\s*=\s*(.*)")

setup(name         = "pypjua",
      version      = version,
      author       = "Ruud Klaver",
      author_email = "ruud@ag-projects.com",
      url          = "http://www.ag-projects.com/",
      description  = title,
      long_description = description,
      license      = "GPL",
      platforms    = ["Linux"],
      classifiers  = [
          #"Development Status :: 1 - Planning",
          "Development Status :: 2 - Pre-Alpha",
          #"Development Status :: 3 - Alpha",
          #"Development Status :: 4 - Beta",
          #"Development Status :: 5 - Production/Stable",
          #"Development Status :: 6 - Mature",
          #"Development Status :: 7 - Inactive",
          #"Intended Audience :: Service Providers",
          "License :: GNU General Public License (GPL)",
          #"Operating System :: POSIX :: Linux",
          #"Programming Language :: Python",
          #"Programming Language :: C"
      ],
      packages     = ["pypjua", "pypjua.clients"],
      package_data = {'pypjua.clients' : ['ring_inbound.wav', 'ring_outbound.wav']},
      scripts = ['scripts/' + x for x in os.listdir('scripts')],
      ext_modules  = [
          Extension(name = "pypjua._pjsip",
                    sources = ["pypjua/_pjsip.c"],
		            depends = ["pypjua/_pjsip.pyx"],
		            include_dirs = includes,
                    library_dirs = lib_dirs,
                    define_macros = macros,
                    libraries = libs,
                    extra_link_args = extras)
      ]
)
