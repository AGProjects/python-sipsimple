#!/usr/bin/python

from distutils.core import setup
from distutils.extension import Extension
from distutils.command.build_scripts import build_scripts
import re
import os
import glob

from setup_pjsip import PJSIP_build_ext

# cannot import pypjua here
exec(file('pypjua/clients/setupconfig.py').read())

version = "0.3.0"

title = "SIP SIMPLE client"
description = "Python SIP SIMPLE client library using PJSIP"
scripts = [os.path.join('scripts', x) for x in os.listdir('scripts') if re.match('^sip_.*\\.py$', x) or re.match('^xcap_.*\\.py$', x)]
data_files = glob.glob(os.path.join('scripts', '*.wav'))

if data_files_dir:
    data_files = [(data_files_dir, data_files)]

if os.name == 'posix':
    class my_build_scripts(build_scripts):
        "remove .py extension from the scripts"

        def run (self):
            res = build_scripts.run(self)
            for script in self.scripts:
                filename = os.path.basename(script)
                if filename.endswith('.py'):
                    path = os.path.join(self.build_dir, filename)
                    print 'renaming %s -> %s' % (path, path[:-3])
                    os.rename(path, path[:-3])
else:
    my_build_scripts = build_scripts


setup(name         = "sipclient",
      version      = version,
      author       = "Ruud Klaver",
      author_email = "ruud@ag-projects.com",
      url          = "http://pypjua.com/",
      description  = title,
      long_description = description,
      license      = "GPL",
      platforms    = ["Platform Independent"],
      classifiers  = [
          #"Development Status :: 1 - Planning",
          #"Development Status :: 2 - Pre-Alpha",
          "Development Status :: 3 - Alpha",
          #"Development Status :: 4 - Beta",
          #"Development Status :: 5 - Production/Stable",
          #"Development Status :: 6 - Mature",
          #"Development Status :: 7 - Inactive",
          "Intended Audience :: Service Providers",
          "License :: GNU General Public License (GPL)",
          "Operating System :: OS Independent",
          "Programming Language :: Python",
          "Programming Language :: C"
      ],
      packages     = ["pypjua", "pypjua.clients", "pypjua.applications"],
      package_data = {
          "pypjua": ["svn_revision"],
          'pypjua.applications' : ['xml-schemas/*']
      },
      data_files = data_files,
      scripts = scripts,
      ext_modules  = [
            Extension(name = "pypjua.core",
            sources = ["pypjua/core.pyx", "pypjua/core.pxd"] + glob.glob(os.path.join("pypjua", "core.*.pxi")))
            ],
      cmdclass = { 'build_scripts' : my_build_scripts,
                   'build_ext': PJSIP_build_ext }
)
