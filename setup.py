#!/usr/bin/env python

from distutils.core import setup
from distutils.extension import Extension
import os
import glob

from setup_pjsip import PJSIP_build_ext

import sipsimple


setup(name         = "python-sipsimple",
      version      = sipsimple.__version__,
      author       = "AG Projects",
      author_email = "support@ag-projects.com",
      url          = "http://sipsimpleclient.com",
      description  = "SIP SIMPLE client",
      long_description = "Python SIP SIMPLE client library using PJSIP",
      platforms    = ["Platform Independent"],
      classifiers  = [
          "Development Status :: 4 - Beta",
          #"Development Status :: 5 - Production/Stable",
          #"Development Status :: 6 - Mature",
          "Intended Audience :: Service Providers",
          "License :: GNU Lesser General Public License (LGPL)",
          "Operating System :: OS Independent",
          "Programming Language :: Python"
      ],
      packages     = ["sipsimple", "sipsimple.core", "sipsimple.streams", "sipsimple.streams.applications", "sipsimple.payloads", "sipsimple.configuration", "sipsimple.configuration.backend"],
      package_data = {
          'sipsimple.payloads' : ['xml-schemas/*']
      },
      ext_modules  = [
            Extension(name = "sipsimple.core._core",
            sources = ["sipsimple/core/_core.pyx", "sipsimple/core/_core.pxd"] + glob.glob(os.path.join("sipsimple", "core", "_core.*.pxi")))
            ],
      cmdclass = { 'build_ext': PJSIP_build_ext }
)
