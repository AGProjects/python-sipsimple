#!/usr/bin/env python

from distutils.core import setup
from distutils.extension import Extension
import os
import glob

from setup_pjsip import PJSIP_build_ext, PJSIP_sdist
import sipsimple

def find_packages(toplevel):
    return [directory.replace(os.path.sep, '.') for directory, subdirs, files in os.walk(toplevel) if '__init__.py' in files]

setup(name         = "python-sipsimple",
      version      = sipsimple.__version__,
      author       = "AG Projects",
      author_email = "support@ag-projects.com",
      url          = "http://sipsimpleclient.com",
      description  = "SIP SIMPLE Client SDK",
      long_description = "Python SDK for development of SIP end-points",
      platforms    = ["Platform Independent"],
      classifiers  = [
          "Development Status :: 5 - Production/Stable",
          "Intended Audience :: Service Providers",
          "License :: OSI Approved :: GNU General Public License (GPL)",
          "Operating System :: OS Independent",
          "Programming Language :: Python"
      ],
      packages     = find_packages('sipsimple'),
      package_data = {
          'sipsimple.payloads' : ['xml-schemas/*']
      },
      ext_modules  = [
            Extension(name = "sipsimple.core._core",
            sources = ["sipsimple/core/_core.pyx", "sipsimple/core/_core.pxd"] + glob.glob(os.path.join("sipsimple", "core", "_core.*.pxi")))
            ],
      cmdclass = {
            'build_ext': PJSIP_build_ext,
            'sdist'    : PJSIP_sdist
      }
)
