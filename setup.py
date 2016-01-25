#!/usr/bin/env python

import glob
import os

from distutils.core import setup
from distutils.extension import Extension
from setup_pjsip import PJSIP_build_ext
from sipsimple import __info__ as package_info


def find_packages(root):
    return [directory.replace(os.path.sep, '.') for directory, sub_dirs, files in os.walk(root) if '__init__.py' in files]


setup(
    name=package_info.__project__,
    version=package_info.__version__,

    description=package_info.__summary__,
    license=package_info.__license__,
    url=package_info.__webpage__,

    author=package_info.__author__,
    author_email=package_info.__email__,

    platforms=["Platform Independent"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Operating System :: OS Independent",
        "Programming Language :: C",
        "Programming Language :: Cython",
        "Programming Language :: Python"
    ],

    packages=find_packages('sipsimple'),
    package_data={
        'sipsimple.payloads': ['xml-schemas/*']
    },

    ext_modules=[
        Extension(name="sipsimple.core._core", sources=["sipsimple/core/_core.pyx", "sipsimple/core/_core.pxd"] + glob.glob(os.path.join("sipsimple", "core", "_core.*.pxi"))),
        Extension(name="sipsimple.util._sha1", sources=["sipsimple/util/_sha1.pyx"], depends=["sipsimple/util/_sha1.h"])
    ],

    cmdclass={
        'build_ext': PJSIP_build_ext
    },

    provides=['sipsimple']
)
