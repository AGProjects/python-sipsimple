#!/usr/bin/python

import glob
import os

from distutils.core import setup
from distutils.extension import Extension
from setup_pjsip import PJSIP_build_ext


def find_packages(root):
    return [directory.replace(os.path.sep, '.') for directory, sub_dirs, files in os.walk(root) if '__init__.py' in files]


class PackageInfo(object):
    def __init__(self, info_file):
        with open(info_file) as f:
            exec(f.read(), self.__dict__)
        self.__dict__.pop('__builtins__', None)

    def __getattribute__(self, name):  # this is here to silence the IDE about missing attributes
        return super(PackageInfo, self).__getattribute__(name)


package_info = PackageInfo(os.path.join('sipsimple', '__info__.py'))


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
