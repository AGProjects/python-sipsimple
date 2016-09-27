
import errno
import itertools
import os
import platform
import re
import shutil
import subprocess
import sys

if sys.platform.startswith('linux'):
    sys_platform = 'linux'
elif sys.platform.startswith('freebsd'):
    sys_platform = 'freebsd'
else:
    sys_platform = sys.platform


# Hack to set environment variables before importing distutils
# modules that will fetch them and set the compiler and linker
# to be used. -Saul

if sys_platform == "darwin":
    min_osx_version = "10.11"
    try:
        osx_sdk_path = subprocess.check_output(["xcodebuild", "-version", "-sdk", "macosx", "Path"]).strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError("Could not locate SDK path: %s" % str(e))
    # OpenSSL (must be installed with Homebrew)
    ossl_cflags = "-I/usr/local/opt/openssl/include"
    ossl_ldflags = "-L/usr/local/opt/openssl/lib"
    # SQLite (must be installed with Homebrew)
    sqlite_cflags = "-I/usr/local/opt/sqlite/include"
    sqlite_ldflags = "-L/usr/local/opt/sqlite/lib"
    # Prepare final flags
    arch_flags =  "-arch x86_64"
    local_cflags = " %s %s %s -mmacosx-version-min=%s -isysroot %s" % (arch_flags, ossl_cflags, sqlite_cflags, min_osx_version, osx_sdk_path)
    local_ldflags = " %s %s %s -isysroot %s" % (arch_flags, ossl_ldflags, sqlite_ldflags, osx_sdk_path)
    os.environ['CFLAGS'] = os.environ.get('CFLAGS', '') + local_cflags
    os.environ['LDFLAGS'] = os.environ.get('LDFLAGS', '') + local_ldflags
    os.environ['ARCHFLAGS'] = arch_flags
    os.environ['MACOSX_DEPLOYMENT_TARGET'] = min_osx_version

from distutils import log
from distutils.dir_util import copy_tree
from distutils.errors import DistutilsError
from Cython.Distutils import build_ext


class PJSIP_build_ext(build_ext):
    config_site = ["#define PJ_SCANNER_USE_BITWISE 0",
                   "#define PJSIP_SAFE_MODULE 0",
                   "#define PJSIP_MAX_PKT_LEN 262144",
                   "#define PJSIP_UNESCAPE_IN_PLACE 1",
                   "#define PJMEDIA_AUDIO_DEV_HAS_COREAUDIO %d" % (1 if sys_platform=="darwin" else 0),
                   "#define PJMEDIA_AUDIO_DEV_HAS_ALSA %d" % (1 if sys_platform=="linux" else 0),
                   "#define PJMEDIA_AUDIO_DEV_HAS_WMME %d" % (1 if sys_platform=="win32" else 0),
                   "#define PJMEDIA_HAS_SPEEX_AEC 0",
                   "#define PJMEDIA_HAS_WEBRTC_AEC %d" % (1 if re.match('i\d86|x86|x86_64', platform.machine()) else 0),
                   "#define PJMEDIA_RTP_PT_TELEPHONE_EVENTS 101",
                   "#define PJMEDIA_RTP_PT_TELEPHONE_EVENTS_STR \"101\"",
                   "#define PJMEDIA_STREAM_ENABLE_KA PJMEDIA_STREAM_KA_EMPTY_RTP",
                   "#define PJMEDIA_STREAM_VAD_SUSPEND_MSEC 0",
                   "#define PJMEDIA_CODEC_MAX_SILENCE_PERIOD -1",
                   "#define PJ_ICE_MAX_CHECKS 256",
                   "#define PJ_LOG_MAX_LEVEL 6",
                   "#define PJ_IOQUEUE_MAX_HANDLES 1024",
                   "#define PJ_DNS_RESOLVER_MAX_TTL 0",
                   "#define PJ_DNS_RESOLVER_INVALID_TTL 0",
                   "#define PJSIP_TRANSPORT_IDLE_TIME 7200",
                   "#define PJ_ENABLE_EXTRA_CHECK 1",
                   "#define PJSIP_DONT_SWITCH_TO_TCP 1",
                   "#define PJMEDIA_VIDEO_DEV_HAS_SDL 0",
                   "#define PJMEDIA_VIDEO_DEV_HAS_AVI 0",
                   "#define PJMEDIA_VIDEO_DEV_HAS_FB 1",
                   "#define PJMEDIA_VIDEO_DEV_HAS_V4L2 %d" % (1 if sys_platform=="linux" else 0),
                   "#define PJMEDIA_VIDEO_DEV_HAS_AVF %d" % (1 if sys_platform=="darwin" else 0),
                   "#define PJMEDIA_VIDEO_DEV_HAS_DSHOW %d" % (1 if sys_platform=="win32" else 0),
                   "#define PJMEDIA_VIDEO_DEV_HAS_CBAR_SRC 1",
                   "#define PJMEDIA_VIDEO_DEV_HAS_NULL 1"]

    user_options = build_ext.user_options
    user_options.extend([
        ("pjsip-clean-compile", None, "Clean PJSIP tree before compilation"),
        ("pjsip-disable-assertions", None, "Disable assertion checks within PJSIP"),
        ("pjsip-verbose-build", None, "Print output of PJSIP compilation process")
        ])
    boolean_options = build_ext.boolean_options
    boolean_options.extend(["pjsip-clean-compile", "pjsip-disable-assertions", "pjsip-verbose-build"])

    @staticmethod
    def distutils_exec_process(cmdline, silent=True, input=None, **kwargs):
        """Execute a subprocess and returns the returncode, stdout buffer and stderr buffer.
        Optionally prints stdout and stderr while running."""
        try:
            sub = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
            stdout, stderr = sub.communicate(input=input)
            returncode = sub.returncode
            if not silent:
                sys.stdout.write(stdout)
                sys.stderr.write(stderr)
        except OSError, e:
            if e.errno == errno.ENOENT:
                raise RuntimeError('"%s" is not present on this system' % cmdline[0])
            else:
                raise
        if returncode != 0:
            raise RuntimeError('Got return value %d while executing "%s", stderr output was:\n%s' % (returncode, " ".join(cmdline), stderr.rstrip("\n")))
        return stdout

    @staticmethod
    def get_make_cmd():
        if sys_platform == "freebsd":
            return "gmake"
        else:
            return "make"

    @staticmethod
    def get_opts_from_string(line, prefix):
        """Returns all options that have a particular prefix on a commandline"""
        chunks = [chunk.strip() for chunk in line.split()]
        return [chunk[len(prefix):] for chunk in chunks if chunk.startswith(prefix)]

    @classmethod
    def get_makefile_variables(cls, makefile):
        """Returns all variables in a makefile as a dict"""
        stdout = cls.distutils_exec_process([cls.get_make_cmd(), "-f", makefile, "-pR", makefile], silent=True)
        return dict(tup for tup in re.findall("(^[a-zA-Z]\w+)\s*:?=\s*(.*)$", stdout, re.MULTILINE))

    @classmethod
    def makedirs(cls, path):
        try:
            os.makedirs(path)
        except OSError, e:
            if e.errno==errno.EEXIST and os.path.isdir(path) and os.access(path, os.R_OK | os.W_OK | os.X_OK):
                return
            raise

    def initialize_options(self):
        build_ext.initialize_options(self)
        self.pjsip_clean_compile = 0
        self.pjsip_verbose_build = 0
        self.pjsip_dir = os.path.join(os.path.dirname(__file__), "deps", "pjsip")

    def configure_pjsip(self):
        log.info("Configuring PJSIP")
        with open(os.path.join(self.build_dir, "pjlib", "include", "pj", "config_site.h"), "wb") as f:
            f.write("\n".join(self.config_site+[""]))
        cflags = "-DNDEBUG -g -fPIC -fno-omit-frame-pointer -fno-strict-aliasing -Wno-unused-label"
        if self.debug or hasattr(sys, 'gettotalrefcount'):
            log.info("PJSIP will be built without optimizations")
            cflags += " -O0"
        else:
            cflags += " -O2"
        env = os.environ.copy()
        env['CFLAGS'] = ' '.join(x for x in (cflags, env.get('CFLAGS', None)) if x)
        if sys_platform == "win32":
            cmd = ["bash", "configure"]
        else:
            cmd = ["./configure"]
        cmd.extend(["--disable-g7221-codec"])
        ffmpeg_path = env.get("SIPSIMPLE_FFMPEG_PATH", None)
        if ffmpeg_path is not None:
            cmd.append("--with-ffmpeg=%s" % os.path.abspath(os.path.expanduser(ffmpeg_path)))
        libvpx_path = env.get("SIPSIMPLE_LIBVPX_PATH", None)
        if libvpx_path is not None:
            cmd.append("--with-vpx=%s" % os.path.abspath(os.path.expanduser(libvpx_path)))
        self.distutils_exec_process(cmd, silent=not self.pjsip_verbose_build, cwd=self.build_dir, env=env)
        if "#define PJ_HAS_SSL_SOCK 1\n" not in open(os.path.join(self.build_dir, "pjlib", "include", "pj", "compat", "os_auto.h")).readlines():
            os.remove(os.path.join(self.build_dir, "build.mak"))
            raise DistutilsError("PJSIP TLS support was disabled, OpenSSL development files probably not present on this system")

    def compile_pjsip(self):
        log.info("Compiling PJSIP")
        self.distutils_exec_process([self.get_make_cmd()], silent=not self.pjsip_verbose_build, cwd=self.build_dir)

    def clean_pjsip(self):
        log.info("Cleaning PJSIP")
        try:
            shutil.rmtree(self.build_dir)
        except OSError, e:
            if e.errno == errno.ENOENT:
                return
            raise

    def update_extension(self, extension):
        build_mak_vars = self.get_makefile_variables(os.path.join(self.build_dir, "build.mak"))
        extension.include_dirs = self.get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-I")
        extension.library_dirs = self.get_opts_from_string(build_mak_vars["PJ_LDFLAGS"], "-L")
        extension.libraries = self.get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-l")
        extension.define_macros = [tuple(define.split("=", 1)) for define in self.get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-D")]
        extension.define_macros.append(("PJ_SVN_REVISION", open(os.path.join(self.build_dir, "base_rev"), "r").read().strip()))
        extension.define_macros.append(("__PYX_FORCE_INIT_THREADS", 1))
        extension.extra_compile_args.append("-Wno-unused-function")    # silence warning

        if sys_platform == "darwin":
            extension.define_macros.append(("MACOSX_DEPLOYMENT_TARGET", min_osx_version))
            frameworks = re.findall("-framework (\S+)(?:\s|$)", build_mak_vars["PJ_LDLIBS"])
            extension.extra_link_args = list(itertools.chain(*(("-framework", val) for val in frameworks)))
            extension.extra_link_args.append("-mmacosx-version-min=%s" % min_osx_version)
            extension.extra_compile_args.append("-mmacosx-version-min=%s" % min_osx_version)
            extension.library_dirs.append("%s/usr/lib" % osx_sdk_path)
            extension.include_dirs.append("%s/usr/include" % osx_sdk_path)

        extension.depends = build_mak_vars["PJ_LIB_FILES"].split()
        self.libraries = extension.depends[:]

    def cython_sources(self, sources, extension):
        log.info("Compiling Cython extension %s" % extension.name)
        if extension.name == "sipsimple.core._core":
            self.build_dir = os.path.join(self.build_temp, "pjsip")
            if self.pjsip_clean_compile:
                self.clean_pjsip()
            copy_tree(self.pjsip_dir, self.build_dir, verbose=0)
            if not os.path.exists(os.path.join(self.build_dir, "build.mak")):
                self.configure_pjsip()
            self.update_extension(extension)
            self.compile_pjsip()
        return build_ext.cython_sources(self, sources, extension)

