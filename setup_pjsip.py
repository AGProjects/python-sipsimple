from __future__ import with_statement

import errno
import ctypes
import itertools
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib2

# Hack to set environment variables before importing distutils
# modules that will fetch them and set the compiler and linker
# to be used. -Saul

if sys.platform == "darwin":
    sipsimple_osx_arch = os.environ.get('SIPSIMPLE_OSX_ARCH', {4: 'i386', 8: 'x86_64'}[ctypes.sizeof(ctypes.c_size_t)])
    sipsimple_osx_sdk = os.environ.get('SIPSIMPLE_OSX_SDK', re.match("(?P<major>\d+.\d+)(?P<minor>.\d+)?", platform.mac_ver()[0]).groupdict()['major'])
    old_sdk_path = "/Developer/SDKs"
    new_sdk_path = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs"
    if os.path.exists(new_sdk_path):
        osx_sdk_path = os.path.join(new_sdk_path, "MacOSX%s.sdk" % sipsimple_osx_sdk)
    else:
        osx_sdk_path = os.path.join(old_sdk_path, "MacOSX%s.sdk" % sipsimple_osx_sdk)
    os.environ['CC'] = "gcc -isysroot %s" % osx_sdk_path
    os.environ['ARCHFLAGS'] = "-arch "+" -arch ".join(sipsimple_osx_arch.split())
    os.environ['LDSHARED'] = "gcc -Wl,-F. -bundle -undefined dynamic_lookup -isysroot %s" % osx_sdk_path

from distutils import log
from distutils.errors import DistutilsError
from distutils.command.sdist import sdist
from Cython.Distutils import build_ext


class PJSIP_build_ext(build_ext):
    pjsip_source_file     = "pjsip-1.0-r3687.tar.gz"
    portaudio_source_file = "portaudio-trunk-r1412.tar.gz"
    webrtc_source_file    = "webrtc-r588.tar.gz"
    source_files_base_url = "http://download.ag-projects.com/SipClient/pjsip"

    config_site = ["#define PJ_SCANNER_USE_BITWISE 0",
                   "#define PJSIP_SAFE_MODULE 0",
                   "#define PJSIP_MAX_PKT_LEN 65536",
                   "#define PJSIP_UNESCAPE_IN_PLACE 1",
                   "#define PJMEDIA_HAS_L16_CODEC 0",
                   "#define PJ_ICE_MAX_CHECKS 256",
                   "#define PJ_LOG_MAX_LEVEL 6",
                   "#define PJ_IOQUEUE_MAX_HANDLES 1024",
                   "#define PJMEDIA_HAS_SPEEX_AEC %d" % (0 if sys.platform=="darwin" else 1),
                   "#define PJMEDIA_HAS_WEBRTC_AEC %d" % (1 if sys.platform=="darwin" else 0),
                   "#define PJ_DNS_RESOLVER_MAX_TTL 0",
                   "#define PJ_DNS_RESOLVER_INVALID_TTL 0",
                   "#define PJSIP_TRANSPORT_IDLE_TIME 7200",
                   "#define PJ_ENABLE_EXTRA_CHECK 1"]

    patch_files = ["patches/pjsip-2371-sip_inv-on_rx_reinvite.patch",
                   "patches/pjsip-3217-sdp_neg_cancel_remote_offer.patch",
                   "patches/pjsip-2553-sip_inv-cancel_sdp_neg_on_sending_negative_reply_to_reinvite.patch",
                   "patches/pjsip-2553-sip_inv-dont_disconnect_on_408_reply_to_reinvite.patch",
                   "patches/pjsip-2553-sip_inv-terminate-reinvite-tsx-on-cancel.patch",
                   "patches/pjsip-2553-sip_inv-improved_missing_ack_handling.patch",
                   "patches/pjsip-2425-sdp_media_line.patch",
                   "patches/pjsip-2394-sip_dialog-no_totag_check_on_dialog_state_update.patch",
                   "patches/pjsip-2832-sdp_ignore_missing_rtpmap_for_dynamic_pt.patch",
                   "patches/pjsip-2833-parse_pjsip_allow_events_hdr.patch",
                   "patches/pjsip-2830-runtime_device_change_detection.patch",
                   "patches/pjsip-2342-g722-14-bits-conversion.patch",
                   "patches/pjsip-2656-ip_selection_algorithm.patch",
                   "patches/pjsip-2830-allow_cancel_reinvite.patch",
                   "patches/pjsip-2830-ice_priority_calculation.patch",
                   "patches/pjsip-2830-ice_regular_nomination.patch",
                   "patches/pjsip-2830-dont_compile_pjsua.patch",
                   "patches/pjsip-2830-ice_choose_right_candidate.patch",
                   "patches/pjsip-2830-ice_avoid_crash_on_ice_completion_cb.patch",
                   "patches/pjsip-2830-ice_status_callbacks.patch",
                   "patches/pjsip-2830-add_mixer_port.patch",
                   "patches/pjsip-2830-ice_transport_info.patch",
                   "patches/pjsip-2830-fix_mixer_port.patch",
                   "patches/pjsip-2830-reuse-thread-desc-in-pa-port.patch",
                   "patches/pjsip-2830-fix_headphones_plug_crash.patch",
                   "patches/pjsip-2830-ice_keepalive_support.patch",
                   "patches/pjsip-2830-dont_accept_sdp_everywhere.patch",
                   "patches/pjsip-2830-allocate_thread_desc_from_pool.patch",
                   "patches/pjsip-2830-do_not_close_stream_too_fast.patch",
                   "patches/pjsip-2830-hide_route_header.patch",
                   "patches/pjsip-2830-runtime_device_change_detection_wmme.patch",
                   "patches/pjsip-2830-fix_crash_with_retry_after_header.patch",
                   "patches/pjsip-3368-evsub_timer_functions.patch",
                   "patches/pjsip-3368-remove_hdr_by_name.patch",
                   "patches/pjsip-3187-sdp_neg_fix_on_bogus_answer.patch",
                   "patches/pjsip-3198-do_not_copy_attrs_on_deactivated_media.patch",
                   "patches/pjsip-2830-remove_unused_ssl_methods.patch",
                   "patches/pjsip-2830-pjmedia_get_default_device_functions.patch",
                   "patches/pjsip-3717-reset_rtcp_stats.patch",
                   "patches/pjsip-disable_mutex_unlock_assert.patch",
                   "patches/pjsip-disable_assert_on_recoverable_error.patch",
                   "patches/pjsip-3414-g722_zero_division.patch",
                   "patches/pjsip-libsrtp-fix_crash_on_rtcp_decode.patch",
                   "patches/pjsip-3149-allow_empty_realm.patch",
                   "patches/pjsip-sip_inv-stop_on_create_offer_processing.patch",
                   "patches/pjsip-sdp_neg-no_direction_update.patch",
                   "patches/pjsip-3115-aec_latency_fixes.patch",
                   "patches/pjsip-echo_reset.patch",
                   "patches/pjsip-webrtc_aec.patch"]

    portaudio_patch_files = ["patches/portaudio-1420-runtime_device_change_detection.patch",
                             "patches/portaudio-1420-compile_snow_leopard.patch",
                             "patches/portaudio-1420-pa_mac_core_x64_assert_fix.patch",
                             "patches/portaudio-1420-runtime_device_change_detection_wmme.patch"]

    user_options = build_ext.user_options
    user_options.extend([
        ("pjsip-clean-compile", None, "Clean PJSIP tree before compilation"),
        ("pjsip-disable-assertions", None, "Disable assertion checks within PJSIP, most will revert to exceptions instead")
        ])
    boolean_options = build_ext.boolean_options
    boolean_options.extend(["pjsip-clean-compile", "pjsip-disable-assertions"])
    cython_version_required = (0, 13)

    @staticmethod
    def distutils_exec_process(cmdline, silent, input=None, **kwargs):
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
        if sys.platform.startswith("freebsd"):
            return "gmake"
        else:
            return "make"

    @staticmethod
    def get_opts_from_string(line, prefix):
        """Returns all options that have a particular prefix on a commandline"""
        return re.findall("%s(\S+)(?:\s|$)" % prefix, line)

    @classmethod
    def check_cython_version(cls):
        from Cython.Compiler.Version import version as cython_version
        if tuple(int(x) for x in cython_version.split(".")) < cls.cython_version_required:
            raise DistutilsError("Cython version %s or higher needed" % ".".join(str(i) for i in cls.cython_version_required))

    @classmethod
    def download_file(cls, filename):
        try:
            file = urllib2.urlopen("%s/%s" % (cls.source_files_base_url, filename))
            dest = os.path.join("pjsip", filename)
            with open(dest, 'wb') as f:
                f.write(file.read())
        except Exception, e:
            raise DistutilsError("Error downloading file %s: %s" % (filename, e))

    @classmethod
    def get_makefile_variables(cls, makefile):
        """Returns all variables in a makefile as a dict"""
        stdout = cls.distutils_exec_process([cls.get_make_cmd(), "-f", makefile, "-pR", makefile], True)
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
        self.pjsip_disable_assertions = int(os.environ.get("PJSIP_NO_ASSERT", 0))
        self.pjsip_build_dir = os.environ.get("PJSIP_BUILD_DIR", None)

    def fetch_pjsip(self):
        if os.path.exists(self.build_dir):
            return
        pjsip_sources_dir = "pjsip"
        self.makedirs(pjsip_sources_dir)
        if not os.path.exists(os.path.join(pjsip_sources_dir, self.pjsip_source_file)):
            self.download_file(self.pjsip_source_file)
        if not os.path.exists(os.path.join(pjsip_sources_dir, self.portaudio_source_file)):
            self.download_file(self.portaudio_source_file)
        if not os.path.exists(os.path.join(pjsip_sources_dir, self.webrtc_source_file)):
            self.download_file(self.webrtc_source_file)
        log.info("Unpacking PJSIP")
        extract_dir = os.path.join(self.pjsip_build_dir or self.build_temp)
        try:
            t = tarfile.open(os.path.join(pjsip_sources_dir, self.pjsip_source_file), 'r')
            t.extractall(extract_dir)
        except tarfile.TarError, e:
            raise DistutilsError("Error uncompressing file %s: %s" % (self.pjsip_source_file, e))
        shutil.rmtree(os.path.join(self.build_dir, 'third_party', 'portaudio'))
        extract_dir = os.path.join(self.build_dir, 'third_party')
        try:
            t = tarfile.open(os.path.join(pjsip_sources_dir, self.portaudio_source_file), 'r')
            t.extractall(extract_dir)
        except tarfile.TarError, e:
            raise DistutilsError("Error uncompressing file %s: %s" % (self.portaudio_source_file, e))
        try:
            t = tarfile.open(os.path.join(pjsip_sources_dir, self.webrtc_source_file), 'r')
            t.extractall(extract_dir)
        except tarfile.TarError, e:
            raise DistutilsError("Error uncompressing file %s: %s" % (self.webrtc_source_file, e))
        self.patch_pjsip()
        self.patch_portaudio()

    def patch_pjsip(self):
        log.info("Patching PJSIP")
        open(os.path.join(self.build_dir, "pjlib", "include", "pj", "config_site.h"), "wb").write("\n".join(self.config_site+[""]))
        for patch_file in self.patch_files:
            self.distutils_exec_process(["patch", "--forward", "-d", self.build_dir, "-p0", "-i", os.path.abspath(patch_file)], True)

    def patch_portaudio(self):
        log.info("Patching PortAudio")
        portaudio_dir = os.path.join(self.build_dir, 'third_party', 'portaudio')
        for patch_file in self.portaudio_patch_files:
            self.distutils_exec_process(["patch", "--forward", "-d", portaudio_dir, "-p0", "-i", os.path.abspath(patch_file)], True)

    def configure_pjsip(self):
        log.info("Configuring PJSIP")
        if self.debug or hasattr(sys, 'gettotalrefcount'):
            log.info("PJSIP will be built with debugging symbols")
            cflags = "-O0 -g -fPIC"
        else:
            cflags = "-O3 -fPIC"
        if sys.platform == "darwin":
            cflags += " %s -mmacosx-version-min=%s -isysroot %s " % (os.environ['ARCHFLAGS'], sipsimple_osx_sdk, osx_sdk_path)
        if self.pjsip_disable_assertions:
            cflags += " -DNDEBUG"
        env = os.environ.copy()
        env['CFLAGS'] = ' '.join(x for x in (cflags, env.get('CFLAGS', None)) if x)
        if sys.platform == "darwin":
            env['LDFLAGS'] = "%s -L%s/usr/lib" % (os.environ['ARCHFLAGS'], osx_sdk_path)
            self.distutils_exec_process(["./configure"], True, cwd=self.build_dir, env=env)
        elif sys.platform == "win32":
            # TODO: add support for building with other compilers like Visual Studio. -Saul
            env['CFLAGS'] += " -Ic:/openssl/include"
            env['LDFLAGS'] = "-Lc:/openssl/lib/MinGW"
            self.distutils_exec_process(["bash", "configure"], True, cwd=self.build_dir, env=env)
        else:
            self.distutils_exec_process(["./configure"], True, cwd=self.build_dir, env=env)
        if "#define PJSIP_HAS_TLS_TRANSPORT 1\n" not in open(os.path.join(self.build_dir, "pjsip", "include", "pjsip", "sip_autoconf.h")).readlines():
            os.remove(os.path.join(self.build_dir, "build.mak"))
            raise DistutilsError("PJSIP TLS support was disabled, OpenSSL development files probably not present on this system")

    def compile_pjsip(self):
        log.info("Compiling PJSIP")
        self.distutils_exec_process([self.get_make_cmd()], True, cwd=self.build_dir)

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
        extension.define_macros.append((("PJ_SVN_REVISION"), re.match(".*-r(?P<revision>\d+).tar.gz", self.pjsip_source_file).groupdict()["revision"]))
        extension.extra_link_args = list(itertools.chain(*[["-framework", val] for val in self.get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-framework ")]))
        extension.extra_compile_args = ["-Wno-unused-variable"]

        if sys.platform == "darwin":
            extension.extra_link_args.append("-mmacosx-version-min=%s" % sipsimple_osx_sdk)
            extension.extra_compile_args.append("-mmacosx-version-min=%s" % sipsimple_osx_sdk)
            extension.library_dirs.append("%s/usr/lib" % osx_sdk_path)
            extension.include_dirs.append("%s/usr/include" % osx_sdk_path)

        extension.depends = build_mak_vars["PJ_LIB_FILES"].split()
        self.libraries = extension.depends[:]
        self.libraries.append(("%(PJ_DIR)s/pjmedia/lib/libpjsdp-%(LIB_SUFFIX)s" % build_mak_vars).replace("$(TARGET_NAME)", build_mak_vars["TARGET_NAME"]))

    def cython_sources(self, sources, extension):
        if extension.name == "sipsimple.core._core":
            self.build_dir = os.path.join(self.pjsip_build_dir or self.build_temp, "pjsip")
            self.check_cython_version()
            if self.pjsip_clean_compile:
                self.clean_pjsip()
            self.fetch_pjsip()
            if self.pjsip_clean_compile or not os.path.exists(os.path.join(self.build_dir, "build.mak")):
                self.configure_pjsip()
            self.update_extension(extension)
            if self.pjsip_clean_compile or not all(map(lambda x: os.path.exists(x), self.libraries)):
                for lib in self.libraries:
                    try:
                        os.remove(lib)
                    except OSError:
                        pass
                self.compile_pjsip()
        return build_ext.cython_sources(self, sources, extension)


class PJSIP_sdist(sdist):
    pjsip_source_file     = PJSIP_build_ext.pjsip_source_file
    portaudio_source_file = PJSIP_build_ext.portaudio_source_file
    webrtc_source_file    = PJSIP_build_ext.webrtc_source_file
    source_files_base_url = PJSIP_build_ext.source_files_base_url

    download_file = PJSIP_build_ext.download_file
    makedirs      = PJSIP_build_ext.makedirs

    def initialize_options(self):
        sdist.initialize_options(self)
        pjsip_sources_dir = "pjsip"
        self.makedirs(pjsip_sources_dir)
        if not os.path.exists(os.path.join(pjsip_sources_dir, self.pjsip_source_file)):
            log.info("Downloading PJSIP source")
            self.download_file(self.pjsip_source_file)
        if not os.path.exists(os.path.join(pjsip_sources_dir, self.portaudio_source_file)):
            log.info("Downloading PortAudio source")
            self.download_file(self.portaudio_source_file)
        if not os.path.exists(os.path.join(pjsip_sources_dir, self.webrtc_source_file)):
            log.info("Downloading WebRTC source")
            self.download_file(self.webrtc_source_file)

