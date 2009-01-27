import subprocess
import re
import itertools
import sys
import os

from distutils.errors import DistutilsError
from distutils import log
from Cython.Distutils import build_ext

def get_make_cmd():
    if sys.platform.startswith("freebsd"):
        return "gmake"
    else:
        return "make"

def get_opts_from_string(line, prefix):
    """Returns all options that have a particular prefix on a commandline"""
    return re.findall("%s(\S+)(?:\s|$)" % prefix, line)

def exec_process(cmdline, silent, input=None, **kwargs):
    """Execute a subprocess and returns the returncode, stdout buffer and stderr buffer.
       Optionally prints stdout and stderr while running."""
    sub = subprocess.Popen(cmdline, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    stdout, stderr = sub.communicate(input=input)
    if not silent:
        sys.stdout.write(stdout)
        sys.stderr.write(stderr)
    return sub.returncode, stdout, stderr

def distutils_exec_process(cmdline, silent, input=None, **kwargs):
    try:
        returncode, stdout, stderr = exec_process(cmdline, silent, input, **kwargs)
    except OSError,e:
        if e.errno == 2:
            raise DistutilsError('"%s" is not present on this system' % cmdline[0])
        else:
            raise
    if returncode != 0:
        raise DistutilsError('Got return value %d while executing "%s", stderr output was:\n%s' % (returncode, " ".join(cmdline), stderr.rstrip("\n")))
    return stdout

def get_makefile_variables(makefile):
    """Returns all variables in a makefile as a dict"""
    stdout = distutils_exec_process([get_make_cmd(), "-f", makefile, "-pR", makefile], True)
    return dict(tup for tup in re.findall("(^[a-zA-Z]\w+)\s*:?=\s*(.*)$", stdout, re.MULTILINE))

def get_svn_revision(svn_dir):
    svn_info = distutils_exec_process(["svn", "info", svn_dir], True)
    return int(re.search("Last Changed Rev: (\d+)", svn_info).group(1))

class PJSIP_build_ext(build_ext):
    config_site = ["#define PJ_SCANNER_USE_BITWISE 0",
                   "#define PJSIP_SAFE_MODULE 0",
                   "#define PJSIP_MAX_PKT_LEN 65536",
                   "#define PJSIP_UNESCAPE_IN_PLACE 1",
                   "#define PJMEDIA_HAS_L16_CODEC 0"]
    patch_files = ["patches/pjsip-2371-sip_inv-on_rx_reinvite.patch",
                   "patches/pjsip-2425-sdp_media_line.patch"]

    user_options = build_ext.user_options
    user_options.extend([
        ("pjsip-svn-repo=", None, "PJSIP SVN repository to checkout from"),
        ("pjsip-svn-revision=", None, "PJSIP SVN revision to fetch"),
        ("pjsip-clean-compile", None, "Clean PJSIP tree before compilation")
        ])
    boolean_options = build_ext.boolean_options
    boolean_options.extend(["pjsip-clean-compile"])
    cython_version_required = (0, 10)

    def initialize_options(self):
        build_ext.initialize_options(self)
        self.pjsip_clean_compile = 0
        self.pjsip_svn_repo = os.environ.get("PJSIP_SVN_REPO", "http://svn.pjsip.org/repos/pjproject/trunk")
        self.pjsip_svn_revision = os.environ.get("PJSIP_SVN_REVISION", "HEAD")

    def check_cython_version(self):
        from Cython.Compiler.Version import version as cython_version
        if tuple(int(x) for x in cython_version.split(".")) < self.cython_version_required:
            raise DistutilsError("Cython version %s or higher needed" % ".".join(str(i) for i in self.cython_version_required))

    def fetch_pjsip_from_svn(self):
        self.svn_dir = os.path.join(self.build_temp, "pjsip")
        try:
            old_svn_rev = get_svn_revision(self.svn_dir)
        except:
            old_svn_rev = -1
        if not os.path.exists(self.svn_dir):
            log.info("Fetching PJSIP from SVN repository")
            distutils_exec_process(["svn", "co", "-r", self.pjsip_svn_revision, self.pjsip_svn_repo, self.svn_dir], True, input='t\n')
            open(os.path.join(self.svn_dir, "pjlib", "include", "pj", "config_site.h"), "wb").write("\n".join(self.config_site))
        else:
            log.info("PJSIP SVN tree found, updating from SVN repository")
            distutils_exec_process(["svn", "up", "-r", self.pjsip_svn_revision, self.svn_dir], True, input='t\n')
        new_svn_rev = get_svn_revision(self.svn_dir)
        print "Using SVN revision %d" % new_svn_rev
        return old_svn_rev != new_svn_rev

    def patch_pjsip(self):
        log.info("Patching PJSIP")
        distutils_exec_process(["svn", "revert", "-R", self.svn_dir], True)
        for patch_file in self.patch_files:
            distutils_exec_process(["patch", "--forward", "-d", self.svn_dir, "-p0", "-i", os.path.abspath(patch_file)], True)

    def configure_pjsip(self):
        log.info("Configuring PJSIP")
        if sys.platform == "darwin":
            cflags = "-fPIC -arch ppc -arch i386"
        else:
            cflags = "-fPIC"
        env = os.environ.copy()
        env['CFLAGS'] = ' '.join(x for x in (cflags, env.get('CFLAGS', None)) if x)
        distutils_exec_process(["./configure"], True, cwd=self.svn_dir, env=env)
        if "#define PJSIP_HAS_TLS_TRANSPORT 1\n" not in open(os.path.join(self.svn_dir, "pjsip", "include", "pjsip", "sip_autoconf.h")).readlines():
            os.remove(os.path.join(self.svn_dir, "build.mak"))
            raise DistutilsError("PJSIP TLS support was disabled, OpenSSL development files probably not present on this system")

    def clean_pjsip(self):
        log.info("Cleaning PJSIP")
        distutils_exec_process([get_make_cmd(), "realclean"], True, cwd=self.svn_dir)

    def update_extension(self, extension):
        build_mak_vars = get_makefile_variables(os.path.join(self.svn_dir, "build.mak"))
        extension.include_dirs = get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-I")
        extension.library_dirs = get_opts_from_string(build_mak_vars["PJ_LDFLAGS"], "-L")
        extension.libraries = get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-l")
        extension.define_macros = [tuple(define.split("=", 1)) for define in get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-D")]
        extension.define_macros.append((("PJ_SVN_REVISION"), str(get_svn_revision(self.svn_dir))))
        extension.extra_link_args = list(itertools.chain(*[["-framework", val] for val in get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-framework ")]))
        extension.extra_compile_args = ["-Wno-unused-variable"]
        extension.depends = build_mak_vars["PJ_LIB_FILES"].split()
        self.libraries = extension.depends[:]
        self.libraries.append(("%(PJ_DIR)s/pjmedia/lib/libpjsdp-%(LIB_SUFFIX)s" % build_mak_vars).replace("$(TARGET_NAME)", build_mak_vars["TARGET_NAME"]))

    def remove_libs(self):
        for lib in self.libraries:
            try:
                os.remove(lib)
            except:
                pass

    def compile_pjsip(self):
        log.info("Compiling PJSIP")
        distutils_exec_process([get_make_cmd()], True, cwd=self.svn_dir)

    def cython_sources(self, sources, extension):
        if extension.name == "pypjua.core":
            self.check_cython_version()
            svn_updated = self.fetch_pjsip_from_svn()
            if svn_updated:
                if self.patch_files:
                    self.patch_pjsip()
            compile_needed = svn_updated
            if not os.path.exists(os.path.join(self.svn_dir, "build.mak")):
                self.configure_pjsip()
                compile_needed = True
            if self.pjsip_clean_compile:
                self.clean_pjsip()
                compile_needed = True
            self.update_extension(extension)
            if compile_needed or not all(map(lambda x: os.path.exists(x), self.libraries)):
                self.remove_libs()
                self.compile_pjsip()
        return build_ext.cython_sources(self, sources, extension)

