import subprocess
import re
import itertools
import sys
import os

from distutils.errors import DistutilsError
from distutils import log
from Cython.Distutils import build_ext

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
    stdout = distutils_exec_process(["make", "-f", makefile, "-pR", makefile], True)
    return dict(tup for tup in re.findall("(^[a-zA-Z]\w+)\s*:?=\s*(.*)$", stdout, re.MULTILINE))

class PJSIP_build_ext(build_ext):
    svn_repo = "http://svn.pjsip.org/repos/pjproject/trunk"
    config_site = ["#define PJ_SCANNER_USE_BITWISE 0",
                   "#define PJSIP_SAFE_MODULE 0",
                   "#define PJSIP_MAX_PKT_LEN 65536",
                   "#define PJSIP_UNESCAPE_IN_PLACE 1"]
    patch_file = "patches/pjsip-2371-sip_inv-on_rx_reinvite.patch"
    svn_revision_file = "pypjua/svn_revision"

    def fetch_pjsip_from_svn(self):
        self.svn_dir = os.path.join(self.build_temp, "pjsip")
        if not os.path.exists(self.svn_dir):
            log.info("Fetching PJSIP from SVN repository")
            distutils_exec_process(["svn", "co", self.svn_repo, self.svn_dir], True, input='t\n')
            open(os.path.join(self.svn_dir, "pjlib", "include", "pj", "config_site.h"), "wb").write("\n".join(self.config_site))
            try:
                os.remove(self.svn_revision_file)
            except:
                pass
        else:
            log.info("PJSIP SVN tree found, updating from SVN repository")
            distutils_exec_process(["svn", "up", self.svn_dir], True, input='t\n')
        svn_revision = int(re.search("Revision: (\d+)", distutils_exec_process(["svn", "info", self.svn_dir], True)).group(1))
        print "Using SVN revision %d" % svn_revision
        return svn_revision

    def patch_pjsip(self):
        log.info("Patching PJSIP")
        distutils_exec_process(["svn", "revert", "-R", self.svn_dir], True)
        distutils_exec_process(["patch", "-d", self.svn_dir, "-p0", "-i", os.path.abspath(self.patch_file)], True)

    def configure_pjsip(self):
        log.info("Configuring PJSIP")
        if sys.platform == "darwin":
            cflags = "-fPIC -arch ppc -arch i386"
        else:
            cflags = "-fPIC"
        env = os.environ.copy()
        if "CFLAGS" in env:
            env["CFLAGS"] = " ".join([env["CFLAGS"], cflags])
        else:
            env["CFLAGS"] = cflags
        distutils_exec_process(["./configure"], True, cwd=self.svn_dir, env=env)

    def update_extension(self, extension):
        build_mak_vars = get_makefile_variables(os.path.join(self.svn_dir, "build.mak"))
        extension.include_dirs = get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-I")
        extension.library_dirs = get_opts_from_string(build_mak_vars["PJ_LDFLAGS"], "-L")
        extension.libraries = get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-l")
        extension.define_macros = [tuple(define.split("=", 1)) for define in get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-D")]
        extension.extra_link_args = list(itertools.chain(*[["-framework", val] for val in get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-framework ")]))
        extension.extra_compile_args = ["-Wno-unused-variable"]
        extension.depends = self.libraries = build_mak_vars["PJ_LIB_FILES"].split()

    def remove_libs(self):
        for lib in self.libraries:
            try:
                os.remove(lib)
            except:
                pass

    def compile_pjsip(self):
        log.info("Compiling PJSIP")
        distutils_exec_process(["make"], True, cwd=self.svn_dir)

    def cython_sources(self, sources, extension):
        if extension.name == "pypjua.core":
            new_svn_revision = self.fetch_pjsip_from_svn()
            try:
                current_svn_revision = int(open(self.svn_revision_file, "rb").read())
            except:
                current_svn_revision = -1
            if new_svn_revision > current_svn_revision:
                self.patch_pjsip()
                if not os.path.exists(os.path.join(self.svn_dir, "build.mak")):
                    self.configure_pjsip()
                self.update_extension(extension)
                self.remove_libs()
                self.compile_pjsip()
                open(self.svn_revision_file, "wb").write(str(new_svn_revision))
            else:
                self.update_extension(extension)
        return build_ext.cython_sources(self, sources, extension)