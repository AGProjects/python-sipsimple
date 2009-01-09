import subprocess
import re
import itertools

def get_opts_from_string(line, prefix):
    """Returns all options that have a particular prefix on a commandline"""
    return re.findall("%s(\S+)(?:\s|$)" % prefix, line)

def exec_process(cmdline, silent):
    """Execute a subprocess and returns the returncode, stdout buffer and stderr buffer.
       Optionally prints stdout and stderr while running."""
    stdout_buf = []
    stderr_buf = []
    try:
        sub = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError, e:
        if e.errno == 2:
            raise Exception('Could not find "%s" executable' % cmdline[0])
    while True:
        stdout_data = sub.stdout.read()
        if stdout_data:
            stdout_buf.append(stdout_data)
            if not silent:
                print stdout_data
        stderr_data = sub.stderr.read()
        if stderr_data:
            stderr_buf.append(stderr_data)
            if not silent:
                print stderr_data
        if sub.poll() != None:
            break
    return sub.returncode, "".join(stdout_buf), "".join(stderr_buf)

def get_stdout_from_process(cmdline):
    """Silently get stdout from a particular process.
       Throws exception on a non-zero return code."""
    returncode, stdout, stderr = exec_process(cmdline, True)
    if returncode != 0:
        raise Exception('Got return value %d while executing "%s", stderr output was:\n%s' % (returncode, " ".join(cmdline), stderr))
    return stdout

def get_makefile_variables(makefile):
    """Returns all variables in a makefile as a dict"""
    stdout = get_stdout_from_process(["make", "-f", makefile, "-pR", makefile])
    return dict(tup for tup in re.findall("(^[a-zA-Z]\w+)\s*:?=\s*(.*)$", stdout, re.MULTILINE))

def get_pjsip_extension_kwargs(makefile):
    """Returns all the compilation and linking related keyword arguments needed to create
       the Extension object for the pypjua.core module, parsed from the PJSIP build.mak file."""
    kwargs = {}
    build_mak_vars = get_makefile_variables(makefile)
    kwargs["include_dirs"] = get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-I")
    kwargs["library_dirs"] = get_opts_from_string(build_mak_vars["PJ_LDFLAGS"], "-L")
    kwargs["libraries"] = get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-l")
    kwargs["define_macros"] = [tuple(define.split("=", 1)) for define in get_opts_from_string(build_mak_vars["PJ_CFLAGS"], "-D")]
    kwargs["depends"] = build_mak_vars["PJ_LIB_FILES"].split()
    kwargs["extra_link_args"] = list(itertools.chain(*[["-framework", val] for val in get_opts_from_string(build_mak_vars["PJ_LDLIBS"], "-framework ")]))
    kwargs["extra_compile_args"] = ["-Wno-unused-variable"]
    return kwargs