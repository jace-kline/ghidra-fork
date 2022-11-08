from collections import namedtuple
import os
import pickle
import shutil
import subprocess
import pandas as pd
from pathlib import Path, PosixPath
from typing import Any, List, Union

from cache import *
import parse_dwarf
from compare_unoptimized import *
from metrics import *

# GLOBALS
CODEDIR = Path(__file__).resolve().parent # the path to the parent directory of this module
PICKLE_CACHE_DIR = CODEDIR.joinpath("pickle_cache")

LANG_DEPS = [ dep for dep in CODEDIR.glob("lang*.py") ]
COMPARE_DEPS = [ dep for dep in CODEDIR.glob("compare*.py") ]
RESOLVE_DEPS = [ dep for dep in CODEDIR.glob("resolve*.py") ]

BuildOptions = namedtuple("BuildOptions", ("debug", "strip", "optimization"), defaults=(False, False, 0))

def to_cc_flags(opts: BuildOptions) -> str:
    return "{} {} -O{}".format(
        "-g" if opts.debug else "",
        "-s" if opts.debug else "",
        opts.optimization
    ).strip()

def suffix(opts: BuildOptions) -> str:
    s = "_O{}".format(opts.optimization)
    if opts.debug:
        s += "_debug"
    if opts.strip:
        s += "_strip"
    return s

# mangle the build options into an appropriate binary name
def mangle(progname: str, opts: BuildOptions) -> str:
    return progname + suffix(opts)

def last_modification_ns(p: Path) -> int:
        res = p.stat().st_mtime_ns
        return res if res else -1

# Does the target path exist & is it newer than the modification dates of all deps?
def up_to_date(path: Path, deps: List[Path]) -> bool:

    if not path.exists():
        return False

    target_mtime_ns = last_modification_ns(path)
    return target_mtime_ns > 0 and all([ target_mtime_ns > last_modification_ns(dep) > 0 for dep in deps ])

class Program(object):
    def __init__(
        self,
        name: str,
        dir: Path, # path to the directory where the binary lives
        src_files: List[Path] = [] # list of paths of dependency source code files
    ):
        self.name = name
        self.dir = dir
        self.src_files = src_files

    def get_name(self) -> str:
        return self.name

    # mangle the options into the correct binary name
    def get_binary_name(self, opts: BuildOptions) -> str:
        return mangle(self.name, opts)

    # returns a Path object pointing to the path of the target binary compiled with given options
    def get_binary_path(self, opts: BuildOptions) -> Union[Path, None]:
        return self.dir.joinpath(self.get_binary_name(opts))

    # given build options, returns whether the corresponding binary exists at the expected path and is valid
    def valid_build(self, opts: BuildOptions) -> bool:
        path = self.get_binary_path(opts)
        return path is not None and path.exists() and path.is_file()

    # Given build options, this method builds the binary and returns whether it built successfully.
    # Must implement in child classes.
    def build(self, opts: BuildOptions) -> bool:
        raise NotImplementedError()

    def build_if_not_valid(self, opts: BuildOptions) -> bool:
        if not self.valid_build(opts):
            return self.build(opts)

    # Get the list of source code file paths that produce this program.
    def get_src_files(self) -> List[Path]:
        return self.src_files

    def __hash__(self) -> int:
        return hash((self.name, self.dir))
        
    def __str__(self) -> str:
        return "<Program name={} dir={}>".format(self.name, self.dir)

    def __repr__(self) -> str:
        return self.__str__()

class CoreutilsProgram(Program):
    COREUTILS_PATH: PosixPath = Path("/home/jacekline/dev/research/programs/coreutils-9.1").resolve()

    def __init__(
        self,
        name: str
    ):
        srcpath = __class__.COREUTILS_PATH.joinpath("src")
        binpath = __class__.COREUTILS_PATH.joinpath("bin")
        src_files = [ srcpath.joinpath("{}.c".format(name)) ]

        super(__class__, self).__init__(
            name,
            binpath,
            src_files=src_files
        )

    def build(self, opts: BuildOptions) -> bool:
        makepath = __class__.COREUTILS_PATH
        cleancmd = "make -C {} clean".format(makepath).split()
        makecmd = [
            "make", "-C", makepath,
            "CFLAGS=\'{}\'".format(to_cc_flags(opts)),
            "EXEEXT=\'{}\'".format(suffix(opts))
        ]

        retcode = subprocess.call(cleancmd)
        success = retcode == 0

        if success:
            subprocess.call(makecmd)
            success = self.valid_build(opts)

        if success:
            srcpath = __class__.COREUTILS_PATH.joinpath("src")
            binpath = __class__.COREUTILS_PATH.joinpath("bin")

            for bin in srcpath.glob("*{}".format(suffix(opts))):
                shutil.copy(bin, binpath)
        
        return success

# COREUTILS_EXCLUDED = [ "arch", "coreutils", "hostname", "install", "chcon", "chgrp", "chmod", "chown", "cp", "du", "fmt", "mv", "rm", "nl", "sort", "tail", "chroot", "csplit", "date", "dd", "df", "dir", "env", "expr", "factor", "id", "kill", "ls", "mkdir", "od", "pr", "printf", "ptx", "split", "stat", "stty", "tac", "timeout", "touch", "tr", "uptime", "vdir", "[", "pinky", "shred", "test" ]

COREUTILS_PROG_NAMES = [
    '[', 'b2sum', 'base32', 'base64', 'basename', 'basenc', 'cat', 'chcon',
    'chgrp', 'chmod', 'chown', 'chroot', 'cksum', 'comm', 'cp', 'csplit',
    'cut', 'date', 'dd', 'df', 'dir', 'dircolors', 'dirname', 'du', 'echo', 'env',
    'expand', 'expr', 'factor', 'false', 'fmt', 'fold', 'groups', 'head', 'hostid',
    'id', 'join', 'kill', 'link', 'ln', 'logname', 'ls',
    'md5sum', 'mkdir', 'mkfifo', 'mknod', 'mktemp', 'mv', 'nice', 'nl', 'nohup',
    'nproc', 'numfmt', 'od', 'paste', 'pathchk', 'pinky', 'pr', 'printenv', 'printf',
    'ptx', 'pwd', 'readlink', 'realpath', 'rm', 'rmdir', 'runcon', 'seq', 'sha1sum',
    'sha224sum', 'sha256sum', 'sha384sum', 'sha512sum', 'shred', 'shuf', 'sleep', 'sort',
    'split', 'stat', 'stdbuf', 'stty', 'sum', 'sync', 'tac', 'tail', 'tee', 'test', 'timeout',
    'touch', 'tr', 'true', 'truncate', 'tsort', 'tty', 'uname', 'unexpand', 'uniq', 'unlink',
    'uptime', 'users', 'vdir', 'wc', 'who', 'whoami', 'yes'
]

COREUTILS_PROGS = [ CoreutilsProgram(progname) for progname in COREUTILS_PROG_NAMES ]

class ToyProgram(Program):
    TOY_PROGS_PATH: PosixPath = Path("../progs/").resolve()

    def __init__(
        self,
        name: str
    ):
        progdir = __class__.TOY_PROGS_PATH.joinpath(name)
        src_files = [ srcfile for srcfile in progdir.glob("*.c") ]

        super(__class__, self).__init__(
            name,
            progdir,
            src_files=src_files
        )

    # mangle the options into the correct binary name
    def get_binary_name(self, opts: BuildOptions) -> str:
        return mangle(self.name, opts) + ".bin"

    def build(self, opts: BuildOptions) -> bool:
        makefilepath = __class__.TOY_PROGS_PATH.joinpath("Makefile")
        shutil.copy(makefilepath, self.dir)

        cmd = "make -C {} {}".format(self.dir, self.get_binary_name(opts))
        retcode = subprocess.call(cmd.split())
        return retcode == 0

def save_pickle(obj: Any, path: Path):
    outfile = open(str(path), 'wb')
    pickle.dump(obj, outfile, protocol=2)

# str -> ProgramInfo
def load_pickle(path: Path):
    infile = open(str(path), 'rb')
    obj = pickle.load(infile)
    infile.close()
    return obj

def parse_dwarf_proginfo(binpath: Path) -> ProgramInfo:
    return parse_dwarf.parse_from_objfile(str(binpath))

# returns either the path to the outputted pickle file or None on error
def parse_ghidra_to_pickle(binpath: Path) -> Union[Path, None]:
    GHIDRA_BUILD_DIR = Path(os.environ["GHIDRA_BUILD"]).resolve()
    GHIDRA_ANALYZE_HEADLESS_PATH = GHIDRA_BUILD_DIR.joinpath("support/analyzeHeadless")
    GHIDRA_SCRIPTS_PATH = CODEDIR
    PICKLE_OUT_PATH = CODEDIR.joinpath("ghidra.pickle")

    cmd = """
    {}
        {}
        tempproject
        -import {}
        -scriptpath {}
        -postscript parse_ghidra_exec.py pickle {}
        -deleteproject
    """.format(
        GHIDRA_ANALYZE_HEADLESS_PATH,
        CODEDIR,
        binpath,
        GHIDRA_SCRIPTS_PATH,
        PICKLE_OUT_PATH
    )

    ret = subprocess.call(
        cmd.split(),
        # stdout=subprocess.DEVNULL,
        # stderr=subprocess.STDOUT
    )

    return None if ret != 0 or not PICKLE_OUT_PATH.exists() else PICKLE_OUT_PATH
    

def parse_ghidra_proginfo(binpath: Path) -> ProgramInfo:

    PICKLE_OUT_PATH = parse_ghidra_to_pickle(binpath)
    if PICKLE_OUT_PATH is None:
        raise Exception("Ghidra could not parse binary to pickle object")
    
    # Assume successful parse and storage to ghidra.pickle
    # Load the pickle file (stores ProgramInfo object parsed by Ghidra)
    proginfo = load_pickle(str(PICKLE_OUT_PATH))

    # Delete the pickle file after loaded
    os.remove(str(PICKLE_OUT_PATH))
    
    # Return the parsed program info
    return proginfo

def get_parser(name: str, cache: bool = True) -> Callable:
    _map = {
        "dwarf": {
            "deps": ["parse_dwarf.py", "parse_dwarf_util.py"],
            "parse": parse_dwarf_proginfo 
        },

        "ghidra": {
            "deps": ["parse_ghidra.py", "parse_ghidra_util.py"],
            "parse": parse_ghidra_proginfo
        }
    }

    res = _map.get(name)
    if not res:
        return None

    if not cache:
        return res["parse"]
    else:
        deps = LANG_DEPS + RESOLVE_DEPS + [ CODEDIR.joinpath(dep) for dep in res["deps"] ]
        return redis_path_dependent_cacher(deps)(res["parse"])

def parse_proginfo_pair(prog: Program, opts: BuildOptions, decompiler: str = "ghidra") -> Tuple[ProgramInfo, ProgramInfo]:

    dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)

    # ensure the program binaries are valid/updated
    assert(prog.valid_build(opts))
    assert(prog.valid_build(dwarf_opts))

    dwarf_parser = get_parser("dwarf")
    decomp_parser = get_parser(decompiler)

    dwarf_proginfo = dwarf_parser(prog.get_binary_path(dwarf_opts))
    decomp_proginfo = decomp_parser(prog.get_binary_path(opts))

    return (dwarf_proginfo, decomp_proginfo)

def compare2_uncached(l: ProgramInfo, r: ProgramInfo) -> UnoptimizedProgramInfoCompare2:
    return UnoptimizedProgramInfoCompare2(
        UnoptimizedProgramInfo(l),
        UnoptimizedProgramInfo(r)
    )

compare2 = redis_path_dependent_cacher(LANG_DEPS + RESOLVE_DEPS + COMPARE_DEPS)(compare2_uncached)

def parse_compare_program(
    prog: Program,
    opts: BuildOptions,
    decompiler: str = "ghidra"
) -> UnoptimizedProgramInfoCompare2:
    dwarf, decomp = parse_proginfo_pair(prog, opts, decompiler=decompiler)
    return compare2(dwarf, decomp)

def build_parse_compare_program(
    prog: Program,
    opts: BuildOptions,
    decompiler: str = "ghidra"
) -> UnoptimizedProgramInfoCompare2:
    # build the program binary on the filesystem if necessary
    dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)
    prog.build_if_not_valid(opts)
    prog.build_if_not_valid(dwarf_opts)
    assert(prog.valid_build(opts))
    assert(prog.valid_build(dwarf_opts))

    # get the comparison object
    return parse_compare_program(prog, opts, decompiler=decompiler)

def compute_comparison_metrics(
    cmp: UnoptimizedProgramInfoCompare2,
    metrics: List[Metric]
) -> List[Union[int, float]]:

    # use the comparison to generate the desired metrics
    return [ metric(cmp) for metric in metrics ]

def compute_comparisons_metrics_dataframe(
    prog_names: List[str], # the program names associated with the cmps
    cmps: List[UnoptimizedProgramInfoCompare2],
    metrics: List[Metric]
) -> pd.DataFrame:
    metrics_lists = [ compute_comparison_metrics(cmp, metrics) for cmp in cmps ]
    col_names = [ metric.get_display_name() for metric in metrics ]
    return pd.DataFrame(
        metrics_lists,
        index=prog_names,
        columns=col_names
    )

def compute_programs_metrics_dataframe(
    progs: List[Program],
    opts: BuildOptions,
    metrics: List[Metric],
    decompiler: str = "ghidra"
):
    prog_names = [ prog.get_name() for prog in progs ]
    cmps = [ parse_compare_program(prog, opts, decompiler=decompiler) for prog in progs ]
    return compute_comparisons_metrics_dataframe(prog_names, cmps, metrics)