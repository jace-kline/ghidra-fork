from collections import namedtuple
import os
import pickle
import shutil
import subprocess
from pathlib import Path, PosixPath
from typing import Any, List, Union

import parse_dwarf
from compare_unoptimized import *
from metrics import *

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

class Program(object):
    def __init__(
        self,
        name: str,
        dir: Path # path to the directory where the binary lives
    ):
        self.name = name
        self.dir = dir

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

    def build(self, opts: BuildOptions) -> bool:
        raise NotImplementedError()

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

        super(__class__, self).__init__(name, __class__.COREUTILS_PATH.joinpath("bin"))

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

class ToyProgram(Program):
    TOY_PROGS_PATH: PosixPath = Path("../progs/").resolve()

    def __init__(
        self,
        name: str
    ):
        super(__class__, self).__init__(name, __class__.TOY_PROGS_PATH.joinpath(name))

    # mangle the options into the correct binary name
    def get_binary_name(self, opts: BuildOptions) -> str:
        return mangle(self.name, opts) + ".bin"

    def build(self, opts: BuildOptions) -> bool:
        makefilepath = __class__.TOY_PROGS_PATH.joinpath("Makefile")
        shutil.copy(makefilepath, self.dir)

        cmd = "make -C {} {}".format(self.dir, self.get_binary_name(opts))
        retcode = subprocess.call(cmd.split())
        return retcode == 0

# This is a rudimentary implementation of a Makefile "target".
# A target "out path" that depends on a set of "dependency paths".
class FilesystemDependencyRule(object):
    def __init__(
        self,
        target: Path,
        deps: List[Path],
        build # () -> bool ... function to build the target. Returns True on success, False on failure
    ):
        self.target = target
        self.deps = tuple(deps)
        self.build = build

    def get_target_path(self) -> Path:
        return self.target

    def get_target_hash(self) -> int:
        return hash(self.target)

    def get_deps(self) -> List[Path]:
        return self.deps

    # The logic to produce output to path of self.target
    # with dependence on paths of self.deps
    def build_target(self) -> bool:
        raise NotImplementedError()

    # Is the target date newer than the dates of all deps?
    def target_up_to_date(self) -> bool:
        def last_modification_ns(p: Path) -> int:
            res = p.stat().st_mtime_ns
            return res if res else -1

        target_mtime_ns = last_modification_ns(self.target)
        return target_mtime_ns > 0 and all([ target_mtime_ns > last_modification_ns(dep) for dep in self.deps ])

    def target_exists(self) -> bool:
        return self.target.exists()

    # Tries to load the cached target.
    # If not up to date, rebuilds it.
    # Returns the target path on success, None on failure.
    def make_target(self, rebuild: bool = False) -> Union[Path, None]:
        if not rebuild and self.target_exists() and self.target_up_to_date():
            return self.target
        else:
            return self.target if self.build() else None

    def clean(self):
        if self.target_exists():
            os.remove(str(self.target))

    def __hash__(self) -> int:
        return hash((self.target, self.deps))

def save_pickle(obj: Any, path: Path):
    outfile = open(str(path), 'wb')
    pickle.dump(obj, outfile, protocol=2)

# str -> ProgramInfo
def load_pickle(path: Path):
    infile = open(str(path), 'rb')
    obj = pickle.load(infile)
    infile.close()
    return obj

# A class that takes in a program, parses, and caches/stores/loads the results
# Standardizes the convention for caching and recovering saved pickle files
class ProgramParser(object):
    @staticmethod
    def mangle_pickle_name(parsername: str, binpath: Path) -> str:
        binname = binpath.name # the basename of the binary file
        binhash = hash(binpath) # the hash of the path to the binary file

        # BINNAME-HASH(BINPATH).PARSERNAME.pickle
        return "{}-{}.{}.pickle".format(
            binname,
            binhash,
            parsername
        )

    @staticmethod
    def gen_pickle_path(parsername: str, binpath: Path) -> Path:
        CWD = Path(os.getcwd()).resolve()
        PICKLE_CACHE_DIR = CWD.joinpath("pickle_cache")
        if not PICKLE_CACHE_DIR.exists():
            PICKLE_CACHE_DIR.mkdir()
        
        return PICKLE_CACHE_DIR.joinpath(__class__.mangle_pickle_name(parsername, binpath))

    def __init__(
        self,
        name: str, # the name of the parser entity, e.g., dwarf, ghidra, ida
        srcpaths: List[Path], # the paths of the source files associated with this parser
        parse # Path -> ProgramInfo ... function that takes a binary path and parses to ProgramInfo object
    ):
        self.name = name
        self.srcpaths = srcpaths
        self.parse = parse

    def mk_program_pickle_builder(self, prog: Program, opts: BuildOptions):
        # should return a function of signature () -> bool
        def inner() -> bool:
            proginfo = self.parse(prog.get_binary_path(opts))
            if proginfo:
                save_pickle(proginfo, __class__.gen_pickle_path(self.name, prog.get_binary_path(opts)))
                return True
            return False
        return inner

    def mk_program_pickle_rule(self, prog: Program, opts: BuildOptions) -> FilesystemDependencyRule:
        return FilesystemDependencyRule(
            __class__.gen_pickle_path(self.name, prog.get_binary_path(opts)),
            self.srcpaths,
            self.mk_program_pickle_builder(prog, opts)
        )

    def parse_program(self, prog: Program, opts: BuildOptions, rebuild: bool = False) -> ProgramInfo:
        rule = self.mk_program_pickle_rule(prog, opts)
        path = rule.make_target(rebuild=rebuild)
        if path:
            return load_pickle(path)
        return None

def parse_dwarf_proginfo(binpath: Path) -> ProgramInfo:
    return parse_dwarf.parse_from_objfile(str(binpath))

# returns either the path to the outputted pickle file or None on error
def parse_ghidra_to_pickle(binpath: Path) -> Union[Path, None]:
    GHIDRA_BUILD_DIR = Path(os.environ["GHIDRA_BUILD"]).resolve()
    GHIDRA_ANALYZE_HEADLESS_PATH = GHIDRA_BUILD_DIR.joinpath("support/analyzeHeadless")
    CWD = Path(os.getcwd()).resolve()
    GHIDRA_SCRIPTS_PATH = CWD
    PICKLE_OUT_PATH = CWD.joinpath("ghidra.pickle")

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
        CWD,
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

def get_parser(name: str) -> ProgramParser:
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
    
    CWD = Path(os.getcwd()).resolve()
    deps = [ CWD.joinpath(dep) for dep in res["deps"] ]
    return ProgramParser(name, deps, res["parse"])

def parse_proginfo_pair(prog: Program, opts: BuildOptions, decompiler="ghidra") -> UnoptimizedProgramInfoCompare2:
    dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)

    # ensure the target binaries exist (for the given build options)
    if not prog.valid_build(dwarf_opts):
        raise Exception("Could not fetch program binary with path {}. BuildOptions = {}.".format(prog.get_binary_path(dwarf_opts)), dwarf_opts)
    
    if not prog.valid_build(opts):
        raise Exception("Could not fetch program binary with path {}. BuildOptions = {}.".format(prog.get_binary_path(opts)), opts)

    dwarf_parser = get_parser("dwarf")
    decomp_parser = get_parser(decompiler)

    dwarf_proginfo = dwarf_parser.parse_program(prog, dwarf_opts)
    decomp_proginfo = decomp_parser.parse_program(prog, opts)

    return dwarf_proginfo, decomp_proginfo

def parse_compare(prog: Program, opts: BuildOptions, decompiler_parser=parse_ghidra_proginfo) -> UnoptimizedProgramInfoCompare2:
    dwarf_proginfo, decomp_proginfo = parse_proginfo_pair(prog, opts, decompiler_parser=decompiler_parser)

    return UnoptimizedProgramInfoCompare2(
        UnoptimizedProgramInfo(dwarf_proginfo),
        UnoptimizedProgramInfo(decomp_proginfo)
    )


opts = BuildOptions()
structcases = ToyProgram("structcases")
ls = CoreutilsProgram("ls")
# # dwarf_parser = get_parser("dwarf")

# dwarf, ghidra = parse_proginfo_pair(typecases, opts)

# objpath = CoreutilsProgram.COREUTILS_SRC_PATH.joinpath("ls.o")

# dwarf_proginfo = parse_dwarf_proginfo(objpath)
# ghidra_proginfo = parse_ghidra_proginfo(objpath)