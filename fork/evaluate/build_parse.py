from collections import namedtuple
import os
import pickle
import shutil
import subprocess
from pathlib import Path, PosixPath
from typing import Any, List, Union

from rule import *
import parse_dwarf
from compare_unoptimized import *
from metrics import *

# GLOBALS
CODEDIR = Path(__file__).resolve().parent # the path to the parent directory of this module

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
        dir: Path, # path to the directory where the binary lives
        src_files: List[Path] = [] # list of paths of dependency source code files
    ):
        self.name = name
        self.dir = dir
        self.src_files = src_files

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

    # Get the list of source code file paths that produce this program.
    def get_src_files(self) -> List[Path]:
        return self.src_files

    # Given build options, generate a FilesystemDependencyRule for building this program.
    def mk_build_rule(self, opts: BuildOptions) -> FilesystemDependencyRule:
        return FilesystemDependencyRule(
            self.get_binary_path(opts),
            self.get_src_files(),
            lambda: self.build(opts)
        )

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

# A class that takes in a program, parses, and caches/stores/loads the results
# Standardizes the convention for caching and recovering saved pickle files
class ProgramParser(object):
    @staticmethod
    def mangle_pickle_name(parsername: str, binpath: Path) -> str:
        binname = binpath.name # the basename of the binary file
        # binhash = hash(str(binpath)) # the hash of the string representation of the path to the binary file

        # BINNAME-HASH(BINPATH).PARSERNAME.pickle
        return "{}.{}.pickle".format(
            binname,
            parsername
        )

    @staticmethod
    def gen_pickle_path(parsername: str, binpath: Path) -> Path:
        PICKLE_CACHE_DIR = CODEDIR.joinpath("pickle_cache")
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

    def mk_program_pickle_rule(self, prog: Program, opts: BuildOptions) -> FilesystemDependencyRule:
        def _pickle_builder_thunk(prog: Program, opts: BuildOptions):
            # should return a function of signature () -> bool
            def inner() -> bool:
                assert(prog.get_binary_path(opts).exists())
                proginfo = self.parse(prog.get_binary_path(opts))
                if proginfo:
                    save_pickle(proginfo, __class__.gen_pickle_path(self.name, prog.get_binary_path(opts)))
                    return True
                return False
            return inner

        # make the build rule for building the program
        # implicitly registers rule to RULE_DB
        progrule = prog.mk_build_rule(opts)

        # dependency list
        deps = self.srcpaths + [progrule.get_target_path()]

        return FilesystemDependencyRule(
            __class__.gen_pickle_path(self.name, prog.get_binary_path(opts)),
            deps,
            _pickle_builder_thunk(prog, opts)
        )

    def parse_program(self, prog: Program, opts: BuildOptions, rebuild: bool = False) -> ProgramInfo:
        pickle_rule = self.mk_program_pickle_rule(prog, opts)

        if pickle_rule.make():
            return load_pickle(pickle_rule.get_target_path())
        return None

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
    
    common_deps = [ dep for dep in CODEDIR.glob("lang*.py") ]
    deps = common_deps + [ CODEDIR.joinpath(dep) for dep in res["deps"] ]
    return ProgramParser(name, deps, res["parse"])

def parse_proginfo_pair(prog: Program, opts: BuildOptions, decompiler: str = "ghidra") -> UnoptimizedProgramInfoCompare2:
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

def parse_compare_unoptimized(prog: Program, opts: BuildOptions, decompiler: str = "ghidra") -> UnoptimizedProgramInfoCompare2:
    assert(opts.optimization == 0)
    dwarf_proginfo, decomp_proginfo = parse_proginfo_pair(prog, opts, decompiler=decompiler)

    return UnoptimizedProgramInfoCompare2(
        UnoptimizedProgramInfo(dwarf_proginfo),
        UnoptimizedProgramInfo(decomp_proginfo)
    )


opts = BuildOptions()
structcases = ToyProgram("structcases")
ls = CoreutilsProgram("ls")


cmp = parse_compare_unoptimized(ls, opts)
# cmp.get_right().get_proginfo().print_summary()
# dwarf_parser = get_parser("dwarf")
# ghidra_parser = get_parser("ghidra")

# proginfo = dwarf_parser.parse_program(ls, BuildOptions(debug=True))
# proginfo = ghidra_parser.parse_program(ls, opts)
# proginfo.print_summary()

# prog_rule = structcases.mk_build_rule(opts)
# pickle_rule = ghidra_parser.mk_program_pickle_rule(structcases, opts)
# dwarf_proginfo = dwarf_parser.parse_program(ls, BuildOptions(debug=True))
# ghidra_proginfo = ghidra_parser.parse_program(ls, opts)
# dwarf, ghidra = parse_proginfo_pair(typecases, opts)

# objpath = CoreutilsProgram.COREUTILS_SRC_PATH.joinpath("ls.o")

# dwarf_proginfo = parse_dwarf_proginfo(objpath)
# ghidra_proginfo = parse_ghidra_proginfo(objpath)