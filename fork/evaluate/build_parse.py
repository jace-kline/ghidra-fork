from collections import namedtuple
import os
import pickle
import shutil
import subprocess
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

# class ProgramBuildPickleCacher(object):

#     @staticmethod
#     def gen_pickle_cache_dir() -> Path:
#         if not PICKLE_CACHE_DIR.exists():
#             PICKLE_CACHE_DIR.mkdir()
#         return PICKLE_CACHE_DIR

#     def __init__(
#         self,
#         id: Any, # an ID (str, int, etc) that uniquely identifies the resource being cached
#         objtype: type, # the type that this object caches in the pickle file & returns
#         deps: List[Path], # dependency paths that trigger recache
#         produce: Callable # (Program, BuildOptions) -> objtype ... The function that produces an object of the given type, given a path to a program binary
#     ):
#         self.id = id
#         self.objtype = objtype
#         self.deps = deps
#         self.produce = produce

#     def get_deps(self, prog: Program, opts: BuildOptions) -> List[Path]:
#         return self.deps + [ prog.get_binary_path(opts) ]

#     def mangle_pickle_name(self, prog: Program, opts: BuildOptions) -> str:
#         binname = prog.get_binary_name(opts)

#         # BINNAME.OBJTYPE.ID.pickle
#         return "{}.{}.{}.pickle".format(
#             binname,
#             self.objtype.__name__,
#             self.id
#         )

#     def get_pickle_path(self, prog: Program, opts: BuildOptions) -> Path:
#         return __class__.gen_pickle_cache_dir().joinpath(self.mangle_pickle_name(prog, opts))

#     # does the cached pickle file exist and is it in sync with its dependencies?
#     # assume the program is already built with the given opts
#     def is_cached(self, prog: Program, opts: BuildOptions) -> bool:
#         assert(prog.valid_build(opts))
#         return up_to_date(self.get_pickle_path(prog, opts), self.get_deps(prog, opts))

#     # # child class must implement
#     # def produce(self, binpath: Path) -> Union[Any, None]:
#     #     raise NotImplementedError()

#     def __call__(
#         self,
#         prog: Program,
#         opts: BuildOptions,
#         recache: bool = False
#     ) -> ProgramInfo:
#         assert(prog.valid_build(opts))

#         if self.is_cached(prog, opts) and not recache:
#             return load_pickle(self.get_pickle_path(prog, opts))
#         else:
#             obj = self.produce(prog, opts)
#             if obj:
#                 save_pickle(obj, self.get_pickle_path(prog, opts))
#                 return obj

# # A class that takes in a program, parses, and caches/stores/loads the results
# # Standardizes the convention for caching and recovering saved pickle files
# class ProgramParser(ProgramBuildPickleCacher):
#     def __init__(
#         self,
#         name: str, # the name of the parser entity, e.g., dwarf, ghidra, ida
#         srcpaths: List[Path], # the paths of the source files associated with this parser
#         parse # Path -> ProgramInfo ... function that takes a binary path and parses to ProgramInfo object
#     ):
#         self.name = name
#         self.srcpaths = srcpaths
#         self.parse = parse

#         super(__class__, self).__init__(
#             self.name,
#             ProgramInfo,
#             self.srcpaths,
#             self.parse
#         )

# def mk_program_parser_cacher(
#     name: str, # the name of the parser entity, e.g., dwarf, ghidra, ida
#     srcpaths: List[Path], # the paths of the source files associated with this parser
#     parse: Callable # Path -> ProgramInfo
# ):

#     def produce(prog: Program, opts: BuildOptions) -> ProgramInfo:
#         return parse(prog.get_binary_path(opts))

#     return ProgramBuildPickleCacher(
#         name,
#         ProgramInfo,
#         srcpaths,
#         produce
#     )

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

def get_parser_cached(name: str) -> Callable:
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
    
    deps = LANG_DEPS + RESOLVE_DEPS + [ CODEDIR.joinpath(dep) for dep in res["deps"] ]
    return path_dependent_cacher(deps)(res["parse"])

def parse_proginfo_pair(prog: Program, opts: BuildOptions, decompiler: str = "ghidra") -> Tuple[ProgramInfo, ProgramInfo]:

    dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)

    # ensure the program binaries are valid/updated
    assert(prog.valid_build(opts))
    assert(prog.valid_build(dwarf_opts))

    dwarf_parser = get_parser_cached("dwarf")
    decomp_parser = get_parser_cached(decompiler)

    dwarf_proginfo = dwarf_parser(prog.get_binary_path(dwarf_opts))
    decomp_proginfo = decomp_parser(prog.get_binary_path(opts))

    return (dwarf_proginfo, decomp_proginfo)

def compare2(l: ProgramInfo, r: ProgramInfo) -> UnoptimizedProgramInfoCompare2:
    return UnoptimizedProgramInfoCompare2(
        UnoptimizedProgramInfo(l),
        UnoptimizedProgramInfo(r)
    )

compare2_cached = path_dependent_cacher(LANG_DEPS + RESOLVE_DEPS + COMPARE_DEPS)(compare2)

# def mk_compare2_cacher(decompiler: str = "ghidra"):

#     deps = LANG_DEPS + COMPARE_DEPS + RESOLVE_DEPS

#     def produce(prog: Program, opts: BuildOptions) -> UnoptimizedProgramInfoCompare2:
#         dwarf, decomp = parse_proginfo_pair(prog, opts, decompiler=decompiler)
#         return _compare2(dwarf, decomp)

#     return ProgramBuildPickleCacher(
#         "compare2",
#         UnoptimizedProgramInfoCompare2,
#         deps,
#         produce
#     )

def parse_compare_program(
    prog: Program,
    opts: BuildOptions,
    decompiler: str = "ghidra"
) -> UnoptimizedProgramInfoCompare2:
    dwarf, decomp = parse_proginfo_pair(prog, opts, decompiler=decompiler)
    return compare2_cached(dwarf, decomp)

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
