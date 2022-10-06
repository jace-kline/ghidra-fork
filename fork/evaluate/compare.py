from ast import Sub
import subprocess
import os
import pickle

from program import *
import parse_dwarf
from compare_unoptimized import *

def parse_dwarf_proginfo(binpath: Path) -> ProgramInfo:
    return parse_dwarf.parse_from_objfile(str(binpath))

# str -> ProgramInfo
def load_pickle(picklepath):
    infile = open(picklepath, 'rb')
    obj = pickle.load(infile)
    infile.close()
    return obj

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

def compare(prog: Program, opts: BuildOptions, decompiler_parser=parse_ghidra_proginfo) -> UnoptimizedProgramInfoCompare2:
    dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)

    # ensure the target binaries exist (for the given build options)
    if not prog.valid_build(dwarf_opts):
        raise Exception("Could not fetch program binary with path {}. BuildOptions = {}.".format(prog.get_binary_path(dwarf_opts)), dwarf_opts)
    
    if not prog.valid_build(opts):
        raise Exception("Could not fetch program binary with path {}. BuildOptions = {}.".format(prog.get_binary_path(opts)), opts)

    dwarf_proginfo = parse_dwarf_proginfo(prog.get_binary_path(dwarf_opts))
    decomp_proginfo = decompiler_parser(prog.get_binary_path(opts))

    return UnoptimizedProgramInfoCompare2(
        UnoptimizedProgramInfo(dwarf_proginfo),
        UnoptimizedProgramInfo(decomp_proginfo)
    )

opts = BuildOptions()
typecases = ToyProgram("typecases")
ls = CoreutilsProgram("ls")
cmp = compare(ls, opts)

    