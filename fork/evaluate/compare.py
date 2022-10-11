import subprocess
import os
import pickle

from program import *
import parse_dwarf
from compare_unoptimized import *
from metrics import *



# str -> ProgramInfo
def load_pickle(picklepath):
    infile = open(picklepath, 'rb')
    obj = pickle.load(infile)
    infile.close()
    return obj



def parse_proginfo_pair(prog: Program, opts: BuildOptions, decompiler_parser=parse_ghidra_proginfo) -> UnoptimizedProgramInfoCompare2:
    dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)

    # ensure the target binaries exist (for the given build options)
    if not prog.valid_build(dwarf_opts):
        raise Exception("Could not fetch program binary with path {}. BuildOptions = {}.".format(prog.get_binary_path(dwarf_opts)), dwarf_opts)
    
    if not prog.valid_build(opts):
        raise Exception("Could not fetch program binary with path {}. BuildOptions = {}.".format(prog.get_binary_path(opts)), opts)

    dwarf_proginfo = parse_dwarf_proginfo(prog.get_binary_path(dwarf_opts))
    decomp_proginfo = decompiler_parser(prog.get_binary_path(opts))

    return dwarf_proginfo, decomp_proginfo

def parse_compare(prog: Program, opts: BuildOptions, decompiler_parser=parse_ghidra_proginfo) -> UnoptimizedProgramInfoCompare2:
    dwarf_proginfo, decomp_proginfo = parse_proginfo_pair(prog, opts, decompiler_parser=decompiler_parser)

    return UnoptimizedProgramInfoCompare2(
        UnoptimizedProgramInfo(dwarf_proginfo),
        UnoptimizedProgramInfo(decomp_proginfo)
    )

opts = BuildOptions()
typecases = ToyProgram("typecases")
ls = CoreutilsProgram("ls")
# cmp = parse_compare(ls, opts)
dwarf, ghidra = parse_proginfo_pair(ls, opts)

    