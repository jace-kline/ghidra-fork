from parse_dwarf import *
from build_parse import *
from metrics import *
from program_metrics import *

prognames = [ "ndarray", "typecases", "p0", "structcases" ]
progs = [ ToyProgram(progname) for progname in prognames ]
opts = BuildOptions()
dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)
metrics_groups = make_metrics()

def find_erroneous_overlaps(proginfo: ProgramInfo) -> List[Tuple[Varnode, Varnode]]:
    unopt_proginfo = UnoptimizedProgramInfo(proginfo)
    gbls = unopt_proginfo.get_unoptimized_globals()
    fns = unopt_proginfo.get_unoptimized_functions().values()
    return sum([ ConstPCVariableSetSnapshot(fn.get_varnodes())._find_overlaps() for fn in fns ], []) \
        + ConstPCVariableSetSnapshot(gbls)._find_overlaps()

def _name(varnode: Varnode) -> str:
    return varnode.get_var().get_name()

def _f(proginfo: ProgramInfo) -> Tuple[str, str]:
    return [ (_name(l), _name(r)) for (l, r) in find_erroneous_overlaps(proginfo) ]

s = ""
for prog in COREUTILS_PROGS:
    # prog.build_if_not_valid(opts)
    # prog.build_if_not_valid(dwarf_opts)
    dwarf = ghidra = None
    cmp = None
    results = None
    try:
        dwarf, ghidra = parse_proginfo_pair(prog, opts)
        # print(prog.get_name())
        # print(_f(dwarf))
        # print(_f(ghidra))
        # print(),
        cmp = UnoptimizedProgramInfoCompare2(
            UnoptimizedProgramInfo(dwarf),
            UnoptimizedProgramInfo(ghidra)
        )
        for metrics_group in metrics_groups:
            compute_program_metrics(prog, opts, metrics_group)
    except:
        s += "\"{}\", ".format(prog.get_name())

print(s)

# prog = CoreutilsProgram("chroot")
# dwarf, ghidra = parse_proginfo_pair(prog, opts)
# dwarf.print_summary()
        # fail_status = None
        # if dwarf is None or ghidra is None:
        #     fail_status = "parse"
        # elif cmp is None:
        #     fail_status = "compare"
    # print("{} : dwarf={} ghidra={} cmp={}".format(prog.get_name(), dwarf, ghidra, cmp))
    # print(cmp.show_summary())

# for prog, cmp in zip(progs, cmps):
#     if cmp is None:
#         print(prog.get_name())

# for metrics_grp in make_metrics():
#     grid = compute_program_metrics_dataframe(
#         progs,
#         opts,
#         metrics_grp
#     )
#     print(grid)
# cmps = [ parse_compare_unoptimized(prog, opts) for prog in progs ]

# dwarf_parser = get_parser("dwarf")
# ghidra_parser = get_parser("ghidra")

# pairs = []
# cmps = []
# for prog in progs:
#     dwarf = dwarf_parser(prog, dwarf_opts)
#     ghidra = ghidra_parser(prog, opts)
#     pairs.append((dwarf, ghidra))
#     cmps.append(compare2(dwarf, ghidra))

# pairs = [ parse_proginfo_pair(prog, opts) for prog in progs ]
# cmps = [ compare2(l, r) for (l, r) in pairs ]

# proginfos = []
# for prog in progs:
#     binpath = prog.get_binary_path(dwarf_opts)
#     _, dwarfinfo = get_elf_dwarf_info(binpath)
#     parser = ParseDWARF(dwarfinfo)
#     proginfo = parser.parse()
#     proginfos.append(proginfo)


# cmps = [ parse_compare_unoptimized(prog, opts) for prog in progs ]
# pairs = [ parse_proginfo_pair(prog, opts) for prog in progs ]
# cmps = [ compare2(l, r) for (l, r) in pairs ]


