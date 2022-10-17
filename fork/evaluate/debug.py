from parse_dwarf import *
from build_parse import *
from metrics import *
from program_metrics import *

prognames = [ "ndarray", "typecases", "p0", "structcases" ]
progs = [ ToyProgram(progname) for progname in prognames ]
opts = BuildOptions()
dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)



for metrics_grp in make_metrics():
    grid = compute_program_metrics_dataframe(
        progs,
        opts,
        metrics_grp
    )
    print(grid)
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


