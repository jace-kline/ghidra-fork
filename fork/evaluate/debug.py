from parse_dwarf import *
from build_parse import *
from metrics import *
from program_metrics import *

prognames = [ "ndarray", "typecases", "p0", "structcases" ]
progs = [ ToyProgram(progname) for progname in prognames ]
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

# s = ""
# for prog in COREUTILS_PROGS:
#     # prog.build_if_not_valid(opts)
#     # prog.build_if_not_valid(dwarf_opts)
#     dwarf = ghidra = None
#     cmp = None
#     results = None
#     try:
#         dwarf, ghidra = parse_proginfo_pair(prog, opts)
#         # print(prog.get_name())
#         # print(_f(dwarf))
#         # print(_f(ghidra))
#         # print(),
#         cmp = UnoptimizedProgramInfoCompare2(
#             UnoptimizedProgramInfo(dwarf),
#             UnoptimizedProgramInfo(ghidra)
#         )
#         for metrics_group in metrics_groups:
#             compute_program_metrics(prog, opts, metrics_group)
#     except:
#         s += "\"{}\", ".format(prog.get_name())

# print(s)

# prog = ToyProgram("p1")
dwarf_parser = get_parser_cached("dwarf")
ghidra_parser = get_parser_cached("ghidra")

opts = BuildOptions()
dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)
prog = CoreutilsProgram("ls")

dwarf = dwarf_parser(prog.get_binary_path(dwarf_opts))
ghidra = ghidra_parser(prog.get_binary_path(opts))
cmp = compare2_cached(dwarf, ghidra)

# dwarf_unopt, ghidra_unopt = cmp.get_left(), cmp.get_right()
# cmp_flip = cmp.flip()

def missed_varnodes_summary(cmp: UnoptimizedProgramInfoCompare2):
    compared_fn_records = cmp.select_function_compare_records(function_cmp_record_cond=function_compare_record_compared_filter)
    fn_cmps = [ fn_record.get_comparison() for fn_record in compared_fn_records ]
    fn_names = [ fn_record.get_unoptimized_function().get_function().get_name() for fn_record in compared_fn_records ]
    fn_scope_cmps = [ fn_cmp.get_variable_set_comparison() for fn_cmp in fn_cmps ] 
    gbl_scope_cmp = cmp.get_globals_comparison()
    named_scope_cmps: List[Tuple[str, ConstPCVariableSetSnapshotCompare2]] = [("GLOBALS", gbl_scope_cmp)] + list(zip(fn_names, fn_scope_cmps))
    for scopename, scopecmp in named_scope_cmps:
        varnode_records = scopecmp.select_varnode_compare_records(varnode_cmp_record_cond=varnode_base_filter)
        missed_records = [ record for record in varnode_records if record.get_compare_level() == VarnodeCompareLevel.NO_MATCH ]
        if missed_records:
            print(scopename)
        for varnode_record in missed_records:
            varnode = varnode_record.get_varnode()
            varname = varnode.get_var().get_name() if varnode.get_var() is not None else None
            addr_range = varnode.get_addr_range()
            print("\t{} @ ({}, {})".format(
                varname,
                # VarnodeCompareLevel.to_string(varnode_record.get_compare_level()),
                addr_range.get_start(),
                addr_range.get_end()
            ))
            
            right_varnodes = [ varnode for varnode in scopecmp.get_right().get_varnodes() if varnode_base_filter(varnode) ]
            overlapped_varnodes = [ varnode for varnode in right_varnodes if addr_range.does_overlap(varnode.get_addr_range()) ]
            for overlap_varnode in overlapped_varnodes:
                overlap_varname = overlap_varnode.get_var().get_name() if varnode.get_var() is not None else None
                overlap_addr_range = varnode.get_addr_range()
                print("\t{} @ ({}, {})".format(
                    overlap_varname,
                    # VarnodeCompareLevel.to_string(varnode_record.get_compare_level()),
                    overlap_addr_range.get_start(),
                    overlap_addr_range.get_end()
                ))

print("------------------- DWARF vs GHIDRA -------------------")
missed_varnodes_summary(cmp)
# print(cmp.show_summary())

# print(),
print("------------------- DWARF -------------------")
# dwarf.print_summary()

# print(),
# print("------------------- GHIDRA vs DWARF -------------------")
# missed_varnodes_summary(cmp_flip)

# dwarf.print_summary()

# for prog in progs:
#     prog.build_if_not_valid(opts)
#     prog.build_if_not_valid(dwarf_opts)
#     dwarf, ghidra = parse_proginfo_pair(prog, opts)
#     cmp = _compare2(dwarf, ghidra)
#     print(cmp.show_summary())

    # print(prog.get_name())
    # missed_varnodes_summary(cmp)
    # print(),


# metrics_groups = make_metrics()
# varnodes_group = metrics_groups[2]
# # results = varnodes_group.compute_results(cmp)
# # for res in results:
# #     print("{} : {}".format(res.get_metric().get_display_name(), res.get_result()))

# df = compute_program_metrics_dataframe_cached(progs, opts, varnodes_group, recache=True)
# print(df)

# for varnode in varnodes_missed(cmp):
#     varname = varnode.get_var().get_name() if varnode.get_var() is not None else None
#     addr_range = varnode.get_addr_range()
#     print("\t{} @ ({}, {})".format(
#         varname,
#         # VarnodeCompareLevel.to_string(varnode_record.get_compare_level()),
#         addr_range.get_start(),
#         addr_range.get_end()
#     ))

# dwarf.print_summary()
# ghidra.print_summary()

# comparable_records = select_comparable_varnode_compare_records(cmp)
# missed_records = varnode_compare_records_missed_(comparable_records)

# for record in missed_records:
#     varnode = record.get_varnode()
#     var = varnode.get_var()
#     fn = var.get_parent_function() if var is not None else None
#     addr_range = varnode.get_addr_range()
#     print("{} : {} @ ({}, {})".format(
#         fn.get_name() if fn is not None else None,
#         var.get_name() if var is not None else None,
#         addr_range.get_start(),
#         addr_range.get_end()
#     ))





