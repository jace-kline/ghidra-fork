import sys
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

from build import *
from compare_unoptimized import *
from metrics import *

def test_compare_dtypes(left, right, offset):
    # compare
    comparison = DataTypeCompare2(left, right, offset)
    print(comparison)

    # get the descent
    descent = comparison.get_left_descent()
    descent = descent if descent is not None else comparison.get_right_descent()

    # if descent exists, print path
    if descent:
        print("Descent path:")
        for record in comparison.get_left_descent().get_path():
            print("\t{}".format(record))

def test0():
    left = DataTypeInt(size=4)
    right = DataTypeInt(size=4)

    test_compare_dtypes(left, right, 0)

def test1():
    left = DataTypeStruct(
        name="outerstruct",
        membertypes=[
            DataTypeStruct( # offset = 0
            name="innerstruct",
            membertypes=[
                DataTypeInt(size=4), # offset = 0
                DataTypeInt(size=4) # offset = 4
            ]),
            DataTypeStruct( # offset = 8
            name="innerstruct",
            membertypes=[
                DataTypeInt(size=4), # offset = 8
                DataTypeInt(size=4) # offset = 12
            ]),
            DataTypeInt(size=4) # offset = 16
        ]
    )
    # print(dtype0)

    right = DataTypeInt(size=4)

    test_compare_dtypes(left, right, 16)

def test_compare_unoptimized(progdir, debug=False, strip=False, rebuild=False):
    dwarf_proginfo, ghidra_proginfo = build2(progdir, 0, debug=debug, strip=strip, rebuild=rebuild)

    dwarf = UnoptimizedProgramInfo(dwarf_proginfo)
    ghidra = UnoptimizedProgramInfo(ghidra_proginfo)
    comparison = UnoptimizedProgramInfoCompare2(ghidra, dwarf)

    return (comparison, comparison.flip())

def test_compare_unoptimized_interactive():
    args = sys.argv
    if len(args) < 2:
        print("USAGE: python3 {} [opts...] <path/to/progdir>".format(args[0]))
        exit(0)
    
    # last arg: path to program source directory
    progdir = args[-1]

    # opts
    rebuild = "--rebuild" in args[1:-1] # force rebuild?
    debug = "--debug" in args[1:-1] # provide debugging symbols to Ghidra?
    strip = "--strip" in args[1:-1] # strip symbols in Ghidra binary?

    return test_compare_unoptimized(progdir, debug=debug, strip=strip, rebuild=rebuild)

def compare_summary(cmp_ghidra: UnoptimizedProgramInfoCompare2, cmp_dwarf: UnoptimizedProgramInfoCompare2):
    print("----------GHIDRA DECOMPILER OUTPUT----------\n")
    cmp_ghidra.get_left().get_proginfo().print_summary()

    print("\n----------DWARF OUTPUT (ground truth)----------\n")
    cmp_ghidra.get_right().get_proginfo().print_summary()

    # print("\n---------GHIDRA VS DWARF----------\n")
    # print(cmp_ghidra.show_summary())

    # print("\n---------DWARF VS GHIDRA----------\n")
    # print(cmp_dwarf.show_summary())
    
    # mainfn = [ fn for fn in cmp_ghidra.get_left().get_unoptimized_functions().values() if fn.get_function().get_name() == "main" ][0]

def metrics_summary(cmp: UnoptimizedProgramInfoCompare2):
    display_metrics(cmp)

if __name__ == "__main__":
    # progdir = "../progs/typecases/"
    cmp_ghidra, cmp_dwarf = test_compare_unoptimized_interactive()
    # compare_summary(cmp_ghidra, cmp_dwarf)
    metrics_summary(cmp_dwarf)
