from lang import *
from lang_address import *
from lang_datatype import *
from util import *

from build import *
from compare_unoptimized import *

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

def test_compare_unoptimized(dwarf_proginfo, ghidra_proginfo):
    dwarf = UnoptimizedProgramInfo(dwarf_proginfo)
    ghidra = UnoptimizedProgramInfo(ghidra_proginfo)

    comparison = UnoptimizedProgramInfoCompare2(ghidra, dwarf)
    print(comparison)

if __name__ == "__main__":
    progdir = "../progs/typecases/"
    dwarf_proginfo, ghidra_proginfo = build2(progdir, 0, rebuild=True)
    test_compare_unoptimized(dwarf_proginfo, ghidra_proginfo)