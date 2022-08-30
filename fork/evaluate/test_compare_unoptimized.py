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

def test_compare_unoptimized(progdir, rebuild=False):
    dwarf_proginfo, ghidra_proginfo = build2(progdir, 0, rebuild=rebuild)

    dwarf = UnoptimizedProgramInfo(dwarf_proginfo)
    ghidra = UnoptimizedProgramInfo(ghidra_proginfo)

    comparison = UnoptimizedProgramInfoCompare2(ghidra, dwarf)
    return comparison

if __name__ == "__main__":
    progdir = "../progs/typecases/"
    cmp = test_compare_unoptimized(progdir, rebuild=False)
    print(cmp.show_summary())

    # cmp.get_left().get_proginfo().print_summary()

    # for fn, record in cmp.get_function_compare_record_map().items():
    #     if record.is_comparison():
    #         print("{} : {}".format(
    #             fn.get_function().get_name(),
    #             record.get_comparison())
    #         )

    # for varnode, record in cmp.get_global_compare_record_map().items():
    #     print("{} : {}".format(
    #         varnode.get_addr(),
    #         record.get_status_str()
    #     ))

    # zipper = OrderedZipper(
    #     cmp.get_left().get_unoptimized_functions().values(),
    #     cmp.get_right().get_unoptimized_functions().values(),
    #     key=lambda fn: fn.get_start_pc()
    # )

    # for item in zipper:
    #     if item.is_left():
    #         print("Left({})".format(item.get_value().get_start_pc()))
    #     elif item.is_right():
    #         print("Right({})".format(item.get_value().get_start_pc()))
    #     elif item.is_conflict():
    #         l, r = item.get_value()
    #         print("Conflict({}, {})".format(l.get_start_pc(), r.get_start_pc()))