from lang import *
from lang_address import *
from lang_datatype import *
from compare_optimized import *
from util import *
from build import *

# test the descent of dtype0, looking for dtype1 equivalent
def test_DataTypeRecursiveDescent(dtype0, dtype1, offset, exact_match=False):
    descent = DataTypeRecursiveDescent.descend_find_type_at_offset_recursive(
        dtype0,
        offset,
        match_type=dtype1,
        exact_match=exact_match
    )

    if not descent:
        print("No Descent")
    else:
        print(descent)
        path = descent.get_path()
        if len(path) > 0:
            print("Total offset = {}".format(descent.get_total_offset()))
            print("Descent path:")
            for record in path:
                print("\t{}".format(record))

# Test the get_component_type_at_offset() and get_component_type_containing_offset() methods
# when given a list of offsets.
# Specify size to restrict size for get_component_type_at_offset() method.
def test_at_containing_offset(dtype0, offsets, size=None):
    for offset in offsets:
        at_offset = dtype0.get_component_type_at_offset(offset, size=size)
        containing_offset = dtype0.get_component_type_containing_offset(offset)

        print("@ offset = {}:".format(offset))
        print("\tat = {}".format(at_offset))
        print("\tcontaining = {}".format(containing_offset))


def test0():
    # create 2 DataTypes & compute descent

    i = DataTypeInt(size=4, signed=False)
    j = DataTypeInt(size=4, signed=False)

    test_DataTypeRecursiveDescent(i, j, 0, exact_match=False)

def test1():
    # create 2 DataTypes & compute descent

    dtype0 = DataTypeArray(
        basetype=DataTypeInt(size=4),
        length=10
    )

    dtype1 = DataTypeInt(size=4)
    offset = 8

    test_DataTypeRecursiveDescent(dtype0, dtype1, offset, exact_match=True)

def test2(offset=0):
    # create 2 DataTypes & compute descent

    dtype0 = DataTypeArray(
        basetype=DataTypeStruct(
            name="mystruct",
            membertypes=[
                DataTypeInt(size=4),
                DataTypeInt(size=4)
            ]
        ),
        length=10
    )
    # print(dtype0)

    dtype1 = DataTypeInt(size=4)

    test_DataTypeRecursiveDescent(dtype0, dtype1, offset, exact_match=True)

def test3(offset=0):
    # create 2 DataTypes & compute descent

    dtype0 = DataTypeStruct(
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

    dtype1 = DataTypeInt(size=4)

    test_DataTypeRecursiveDescent(dtype0, dtype1, offset, exact_match=True)

def test4():
    dtype0 = DataTypeStruct(
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

    offsets = range(0, dtype0.get_size())
    test_at_containing_offset(dtype0, offsets, size=4)

def test5():
    dtype0 = DataTypeArray(
        basetype=DataTypeStruct(
            name="mystruct",
            membertypes=[
                DataTypeInt(size=4),
                DataTypeInt(size=4)
            ]
        ),
        length=10
    )
    offsets = range(0, 20)
    test_at_containing_offset(dtype0, offsets, size=8)

def test6(offset=0):
    dtype0 = DataTypeUnion(
        name="myunion",
        membertypes=[
            DataTypeInt(size=4),
            DataTypeFloat(size=8),
            DataTypeArray(
                basetype=DataTypeStruct(
                    name="mystruct",
                    membertypes=[
                        DataTypeInt(size=4),
                        DataTypePointer(basetype=DataTypeInt(size=4), size=8)
                    ]
                ),
                length=10
            )
        ]
    )

    dtype1 = DataTypePointer(basetype=DataTypeInt(size=4), size=8)
    test_DataTypeRecursiveDescent(dtype0, dtype1, offset, exact_match=True)

def test7():
    dtype0 = DataTypeUnion(
        name="myunion",
        membertypes=[
            DataTypeInt(size=4),
            DataTypeFloat(size=8),
            DataTypeArray(
                basetype=DataTypeStruct(
                    name="mystruct",
                    membertypes=[
                        DataTypeInt(size=4),
                        DataTypePointer(basetype=DataTypeInt(size=4), size=8)
                    ]
                ),
                length=10
            )
        ]
    )

    dtype1 = DataTypeUnion(
        name="myunion",
        membertypes=[
            DataTypeInt(size=4),
            DataTypeFloat(size=8),
            DataTypeArray(
                basetype=DataTypeStruct(
                    name="mystruct",
                    membertypes=[
                        DataTypeInt(size=4),
                        DataTypePointer(basetype=DataTypeInt(size=4), size=8)
                    ]
                ),
                length=10
            )
        ]
    )

    assert (dtype0 == dtype1)

def test_recursive_eq():
    dtype0 = DataTypeStruct(
        name="mystruct",
        membertypes=[
            DataTypeInt(size=8, signed=True),
            DataTypePointer(
                basetype=None,
                size=8
            )
        ]
    )

    dtype0.membertypes[1].basetype = dtype0

    dtype1 = DataTypeStruct(
        name="mystruct",
        membertypes=[
            DataTypeInt(size=8, signed=True),
            DataTypePointer(
                basetype=None,
                size=8
            )
        ]
    )

    dtype1.membertypes[1].basetype = dtype1

    print(dtype0 == dtype1)
    print(hash(dtype0))
    print(hash(dtype1))
    print(dtype0)

def test_flatten():
    from build import build_dwarf
    proginfo: ProgramInfo = build_dwarf("../progs/typecases", rebuild=True)

    def print_flattened_vars(vars):
        for var in vars:
            dtype = var.get_datatype()
            print(dtype)
            # if dtype.get_metatype() == MetaType.STRUCT:
            #     print(dtype.membertype_offsets)
            for (off, primitive) in dtype.flatten():
                print("\t{} -> {}".format(off, primitive))

    for fn in proginfo.get_functions():
        print_flattened_vars(fn.get_params() + fn.get_vars())

if __name__ == "__main__":
    test_flatten()