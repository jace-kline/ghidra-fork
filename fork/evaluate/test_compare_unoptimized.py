from lang import *
from lang_address import *
from lang_datatype import *
from util import *
from compare_unoptimized import *

def test_compare_dtypes(left, right, offset, exact_match=False):
    # compare
    comparison = DataTypeCompare.Compare2(left, right, offset, exact_match=exact_match)
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

    test_compare_dtypes(left, right, 0, exact_match=True)

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

    test_compare_dtypes(left, right, 16, exact_match=True)

if __name__ == "__main__":
    test1()