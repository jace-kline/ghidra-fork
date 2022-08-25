from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

# should comparison between primitive types use '==' (True) or 'rough_equal' (False)?
EXACT_MATCH: bool = True

class DataTypeCompareCode(object):
    # no valid comparison could be made
    NO_MATCH = 0

    # a "top-level" match
    MATCH = 1

    # left is a subset / member of right (possibly recursively) at given offset
    LEFT_SUBSET_RIGHT = 2

    # right is a subset / member of left (possibly recursively) at given offset
    RIGHT_SUBSET_LEFT = 3

    @staticmethod
    def to_string(code):
        _map = [
            "NO_MATCH",
            "MATCH",
            "LEFT_SUBSET_RIGHT",
            "RIGHT_SUBSET_LEFT"
        ]
        return _map[code]


# DataType object comparison between 2 objects
class DataTypeCompare2(object):
    def __init__(
        self,
        left: DataType,
        right: DataType,
        offset: int # offset from left start addr to right start addr
    ):
        self.left = left
        self.right = right

        # offset from left start addr to right start addr
        # if negative, indicates that right starts before left
        # == right var addr - left var addr
        self.offset = offset

        # initialize the descent and compare_code members to None
        self.left_descent = self.right_descent = None
        self.compare_code = DataTypeCompareCode.NO_MATCH

        # perform the comparison logic & compute the compare_code
        self._compare()

    # sets self.left_descent, self.right_descent, self.compare_code
    def _compare(self):
        # base case: offset == 0 and the types "match" at the top level
        if self.offset == 0 and self._match():
            self.compare_code = DataTypeCompareCode.MATCH
            return

        # compute left descent?
        elif (self.left_before_right() or self.start_aligned()) and self.left_bigger_right():
            self.left_descent = DataTypeRecursiveDescent.descend_find_type_at_offset_recursive(
                self.left,
                self.offset,
                match_type=self.right,
                exact_match=EXACT_MATCH
            )

            # if there is a descent found, the right is a subset type of the left type
            if self.left_descent:
                self.compare_code = DataTypeCompareCode.RIGHT_SUBSET_LEFT
                return

        # compute right descent?
        elif (self.right_before_left() or self.start_aligned()) and self.right_bigger_left():
            self.right_descent = DataTypeRecursiveDescent.descend_find_type_at_offset_recursive(
                self.right,
                self.offset,
                match_type=self.left,
                exact_match=EXACT_MATCH
            )

            # if there is a descent found, the right is a subset type of the left type
            if self.right_descent:
                self.compare_code = DataTypeCompareCode.LEFT_SUBSET_RIGHT
                return

        # default: no match
        self.compare_code = DataTypeCompareCode.NO_MATCH

    def _match(self):
        return self.left == self.right if EXACT_MATCH else self.left.rough_match(self.right)

    def top_level_match(self):
        return self.compare_code == DataTypeCompareCode.MATCH

    def left_subset_right(self):
        return self.compare_code == DataTypeCompareCode.LEFT_SUBSET_RIGHT

    def right_subset_left(self):
        return self.compare_code == DataTypeCompareCode.RIGHT_SUBSET_LEFT

    def any_match(self):
        return self.top_level_match() or self.left_subset_right() or self.right_subset_left()

    def no_match(self):
        return self.compare_code == DataTypeCompareCode.NO_MATCH or not self.any_match()

    def get_left(self) -> DataType:
        return self.left

    def get_right(self) -> DataType:
        return self.right

    def get_offset(self) -> int:
        return self.offset

    def get_left_descent(self) -> Union[DataTypeRecursiveDescent, None]:
        return self.left_descent

    def get_right_descent(self) -> Union[DataTypeRecursiveDescent, None]:
        return self.right_descent

    def same_metatype(self) -> bool:
        return self.get_left().get_metatype() == self.get_right().get_metatype()

    def start_aligned(self):
        return self.get_offset() == 0

    def right_before_left(self) -> bool:
        return self.get_offset() < 0

    def left_before_right(self) -> bool:
        return self.get_offset() > 0

    # right size - left size
    def get_size_diff(self) -> int:
        return self.get_right().get_size() - self.get_left().get_size()

    def same_size(self) -> bool:
        return self.get_size_diff() == 0

    def left_bigger_right(self) -> bool:
        return self.get_size_diff() < 0

    def right_bigger_left(self) -> bool:
        return self.get_size_diff() > 0

    def bytes_overlapped(self) -> int:
        return 0 if self.no_match() else min(self.left.get_size(), self.right.get_size())

    def flip(self):
        return __class__(self.right, self.left, -1 * self.offset)

    def __str__(self):
        return "<DataTypeCompare2 compare_code={} left={} right={} offset={} left_descent={} right_descent={}>".format(
            DataTypeCompareCode.to_string(self.compare_code),
            self.left,
            self.right,
            self.offset,
            self.left_descent,
            self.right_descent
        )

    def __repr__(self):
        return str(self)