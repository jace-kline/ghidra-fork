from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

class ProgramInfoCompareNode(object):
    def __init__(self, proginfo: ProgramInfo, truth: bool = True):
        self.proginfo: ProgramInfo = proginfo
        self.truth: bool = truth # is this program info considered the "truth"?

    def is_truth(self) -> bool:
        return self.truth

    def get_proginfo(self) -> ProgramInfo:
        return self.proginfo

# a node that wraps a set of VariableCompareNode objects for comparison
# could be a global scope or function scope
class VariableScopeCompareNode(object):
    def __init__(self, vars: List[Variable], parent: ProgramInfoCompareNode):
        self.varnodes: List[VariableCompareNode] = [ VariableCompareNode(var) for var in vars ]
        self.parent = parent

    def get_varnodes(self):
        return self.varnodes

    def get_parent(self) -> ProgramInfoCompareNode:
        return self.parent

    def is_truth(self) -> bool:
        return self.get_parent().is_truth()

class FunctionCompareNode(VariableScopeCompareNode):
    def __init__(self, function: Function, parent: ProgramInfoCompareNode):
        self.function: Function = function
        super(__class__, self).__init__(self.function.get_vars(), parent)

    def get_function(self) -> Function:
        return self.function

# wraps a Variable object
# exposes methods for comparing this Variable with variable(s) of another set
class VariableCompareNode(object):
    def __init__(self, var: Variable, parent: VariableScopeCompareNode):
        self.var: Variable = var
        # references to all the comparisons this variable is involved in
        self.comparisons: List[VariableCompare.Result] = []
        self.parent = parent

    def is_truth(self):
        return self.parent.is_truth()

    def is_comparable(self) -> bool:
        # does addr exist AND addrtype == STACK | ABSOLUTE?
        addr = self.get_addr()
        return addr and addr.get_addrtype() in [AddressType.ABSOLUTE, AddressType.STACK]

    def get_datatype(self) -> DataType:
        return self.get_var().get_datatype()

    def get_addr(self) -> Union[Address, None]:
        # for unoptimized code, we assume there is only 1 location associated with each var
        # we assume the var exists for the duration of the parent scope's lifetime
        liveranges = self.get_var().get_liveranges()
        return liveranges[0].get_addr() if liveranges and len(liveranges) == 1 else None
    
    def get_addr_range(self) -> Union[AddressRange, None]:
        addr = self.get_addr()
        size = self.get_datatype().get_size()
        return AddressRange(addr, size=size) if addr and size else None

    def compare(self, other):
        # compute the result - not effectful
        pass

    def get_var(self) -> Variable:
        return self.var

    def get_comparisons(self):
        return self.comparisons
    
    def get_compare_result(self):
        # perform logic to interpret status from comparisons...
        # if not comparable, return NotComparable()
        # default: return NoMatch()
        pass

# namespace to enclose the variable comparison result and subclasses
# prevents collisions
class VariableCompare(object):

    class Compare2Code(object):
        NO_OVERLAP = 0 # variables do not overlap at all
        MISALIGNED = 1 # start not aligned, types not matched
        ALIGNED = 2 # start aligned, types not matched
        MATCH = 3 # start aligned, same size, types match
        LEFT_CONTAINS_RIGHT = 4 # right matches a subset of left
        RIGHT_CONTAINS_LEFT = 5 # left matches a subset of right

        @staticmethod
        def to_string(code):
            _map = [
                "NO_OVERLAP",
                "MISALIGNED",
                "ALIGNED",
                "MATCH",
                "LEFT_CONTAINS_RIGHT",
                "RIGHT_CONTAINS_LEFT"
            ]
            return _map[code]

    # the result of comparing 2 VariableCompareNodes
    # assume they are in the same address space (stack, absolute, etc.)
    class Compare2(object):
        def __init__(self,
            left: VariableCompareNode,
            right: VariableCompareNode,
            exact_match: bool = False # compare variable types & sizes exactly?
        ):
            self.left = left
            self.right = right
            self.exact_match = exact_match

            # compute the AddressRangeOverlap between the 2 vars
            self.overlap: Union[AddressRangeOverlap, None] = self.get_left().get_addr_range().get_overlap(self.get_right().get_addr_range())

            # compute offset from left start addr to right start addr
            # = right addr - left addr
            self.offset: Union[int, None] = self.right.get_addr() - self.left.get_addr() if self.does_overlap() else None

            # compare the data types, but only if...
            # overlap exists, offset exists, and overlap is not "misaligned"
            
            self.datatype_comparison: Union[DataTypeCompare.Compare2, None] = None
            if (self.overlap is not None) and (self.offset is not None) and (not self.overlap.misaligned()):
                self.datatype_comparison = DataTypeCompare.Compare2(
                    self.left.get_datatype(),
                    self.right.get_datatype(),
                    self.offset,
                    exact_match=self.exact_match
                )

            self.compare_code: int = self._compute_compare_code()

        def _compute_compare_code(self) -> int:
            code = VariableCompare.Compare2Code.NO_OVERLAP
            
            if not self.does_overlap():
                code = VariableCompare.Compare2Code.NO_OVERLAP
            elif self.is_misaligned():
                code = VariableCompare.Compare2Code.MISALIGNED
            elif self.start_aligned():
                code = VariableCompare.Compare2Code.ALIGNED


            if self.datatype_comparison: # assume we performed a DataType comparison
                if self.datatype_comparison.top_level_match():
                    code = VariableCompare.Compare2Code.MATCH
                elif self.datatype_comparison.right_subset_left():
                    code = VariableCompare.Compare2Code.LEFT_CONTAINS_RIGHT
                elif self.datatype_comparison.left_subset_right():
                    code = VariableCompare.Compare2Code.RIGHT_CONTAINS_LEFT

            return code

        # right.get_addr() - left.get_addr()
        def get_offset(self) -> Union[int, None]:
            return self.offset

        def does_overlap(self) -> bool:
            return self.get_overlap() is not None

        def is_misaligned(self) -> bool:
            return self.does_overlap() and self.overlap.misaligned()

        def get_left(self) -> VariableCompareNode:
            return self.left

        def get_right(self) -> VariableCompareNode:
            return self.right

        def get_overlap(self) -> Union[AddressRangeOverlap, None]:
            return self.overlap

        def bytes_overlapped(self) -> int:
            overlap = self.get_overlap()
            return overlap.bytes_overlapped() if overlap else 0

        # Take this comparison and "flip" it so the left and right are switched
        def flip(self):
            return __class__(self.get_right(), self.get_left())

class DataTypeCompare(object):
    class CompareCode(object):
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
    class Compare2(object):
        def __init__(
            self,
            left: DataType,
            right: DataType,
            offset: int, # offset from left start addr to right start addr
            exact_match: bool = False # should we use '==' to compare?
        ):
            self.left = left
            self.right = right

            # offset from left start addr to right start addr
            # if negative, indicates that right starts before left
            # == right var addr - left var addr
            self.offset = offset

            # should we use '==' or 'rough_match()' to compare?
            self.exact_match = exact_match

            # initialize the descent and compare_code members to None
            self.left_descent = self.right_descent = None
            self.compare_code = DataTypeCompare.CompareCode.NO_MATCH

            # perform the comparison logic & compute the compare_code
            self._compare()

        # sets self.left_descent, self.right_descent, self.compare_code
        def _compare(self):
            # base case: offset == 0 and the types "match" at the top level
            if self.offset == 0 and self._match():
                self.compare_code = DataTypeCompare.CompareCode.MATCH
                return

            # compute left descent?
            elif (self.left_before_right() or self.start_aligned()) and self.left_bigger_right():
                self.left_descent = DataTypeRecursiveDescent.descend_find_type_at_offset_recursive(
                    self.left,
                    self.offset,
                    match_type=self.right,
                    exact_match=self.exact_match
                )

                # if there is a descent found, the right is a subset type of the left type
                if self.left_descent:
                    self.compare_code = DataTypeCompare.CompareCode.RIGHT_SUBSET_LEFT
                    return

            # compute right descent?
            elif (self.right_before_left() or self.start_aligned()) and self.right_bigger_left():
                self.right_descent = DataTypeRecursiveDescent.descend_find_type_at_offset_recursive(
                    self.right,
                    self.offset,
                    match_type=self.left,
                    exact_match=self.exact_match
                )

                # if there is a descent found, the right is a subset type of the left type
                if self.right_descent:
                    self.compare_code = DataTypeCompare.CompareCode.LEFT_SUBSET_RIGHT
                    return

            # default: no match
            self.compare_code = DataTypeCompare.CompareCode.NO_MATCH

        def _match(self):
            return self.left == self.right if self.exact_match else self.left.rough_match(self.right)

        def top_level_match(self):
            return self.compare_code == DataTypeCompare.CompareCode.MATCH

        def left_subset_right(self):
            return self.compare_code == DataTypeCompare.CompareCode.LEFT_SUBSET_RIGHT

        def right_subset_left(self):
            return self.compare_code == DataTypeCompare.CompareCode.RIGHT_SUBSET_LEFT

        def any_match(self):
            return self.top_level_match() or self.left_subset_right() or self.right_subset_left()

        def no_match(self):
            return self.compare_code == DataTypeCompare.CompareCode.NO_MATCH or not self.any_match()

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
            pass

        def __str__(self):
            return "<DataTypeCompare.Compare2 compare_code={} left={} right={} offset={} left_descent={} right_descent={}>".format(
                DataTypeCompare.CompareCode.to_string(self.compare_code),
                self.left,
                self.right,
                self.offset,
                self.left_descent,
                self.right_descent
            )

        def __repr__(self):
            return str(self)


    @staticmethod
    def compare2(left: DataType, right: DataType):
        pass