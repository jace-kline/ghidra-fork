from typing import List, Union
from typing_extensions import Self
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

    def get_varnodes(self) -> List[VariableCompareNode]:
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

    def compare(self, other: Self) -> VariableCompare.Result:
        # compute the result - not effectful
        pass

    def get_var(self) -> Variable:
        return self.var

    def get_comparisons(self) -> List[VariableCompare.Result]:
        return self.comparisons
    
    def get_compare_result(self) -> VariableCompare.Result:
        # perform logic to interpret status from comparisons...
        # if not comparable, return NotComparable()
        # default: return NoMatch()
        pass

# namespace to enclose the variable comparison result and subclasses
# prevents collisions
class VariableCompare(object):

    class Compare2Code(object):
        NO_OVERLAP = 0
        MISALIGNED = 1
        ALIGNED = 2
        LEFT_CONTAINS_RIGHT = 3
        RIGHT_CONTAINS_LEFT = 4

    # the result of comparing 2 VariableCompareNodes
    # assume they are in the same address space (stack, absolute, etc.)
    class Compare2(object):
        def __init__(self, left: VariableCompareNode, right: VariableCompareNode):
            self.left = left
            self.right = right

            # compute the AddressRangeOverlap between the 2 vars
            self.overlap: Union[AddressRangeOverlap, None] = self.get_left().get_addr_range().get_overlap(self.get_right().get_addr_range())

            # compute offset from left start addr to right start addr
            # = right addr - left addr
            self.offset: Union[int, None] = self.right.get_addr() - self.left.get_addr() if self.does_overlap() else None

            # compare the data types, but only if...
            # overlap exists, offset exists, and overlap is not "misaligned"
            
            self.datatype_comparison: Union[DataTypeCompare.Compare2, None] = None
            if (self.overlap is not None) and (self.offset is not None) and (not self.overlap.misaligned()):
                self.datatype_comparison = DataTypeCompare.Compare2(self.left.get_datatype(), self.right.get_datatype(), self.offset)

            self.compare_code: int = self._compute_compare_code()

        def _compute_compare_code(self) -> int:
            if not self.does_overlap():
                return VariableCompare.Compare2Code.NO_OVERLAP
            elif self.is_misaligned():
                return VariableCompare.Compare2Code.MISALIGNED
            elif self.is_start_aligned():
                # look at datatype_comparison info
                pass

            else:
                # possibly a subtype / supertype
                pass

            # TODO: finish this function - requires DataTypeCompare.Compare2

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
        def flip(self) -> Self:
            return __class__(self.get_right(), self.get_left())

    # the main logic to compute a comparison between 2 VariableCompareNode objects
    # not effectful -> does not modify internal states of
    @staticmethod
    def compare2(left: VariableCompareNode, right: VariableCompareNode) -> Compare2Result:

        # given l that contains r, compute the correct Compare2Result variant
        def _contains_helper(l: VariableCompareNode, r: VariableCompareNode) -> Compare2Result:
            # offset from left to right range start
            offset = r.get_addr() - l.get_addr()
            
            # try to find sub-component of left var that matches right var
            descent = DataTypeRecursiveDescent.descend_find_type_at_offset_recursive(l.get_datatype(), offset, size=r.get_size())
            if descent:
                return VariableCompare.OverlapContains(l, r, descent)

            return VariableCompare.OverlapAligned(l, r) if offset == 0 else VariableCompare.OverlapMisaligned(l, r)

        # if either node isn't comparable, there's no overlap
        if not (left.is_comparable() and right.is_comparable()):
            return VariableCompare.NoOverlap(left, right)

        left_addr_range = left.get_addr_range()
        right_addr_range = right.get_addr_range()
        overlap = left_addr_range.get_overlap(right_addr_range)

        if overlap.disjoint():
            return VariableCompare.NoOverlap(left, right)

        elif overlap.ranges_equal():
            return VariableCompare.OverlapAligned(left, right)

        elif overlap.left_contains_right():
            return _contains_helper(left, right)

        elif overlap.right_contains_left():
            return _contains_helper(right, left).flip()

        else:
            return VariableCompare.OverlapMisaligned(left, right)

class DataTypeCompare:
    class CompareCode(object):
        # no valid comparison could be made
        NO_MATCH = 0

        # same metatype, offset = 0, maybe different sizes
        MATCH = 1

        # left is a subset / member of right (possibly recursively) at given offset
        LEFT_SUBSET_RIGHT = 2

        # right is a subset / member of left (possibly recursively) at given offset
        RIGHT_SUBSET_LEFT = 3


    # DataType object comparison between 2 objects
    class Compare2(object):
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
            self.offset = offset

            # check offset and sizes for misalignment
            # is this necessary though? recursive descent should catch this

            # try to compute DataTypeRecursiveDescent if one contains the other

            # compute code given prior information

        def flip(self) -> Self:
            pass

        # TODO : create subtypes


    @staticmethod
    def compare2(left: DataType, right: DataType):
        pass