from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from compare_datatype import *
from util import *

# a Variable associated with a particular Address
# could be useful to work with a Variable as it is instantiated
# at a given PC, or an unoptimized variable with a single location
class Varnode(object):
    def __init__(self, var: Variable, addr: Address):
        self.var = var
        self.addr = addr

    def get_var(self) -> Variable:
        return self.var

    def get_addr(self) -> Address:
        return self.addr

    def get_addr_range(self) -> AddressRange:
        return AddressRange(self.addr, size=self.get_datatype().get_size())

    def get_datatype(self) -> DataType:
        return self.var.get_datatype()

    # builds a VarnodeCompareRecord|None from the infomation contained in the
    # given variable. Only builds if the variable is associated with exactly one address.
    @staticmethod
    def from_single_location_variable(var: Variable):
        liveranges = var.get_liveranges()
        return __class__(var, liveranges[0].get_addr()) if liveranges and len(liveranges) == 1 else None

    @staticmethod
    def from_variable_at_pc(var: Variable, pc: AbsoluteAddress):
        addr = var.get_address_at_pc(pc)
        return Varnode(var, addr) if addr is not None else None

    def __hash__(self) -> int:
        return hash((self.var, self.addr))


class VarnodeCompare2Code(object):
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

# the result of comparing 2 VarnodeCompareRecords
# assume they are in the same address space (stack, absolute, etc.)
class VarnodeCompare2(object):
    def __init__(self,
        left: Varnode,
        right: Varnode,
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
        
        self.datatype_comparison: Union[DataTypeCompare2, None] = None
        if (self.overlap is not None) and (self.offset is not None) and (not self.overlap.misaligned()):
            self.datatype_comparison = DataTypeCompare2(
                self.left.get_datatype(),
                self.right.get_datatype(),
                self.offset,
                exact_match=self.exact_match
            )

        self.compare_code: int = self._compute_compare_code()

    def _compute_compare_code(self) -> int:
        code = VarnodeCompare2Code.NO_OVERLAP
        
        if not self.does_overlap():
            code = VarnodeCompare2Code.NO_OVERLAP
        elif self.is_misaligned():
            code = VarnodeCompare2Code.MISALIGNED
        elif self.start_aligned():
            code = VarnodeCompare2Code.ALIGNED


        if self.datatype_comparison: # assume we performed a DataType comparison
            if self.datatype_comparison.top_level_match():
                code = VarnodeCompare2Code.MATCH
            elif self.datatype_comparison.right_subset_left():
                code = VarnodeCompare2Code.LEFT_CONTAINS_RIGHT
            elif self.datatype_comparison.left_subset_right():
                code = VarnodeCompare2Code.RIGHT_CONTAINS_LEFT

        return code

    # right.get_addr() - left.get_addr()
    def get_offset(self) -> Union[int, None]:
        return self.offset

    def does_overlap(self) -> bool:
        return self.get_overlap() is not None

    def is_misaligned(self) -> bool:
        return self.does_overlap() and self.overlap.misaligned()

    def get_left(self) -> Varnode:
        return self.left

    def get_right(self) -> Varnode:
        return self.right

    def get_overlap(self) -> Union[AddressRangeOverlap, None]:
        return self.overlap

    def bytes_overlapped(self) -> int:
        overlap = self.get_overlap()
        return overlap.bytes_overlapped() if overlap else 0

    # Take this comparison and "flip" it so the left and right are switched
    def flip(self):
        return __class__(self.get_right(), self.get_left())


class VarnodeCompareStatus(object):
    NOT_COMPARABLE = 0 # this varnode cannot be compared with others (due to its address most likely)
    NO_MATCH = 1 # this varnode does not overlap with any others
    MISALIGNED = 2 # start not aligned, types not matched with 1 varnode
    ALIGNED = 3 # start aligned, same size, types not matched with 1 varnode
    MATCH = 4 # start aligned, same size, types match with 1 varnode
    CONTAINS = 5 # right matches a subset of left
    CONTAINED = 6 # left matches a subset of right
    OVERLAPS_MANY = 7 # this varnode overlaps >1 varnodes from other set

    @staticmethod
    def to_string(code):
        _map = [
            "NOT_COMPARABLE",
            "NO_MATCH",
            "MISALIGNED",
            "ALIGNED",
            "MATCH",
            "CONTAINS",
            "CONTAINED",
            "OVERLAPS_MANY"
        ]
        return _map[code]

# wraps a Varnode object (Variable at a single Address)
# collects comparisons made between this varnode and others, and exposes
# methods for sharing information about those comparisons & status overall
class VarnodeCompareRecord(object):
    def __init__(self,
        varnode: Varnode
    ):
        self.varnode: Varnode = varnode

        # references to all the comparisons this variable is involved in
        # this varnode is always the "left" varnode in these comparisons
        self.comparisons: List[VarnodeCompare2] = []

        # set the default status to NO_MATCH or NOT_COMPARABLE, depending on address type
        self.status: int = VarnodeCompareStatus.NO_MATCH if self.is_comparable() else VarnodeCompareStatus.NOT_COMPARABLE

    # fold over the comparisons, update and return status
    def update_status():
        pass

    def is_comparable(self) -> bool:
        # does addr exist AND addrtype == STACK | ABSOLUTE?
        addr = self.get_addr()
        return addr and addr.get_addrtype() in [AddressType.ABSOLUTE, AddressType.STACK]

    def get_varnode(self) -> Varnode:
        return self.varnode

    def get_var(self) -> Variable:
        return self.varnode.get_var()

    def get_datatype(self) -> DataType:
        return self.get_var().get_datatype()

    def get_addr(self) -> Union[Address, None]:
        return self.varnode.get_addr()
    
    def get_addr_range(self) -> Union[AddressRange, None]:
        addr = self.get_addr()
        size = self.get_datatype().get_size()
        return AddressRange(addr, size=size) if addr and size else None

    def add_comparison(self, compare2: VarnodeCompare2):
        # add the Compare2 object to self.comparisons
        # verify that the &compare2.left == &self.varnode
        assert(compare2.get_left() is self.get_varnode())
        self.comparisons.append(compare2)

    def get_comparisons(self):
        return self.comparisons
