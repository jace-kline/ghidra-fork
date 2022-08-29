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
        return AddressRange(self.addr, size=self.get_size())

    def get_datatype(self) -> DataType:
        return self.var.get_datatype()

    def get_size(self) -> int:
        return self.get_datatype().get_size()

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
    OVERLAP = 1 # start not aligned, types not matched
    ALIGNED = 2 # start aligned, same size, types not matched
    MATCH = 3 # start aligned, same size, types match
    LEFT_CONTAINS_RIGHT = 4 # right matches a subset of left
    RIGHT_CONTAINS_LEFT = 5 # left matches a subset of right

    @staticmethod
    def to_string(code):
        _map = [
            "NO_OVERLAP",
            "OVERLAP",
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
        right: Varnode
    ):
        self.left = left
        self.right = right

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
                self.offset
            )

        self.compare_code: int = self._compute_compare_code()

    def _compute_compare_code(self) -> int:
        code = VarnodeCompare2Code.NO_OVERLAP
        
        if not self.does_overlap():
            code = VarnodeCompare2Code.NO_OVERLAP
        elif self.is_aligned(): # same size & start addr
            code = VarnodeCompare2Code.ALIGNED
        else:
            code = VarnodeCompare2Code.OVERLAP


        if self.does_overlap() and self.datatype_comparison is not None: # assume we performed a DataType comparison
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

    def get_left(self) -> Varnode:
        return self.left

    def get_right(self) -> Varnode:
        return self.right

    def get_overlap(self) -> Union[AddressRangeOverlap, None]:
        return self.overlap

    def get_compare_code(self) -> int:
        return self.compare_code

    def get_compare_code_str(self) -> str:
        return VarnodeCompare2Code.to_string(self.compare_code)

    # same start addr?
    def is_start_aligned(self) -> bool:
        return self.overlap.start_aligned()

    # left size == right size
    def is_same_size(self) -> bool:
        return self.left.get_size() == self.right.get_size()

    # same start addr & same size
    def is_aligned(self) -> bool:
        return self.is_start_aligned() and self.is_same_size()

    # overlap, but start addrs don't align and the one that starts later extends past the end of the other
    def is_misaligned(self) -> bool:
        return self.overlap.misaligned()

    def bytes_overlapped(self) -> int:
        overlap = self.get_overlap()
        return overlap.bytes_overlapped() if overlap else 0

    def __hash__(self) -> int:
        return hash((self.left, self.right))

class VarnodeCompareStatus(object):
    NOT_COMPARABLE = 0 # this varnode cannot be compared with others (due to its address most likely)
    NO_MATCH = 1 # this varnode does not overlap with any others
    OVERLAP = 2 # not precisely aligned, types not matched with 1 varnode.
    ALIGNED = 3 # start aligned, same size, types not matched with 1 varnode
    MATCH = 4 # start aligned, same size, types match with 1 varnode
    CONTAINS = 5 # right matches a subset of left
    CONTAINS_MANY = 6 # multiple vars are contained within this var & align as subvars
    CONTAINED = 7 # left matches a subset of right
    OVERLAP_MANY = 8 # this varnode overlaps >1 varnodes from other set

    @staticmethod
    def to_string(code):
        _map = [
            "NOT_COMPARABLE",
            "NO_MATCH",
            "OVERLAP",
            "ALIGNED",
            "MATCH",
            "CONTAINS",
            "CONTAINS_MANY",
            "CONTAINED",
            "OVERLAP_MANY"
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
        self.comparisons: dict[Varnode, VarnodeCompare2] = {}

        # set the default status to NO_MATCH or NOT_COMPARABLE, depending on address type
        self.status: int = VarnodeCompareStatus.NO_MATCH if self.is_comparable() else VarnodeCompareStatus.NOT_COMPARABLE

    # compute new status given a new comparison
    def _update_status(self, compare2: VarnodeCompare2):
        # valid transitions...
        # NO_MATCH -> * (except for NOT_COMPARABLE)
        # CONTAINS -> CONTAINS_MANY | OVERLAP_MANY
        # CONTAINS_MANY -> CONTAINS_MANY | OVERLAP_MANY
        # OVERLAP -> OVERLAP_MANY
        # OVERLAP_MANY -> OVERLAP_MANY
        code = compare2.get_compare_code()
        if self.status == VarnodeCompareStatus.NO_MATCH:
            if code == VarnodeCompare2Code.OVERLAP:
                self.status = VarnodeCompareStatus.OVERLAP
            elif code == VarnodeCompare2Code.ALIGNED:
                self.status = VarnodeCompareStatus.ALIGNED
            elif code == VarnodeCompare2Code.MATCH:
                self.status = VarnodeCompareStatus.MATCH
            elif code == VarnodeCompare2Code.LEFT_CONTAINS_RIGHT:
                self.status = VarnodeCompareStatus.CONTAINS
            elif code == VarnodeCompare2Code.RIGHT_CONTAINS_LEFT:
                self.status = VarnodeCompareStatus.CONTAINED

        elif self.status in (VarnodeCompareStatus.CONTAINS, VarnodeCompareStatus.CONTAINS_MANY):
            if code == VarnodeCompare2Code.OVERLAP:
                self.status = VarnodeCompareStatus.OVERLAP_MANY
            elif code == VarnodeCompare2Code.LEFT_CONTAINS_RIGHT:
                self.status = VarnodeCompareStatus.CONTAINS_MANY

        elif self.status in (VarnodeCompareStatus.OVERLAP, VarnodeCompareStatus.OVERLAP_MANY):
            if code in (VarnodeCompare2Code.OVERLAP, VarnodeCompare2Code.LEFT_CONTAINS_RIGHT):
                self.status = VarnodeCompareStatus.OVERLAP_MANY

        else:
            raise Exception(
                "Error: The transition from VarnodeCompareStatus={} with VarnodeCompare2Code={} should not occur"
                .format(VarnodeCompareStatus.to_string(self.status), VarnodeCompare2Code.to_string(code))
            )
    
    def get_status(self) -> int:
        return self.status

    def get_status_str(self) -> str:
        return VarnodeCompareStatus.to_string(self.status)

    def is_comparable(self) -> bool:
        # does addr exist AND the region
        addr = self.varnode.get_addr()
        return addr.get_region().is_range()

    def does_overlap(self) -> bool:
        _cls = VarnodeCompareStatus
        return self.status not in (_cls.NOT_COMPARABLE, _cls.NO_MATCH)

    def exact_match(self) -> bool:
        _cls = VarnodeCompareStatus
        return self.status == _cls.MATCH

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
        # ensure this varnode we are comparing against hasn't already
        # been inserted
        if compare2.get_right() not in self.comparisons:
            self.comparisons[compare2.get_right()] = compare2
            self._update_status(compare2)

    def get_compared_varnodes(self):
        return self.comparisons.keys()

    def get_comparisons(self) -> 'dict[Varnode, VarnodeCompare2]':
        return self.comparisons

    def bytes_overlapped(self):
        return sum([ cmp.bytes_overlapped() for cmp in self.comparisons.values() ])
