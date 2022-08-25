from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

from compare_variable import *

def make_address_space(region: AddressRegion, varnodes: List[Varnode]) -> 'ConstPCAddressSpace':
    _cls = ConstPCAddressSpaceRangeable if region.is_range() else ConstPCAddressSpace
    return _cls(region, varnodes)

# represents a "snapshot"/set of variables at a given PC during the program
# allows us to compare memory regions, etc. for variables at a given PC
class ConstPCVariableSetSnapshot(object):
    def __init__(self, varnodes: List[Varnode]):
        self.varnodes = tuple(varnodes)

        # partition Varnodes into address spaces based on their address regions
        self.spaces: dict[AddressRegion, ConstPCAddressSpace] = self._partition_spaces()

    def _partition_spaces(self) -> 'List[ConstPCAddressSpace]':
        # collect Varnodes for each AddressRegion
        _map: dict[AddressRegion, List[Varnode]] = {}

        for varnode in self.varnodes:
            region = varnode.get_addr().get_region()
            if region in _map:
                _map[region].append(varnode)
            else:
                _map[region] = [varnode]

        # construct the ConstPCAddressSpace objects for each
        return dict([ (region, make_address_space(region, varnodes)) for (region, varnodes) in _map.items() ])

    def get_varnodes(self) -> List[Varnode]:
        return self.varnodes

    def get_address_spaces(self) -> 'dict[AddressRegion, ConstPCAddressSpace]':
        return self.spaces

    # returns the correct ConstPCAddressSpace based on the AddressRegion key (or None)
    def get_address_space(self, region: AddressRegion) -> 'Union[ConstPCAddressSpace, None]':
        return self.spaces.get(region, None)

# compares 2 sets of variables representing a certain "scope" in the program (constant PC)
# this could mean a point in a function or the global scope
class ConstPCVariableSetSnapshotCompare2(object):
    def __init__(self,
        left: ConstPCVariableSetSnapshot,
        right: ConstPCVariableSetSnapshot
    ):
        self.left = left
        self.right = right

        # match left address spaces with right address spaces based on region
        # if there is a region that doesn't match, create empty space to compare with
        self.space_comparisons: dict[AddressRegion, ConstPCAddressSpaceCompare2] = self._compare_spaces()

    def _compare_spaces(self):
        
        _map: dict[AddressRegion, ConstPCAddressSpaceCompare2] = {}

        for region, left_space in self.left.get_address_spaces().items():
            right_space = self.right.get_address_space(region)
            right_space = right_space if right_space is not None else make_address_space(region, [])
            comparison = ConstPCAddressSpaceCompare2(left_space, right_space)
            _map[region] = comparison

        for region, right_space in self.right.get_address_spaces().items():
            if region not in _map:
                left_space = make_address_space(region, [])
                comparison = ConstPCAddressSpaceCompare2(left_space, right_space)
                _map[region] = comparison

        return _map

    def get_left(self) -> ConstPCVariableSetSnapshot:
        return self.left

    def get_right(self) -> ConstPCVariableSetSnapshot:
        return self.right

    def flip(self) -> 'ConstPCVariableSetSnapshotCompare2':
        return __class__(self.right, self.left)

    def bytes_overlapped(self) -> int:
        return sum([ cmp.bytes_overlapped() for cmp in self.space_comparisons.values() ])

    # map each Varnode in left to its associated VarnodeCompareRecord
    def get_left_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        _map = {}
        for region, compare2 in self.space_comparisons.items():
            _map.update(compare2.get_left_varnode_compare_records())
        return _map

    # map each Varnode in right to its associated VarnodeCompareRecord
    def get_right_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        _map = {}
        for region, compare2 in self.space_comparisons.items():
            _map.update(compare2.get_right_varnode_compare_records())
        return _map

    def make_left_compare_record(self) -> 'ConstPCVariableSetSnapshotCompareRecord':
        return ConstPCVariableSetSnapshotCompareRecord(self.left, self)

    def make_right_compare_record(self) -> 'ConstPCVariableSetSnapshotCompareRecord':
        return self.flip().make_left_compare_record()

class ConstPCVariableSetSnapshotCompareRecord(object):
    def __init__(self,
        varset: ConstPCVariableSetSnapshot,
        comparison: ConstPCVariableSetSnapshotCompare2
    ):
        self.varset = varset
        self.comparison = comparison

        assert( self.varset is self.comparison.get_left() )

    def get_varset(self) -> ConstPCVariableSetSnapshot:
        return self.varset

    def get_comparison(self) -> ConstPCVariableSetSnapshotCompare2:
        return self.comparison

    def get_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        return self.comparison.get_left_varnode_compare_records()

    def bytes_overlapped(self) -> int:
        return self.comparison.bytes_overlapped()


# associates an AddressRegion (group of 0+ addresses) with the varnodes that occupy it for a particular PC in the program
class ConstPCAddressSpace(object):
    def __init__(self,
        region: AddressRegion, # determines the region of addresses occupied by this space
        varnodes: List[Varnode] # the list of varnodes within the region
    ):
        self.region = region
        self.varnodes = tuple(varnodes)

        for varnode in self.varnodes:
            self._verify_region(varnode)

    def _verify_region(self, varnode: Varnode):
        assert( varnode.get_addr().get_region() == self.region )

    def get_region(self) -> AddressRegion:
        return self.region

    # is this address space "rangeable" / can the addresses be ordered?
    # by default, return False
    def rangeable(self):
        return self.region.is_range()

    # can this space be compared to another?
    def comparable(self):
        return self.rangeable()

    # by default, no comparison pairs can be formed
    def get_comparison_pairs(self, other: 'ConstPCAddressSpace') -> 'List[ConstPCAddressSpace]':
        return []

# holds an ordered list of Varnode objects of the same Address type
# the address space type must be orderable/rangeable
class ConstPCAddressSpaceRangeable(ConstPCAddressSpace):
    def __init__(self, addrtype: int, varnodes: List[Varnode]):
        # ensure the given address type is "rangeable"
        assert( AddressType.rangeable(addrtype) )

        # instantiate parent
        super(__class__, self).__init__(addrtype, varnodes)

        # sort the passed varnodes (ascending) by address
        self.varnodes = sorted(varnodes, key=lambda v: v.get_addr())

    def rangeable(self):
        return True

    def comparable(self):
        return True

    def get_addrtype(self):
        return self.addrtype

    def get_varnodes(self):
        return self.varnodes

    def get_comparison_pairs(self, other: 'ConstPCAddressSpaceRangeable') -> 'List[ConstPCAddressSpaceRangeable]':
        # create iterator the "merges" the 2 address spaces
        zipper = OrderedZipper(
            self.get_varnodes(),
            other.get_varnodes(),
            key=lambda varnode: varnode.get_addr() # sort by addr
        )

        # accumulate a list of Varnode pairs that overlap between the sets
        pairs = []

        # state variables
        # If prev_left set, then it implies that the prev_left addr range
        # could possibly overlap with the next right addr range.
        # The same applies for prev_right.

        # Varnode | None
        prev_left = None
        # Varnode | None
        prev_right = None

        def _addr_range_overlap(l: Varnode, r: Varnode) -> bool:
            return l.get_addr_range().does_overlap(r.get_addr_range())

        for cur in zipper:
            if cur.is_left(): # left list was iterated
                left_varnode = cur.get_value()
                if prev_right:
                    if _addr_range_overlap(left_varnode, prev_right):
                        pairs.append((left_varnode, prev_right))
                    else:
                        prev_right = None
                prev_left = left_varnode

            elif cur.is_right(): # right list was iterated
                right_varnode = cur.get_value()
                if prev_left:
                    if _addr_range_overlap(prev_left, right_varnode):
                        pairs.append((prev_left, right_varnode))
                    else:
                        prev_left = None
                prev_right = right_varnode

            elif cur.is_conflict(): # left & right varnodes matched start addr
                left_varnode, right_varnode = cur.get_value()
                if _addr_range_overlap(left_varnode, right_varnode):
                    pairs.append((left_varnode, right_varnode))
                prev_left = left_varnode
                prev_right = right_varnode

# compare the varnode sets in left and right address spaces
class ConstPCAddressSpaceCompare2(object):
    def __init__(self,
        left: ConstPCAddressSpace,
        right: ConstPCAddressSpace
    ):
        # ensure regions are matched
        assert ( left.get_region() == right.get_region() )

        self.left = left
        self.right = right
        
        # gather Varnode comparisons between the 2 sets
        self.left_varnode_comparisons: List[VarnodeCompare2] = []
        self.right_varnode_comparisons: List[VarnodeCompare2] = []

        # map of Varnode -> VarnodeCompareRecord for each (left, right) address space
        # we will update these maps each time we make a comparison
        self.left_varnode_compare_records: dict[Varnode, VarnodeCompareRecord] = \
            dict([(varnode, VarnodeCompareRecord(varnode)) for varnode in self.left.get_varnodes()])
        
        self.right_varnode_compare_records: dict[Varnode, VarnodeCompareRecord] = \
            dict([(varnode, VarnodeCompareRecord(varnode)) for varnode in self.right.get_varnodes()])

        # merge the two sets and get pairs of varnodes to compare
        # based on address overlaps
        compare_pairs: List[Tuple[Varnode, Varnode]] = left.get_comparison_pairs(right)

        # for each pair to compare, make the comparison and update internal state
        for left_varnode, right_varnode in compare_pairs:
            self._compare(left_varnode, right_varnode)

    # compare the 2 varnodes and update the internal state
    def _compare(self, left_varnode: Varnode, right_varnode: Varnode):
        # do comparison
        left_comparison = VarnodeCompare2(left_varnode, right_varnode)

        # store into left_varnode_comparisons
        if left_comparison and left_comparison.does_overlap():
            self.left_varnode_comparisons.append(left_comparison)
            self.left_varnode_compare_records[left_varnode] = left_comparison

        # flip comparison
        right_comparison = left_comparison.flip()

        # store into right_varnode_comparisons
        if right_comparison and right_comparison.does_overlap():
            self.right_varnode_comparisons.append(right_comparison)
            self.right_varnode_compare_records[right_varnode] = right_comparison
    
    def get_left_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        return self.left_varnode_compare_records

    def get_right_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        return self.right_varnode_compare_records

    def bytes_overlapped(self) -> int:
        return sum([ cmp.bytes_overlapped() for cmp in self.left_varnode_comparisons ])
