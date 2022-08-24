from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

from compare_variable import *

# represents a "scope"/set of variables at a given PC during the program
class ConstPCScope(object):
    def __init__(self, varnodes: List[Varnode]):
        self.varnodes = varnodes

        # TODO: partition spaces (store or create function to generate dynamically)
        self.spaces = None

# compares 2 sets of variables representing a certain "scope" in the program (constant PC)
# this could mean a point in a function or the global scope
class ConstPCScopeCompare2(object):
    def __init__(self,
        left: ConstPCScope,
        right: ConstPCScope,
        exact_match: bool = False # should variables match exactly?
    ):
        self.left = left
        self.right = right
        self.exact_match = exact_match

    def get_left(self) -> ConstPCScope:
        return self.left

    def get_right(self) -> ConstPCScope:
        return self.right

    # map each Varnode in left to its associated VarnodeCompareRecord
    def get_left_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        # fold over each left address space, collect, and combine
        pass

    # map each Varnode in right to its associated VarnodeCompareRecord
    def get_right_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        # fold over each right address space, collect, and combine
        pass

# holds an ordered list of Varnode objects of the same Address type
# the address space type must be orderable/rangeable
class ConstPCOrderedAddressSpace(object):
    def __init__(self, addrtype: int, varnodes: List[Varnode]):
        # ensure the given address type is "rangeable"
        assert( AddressType.rangeable(addrtype) )
        self.addrtype = addrtype

        # ensure that all passed varnodes have correct addrtype
        for varnode in varnodes:
            self._verify_addrtype(varnode)

        # sort the passed varnodes (ascending) by address
        self.varnodes = sorted(varnodes, key=lambda v: v.get_addr())

    def _verify_addrtype(self, varnode: Varnode):
        assert( varnode.get_addr().get_addrtype() == self.addrtype )

    def get_addrtype(self):
        return self.addrtype

    def get_varnodes(self):
        return self.varnodes

# compare the varnode sets in left and right address spaces
class ConstPCOrderedAddressSpaceCompare2(object):
    def __init__(self,
        left: ConstPCOrderedAddressSpace,
        right: ConstPCOrderedAddressSpace,
        exact_match: bool = False
    ):
        # ensure addrtypes are matched
        assert ( left.get_addrtype() == right.get_addrtype() )

        self.left = left
        self.right = right

        self.exact_match = exact_match
        
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
        compare_pairs: List[Tuple[Varnode, Varnode]] = self._merge()

        # for each pair to compare, make the comparison and update internal state
        for left_varnode, right_varnode in compare_pairs:
            self._compare(left_varnode, right_varnode)

    # compare the 2 varnodes and update the internal state
    def _compare(self, left_varnode: Varnode, right_varnode: Varnode):
        # do comparison
        left_comparison = VarnodeCompare2(left_varnode, right_varnode, exact_match=self.exact_match)

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

    # iterate over the address space pair overlapping varnodes
    # from the left and right sets
    def _merge(self) -> List[Tuple[Varnode, Varnode]]:

        # create iterator the "merges" the 2 address spaces
        zipper = OrderedZipper(
            self.left,
            self.right,
            key=lambda varnode: varnode.get_addr() # sort by addr
        )

        # accumulate a list of Varnode pairs to compare later
        pairs = []

        # state variables
        # If prev_left set, then it implies that the prev_left addr range
        # could possibly overlap with the next right addr range.
        # The same applies for prev_right.

        # StaticPCVariable | None
        prev_left = None
        # StaticPCVariable | None
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
    
    def get_left_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        return self.left_varnode_compare_records

    def get_right_varnode_compare_records(self) -> 'dict[Varnode, VarnodeCompareRecord]':
        return self.right_varnode_compare_records
