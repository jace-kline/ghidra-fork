from http.client import CONFLICT
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

class StaticPCVariable(object):
    def __init__(self, pc, var):
        self.pc = pc
        self.var = var

        # self.addr: Address
        self.addr = self.var.get_address_at_pc(self.pc)

        # self.size: int
        if self.addr:
            self.size = self.var.dtype.size
            self.size = self.size if self.size else 0
        
        # self.addr_range: AddressRange
        if self.addr and self.size > 0 and AddressType.rangeable(self.addr.addrtype):
            self.addr_range = AddressRange(self.addr, size=self.size)

    # is this variable "alive" at the given PC? i.e., does it have a location?
    # This is assumed to be true for all other operations.
    def instantiated(self):
        return self.addr is not None

    def get_datatype(self):
        return self.var.dtype

    def is_global(self):
        return self.var.is_global()

    def get_addrtype(self):
        return self.addr.addrtype


    # does this variable contain the given address?
    def contains(self, addr):
        if not self.addr:
            return False
        elif not self.addr_range:
            return addr == self.addr
        else: # addr and addr_range are instantiated...
            self.addr_range.contains(addr)

    # if this Variable contains the given Address at this PC,
    # what is the offset from the start of this variable's range
    # to the addr? (always positive)
    # return None if this variable doesn't contain the given Address
    # Address -> int | None
    def contained_offset(self, addr):
        if self.contains(addr):
            return self.addr.distance(addr)
        return None

    # StaticPCVariable -> StaticPCVariableComparison
    def compare(self, other):
        raise NotImplementedError()

class StaticPCVariableComparison(object):
    pass

class StaticPCContext(object):
    def __init__(self, pc, vars):
        self.pc = pc
        # map each Variable to a StaticPCVariable.
        # filter out the those that aren't "instantiated" at the given PC.
        self.var_insts = [ var for var in [ StaticPCVariable(self.pc, var) for var in vars ] if var.instantiated() ]

    # Address -> StaticPCVariable | None
    def get_var_at_address(self, addr):
        for var_inst in self.var_insts:
            if var_inst.contains(addr):
                return var_inst
        return None

    def compare(self, other):
        raise NotImplementedError()

class StaticPCContextComparison(object):
    pass

class StaticPCAddressSpace(object):
    # addrtype: AddressType enum value
    def __init__(self, addrtype):
        self.addrtype = addrtype

    # other: StaticPCAddressSpace
    # StaticPCAddressSpace -> StaticPCAddressSpaceComparison
    def compare(self, other):
        raise NotImplementedError()

# Represents a snapshot of an Address space at a given PC that is "rangeable".
# i.e., there is a base and offsets allowed of arbitrary length.
# This includes stack frames, heap allocations, memory accessible from register offset, etc.
class StaticPCRangeableAddressSpace(object):
    def __init__(self, addrtype, var_insts):
        super(__class__, self).__init__(addrtype)
        self.var_insts = var_insts

        # check the var_insts are the correct address type
        # then sort them by their "offset" within their space
        self._verify_var_inst_types()
        self.var_insts.sort(key=lambda v: v.addr)

    def _verify_var_inst_types(self):
        for var_inst in self.var_insts:
            assert (var_inst.get_addrtype() == self.addrtype)

    def compare(self, other):
        # assume self & other var_insts are sorted ascending by addr
        # iterate over the 'Left', 'Right', and 'Conflict' objects
        for res in OrderedZipper(
            self.var_insts,
            other.var_insts,
            key=lambda var_inst: var_inst.addr
        ):
            if res.is_left():
                pass # TODO

            elif res.is_right():
                pass # TODO

            elif res.is_conflict():
                pass # TODO

        # incrementally find the next largest address from either list, then construct
        # a "diff" object to document the the differences
        raise NotImplementedError()

# A wrapper for an Address that makes it into an "address space".
class StaticPCLocation(StaticPCAddressSpace):
    pass

class StaticPCAddressSpaceComparison(object):
    pass