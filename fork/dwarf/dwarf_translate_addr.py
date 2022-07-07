from elftools.dwarf.dwarf_expr import DW_OP_name2opcode
from dwarf_translate_util import *
from translation import *

class DWARFAddressTranslator:
    def __init__(self, dwarfinfo):
        self.dwarfinfo = dwarfinfo

    # given a DIE with a 'DW_AT_location' attribute,
    # returns an Address object
    # if attribute non-existent, return None
    def get_DIE_addr(self, vardie):
        try:
            locexpr = vardie.attributes["DW_AT_location"].value
        except KeyError:
            # return an "UNKNOWN" address if no "DW_AT_location" present
            return Address(
                addrspace=AddressSpace.UNKNOWN,
                offset=0
            )

        op = locexpr[0] # the operation specifier
        bs = locexpr[1:] # the bytes representing location/offset

        # absolute address
        if op == DW_OP_name2opcode["DW_OP_addr"]:
            addr = le_unsigned_decode(bs)
            return Address(
                addrspace=AddressSpace.GLOBAL,
                offset=addr
            )

        # offset from stack frame register's base pointer (DW_AT_frame_base)
        elif op == DW_OP_name2opcode["DW_OP_fbreg"]:
            offset = sleb128_decode(bs)
            return Address(
                addrspace=AddressSpace.STACK,
                offset=offset
            )

        # other
        else:
            raise NotImplementedError(op)