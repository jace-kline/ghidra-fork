from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str
from elftools.dwarf.dwarf_expr import DW_OP_name2opcode
from elftools.dwarf.constants import *
from translation import *

## Utility functions

# given a DIE and an attribute name, fetch the attr value (or None if doesn't exist)
def get_DIE_attr(die, attr):
    res = die.attributes.get(attr, None)
    return None if res is None else res.value

# return the "DW_AT_name" attribute of the DIE as a string
def get_DIE_name(die):
    attr = die.attributes.get("DW_AT_name", None)
    return bytes2str(attr.value) if attr is not None else None

# get the children variable-like DIEs of a given function (or lexical scope) DIE
# called recursively on sub-scopes
# returns (parameter DIEs, variable DIEs)
def get_param_var_DIEs(fndie):

    if not fndie.has_children:
        return []
    
    paramdies = []
    vardies = []
    for die in fndie.iter_children():
        if die.tag == "DW_TAG_formal_parameter":
            paramdies.append(die)

        elif die.tag == "DW_TAG_variable":
            vardies.append(die)

        elif die.tag == "DW_TAG_lexical_block": # recurse
            _, vdies = get_param_var_DIEs(die)
            vardies += vdies

    return (paramdies, vardies)

# get all DIE entries across all CUs
# ignore null DIEs
def get_all_DIEs(dwarfinfo):
    dies = []
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if not die.is_null():
                dies.append(die)
    return dies

def get_function_DIEs(dwarfinfo):
    dies = get_all_DIEs(dwarfinfo)
    return [ die for die in dies if die.tag == "DW_TAG_subprogram" ]

# get global variables
# any 'DW_TAG_variable' DIEs that are direct descendants of the root
# are assumed to be global variables
def get_global_var_DIEs(dwarfinfo):
    globals = []
    for cu in dwarfinfo.iter_CUs():
        rootdie = cu.get_top_DIE()
        globals += [ die for die in rootdie.iter_children() if die.tag == "DW_TAG_variable" ]
    return globals

# This exception shall be raised if there is no ELF/DWARF info or no debugging info is present
class ELF_DWARF_Exception(Exception):
    pass

# parse the ELF and DWARF info from a given object file (specified by its path)
def get_elf_dwarf_info(objfilepath):
    # objfilepath = "./progs/varcases_debug_O0.bin" # "./progs/p0"

    # raises Exception if no file or can't be opened
    f = open(objfilepath, 'rb')
    elffile = ELFFile(f)

    if elffile is None:
        raise ELF_DWARF_Exception("Could not parse ELF info from input file")

    if not elffile.has_dwarf_info():
        raise ELF_DWARF_Exception("File has no DWARF info")

    dwarfinfo = elffile.get_dwarf_info()

    if not dwarfinfo.has_debug_info:
        raise ELF_DWARF_Exception("DWARF info has no debug info")

    return elffile, dwarfinfo
    
# given a DIE with a 'DW_AT_location' OR 'DW_AT_low_pc' attribute,
# returns an Address object
# if attribute non-existent, return None
def parse_dwarf_addr(locexpr):

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

# bs = sequence of integer bytes in little endian order
# reverse the order and concatenate
def le_unsigned_decode(bs):
    val = 0
    for i, b in enumerate(bs):
        val |= (b << (8 * i))
    
    return val

# bs = sequence of integer bytes
# little-endian 128 bit variable encoding
def sleb128_decode(bs):
    # strip the leftmost (8th) bit in each byte
    _bs = [ b & 0x7f for b in bs ]

    # loop over each 7-bit chunk
    # for each chunk, shift its 7 bits left by the byte index * 7
    # concatenate the shifted chunks together with OR operator
    # this also reverses the bytes to big endian
    val = 0
    for i, b in enumerate(_bs):
        val |= (b << (7 * i))

    # sign-extend to fill full bytes
    nbits = 7 * len(_bs) # number of bits in val
    sign = val >> (nbits - 1) # leftmost bit = sign bit
    fillbits = 8 - (nbits % 8) # number of bits to fill to reach full bytes
    nbytes = (nbits + fillbits) // 8 # number of total bytes of the output

    # build the fill bit sequence
    fill = 0
    for i, b in enumerate([ sign for _ in range(0, fillbits) ]):
        fill |= (b << i)

    # prepend the fill bits to the original val
    val |= (fill << nbits)

    # force Python to represent this as a (possibly) signed integer (2's complement)
    val = int.from_bytes(val.to_bytes(nbytes, 'big'), 'big', signed=(sign == 1))

    return val
