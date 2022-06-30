from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile
from elftools.dwarf.constants import *
from elftools.dwarf.dwarf_expr import DW_OP_name2opcode
import struct
from lib import *

def mk_ELFFile(fname):
    try:
        f = open(fname, 'rb')
        elffile = ELFFile(f)
        return elffile
    except:
        return None

## Utility functions

# bs = sequence of integer bytes in little endian order
# reverse the order and concatenate
def le_unsigned_decode(bs):
    val = 0
    for i, b in enumerate(reversed(bs)):
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

# return the "DW_AT_name" attribute of the DIE as a string
def get_DIE_name(die):
    attr = die.attributes.get("DW_AT_name", None)
    return bytes2str(attr.value) if attr is not None else None

# get the children variable-like DIEs of a given function (or lexical scope) DIE
# called recursively on sub-scopes
def get_DIE_child_var_DIEs(fndie):

    if not fndie.has_children:
        return []
    
    vardies = []
    for die in fndie.iter_children():
        if die.tag == "DW_TAG_variable" or die.tag == "DW_TAG_formal_parameter":
            vardies.append(die)

        elif die.tag == "DW_TAG_lexical_block": # recurse
            vardies += get_DIE_child_var_DIEs(die)

    return vardies

# extract functions, variables, datatypes from the given DWARF info
# for a given debug-compiled executable
class DWARFTranslator:
    def __init__(self, dwarfinfo):
        self.dwarfinfo = dwarfinfo

    # get all DIE entries across all CUs
    # ignore null DIEs
    def get_all_DIEs(self):
        dies = []
        for cu in self.dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if not die.is_null():
                    dies.append(die)
        return dies

    def get_function_DIEs(self):
        dies = self.get_all_DIEs()
        return [ die for die in dies if die.tag == "DW_TAG_subprogram" ]

    # get global variables
    # any 'DW_TAG_variable' DIEs that are direct descendants of the root
    # are assumed to be global variables
    def get_global_var_DIEs(self):
        globals = []
        for cu in self.dwarfinfo.iter_CUs():
            rootdie = cu.get_top_DIE()
            globals += [ die for die in rootdie.iter_children() if die.tag == "DW_TAG_variable" ]
        return globals

    # get the DIE for the type representing any other DIE
    # should be accessed only if the die possesses the 'DW_AT_type' attribute
    def get_DIE_type_DIE(self, die, cu=None):
        try:
            return self.dwarfinfo.get_DIE_from_refaddr(die.attributes["DW_AT_type"].value, cu)
        except KeyError:
            return None

    # for any datatype-like DIE,
    # fetch, construct, & return the correct DataType subclass object
    def get_type_DIE_datatype(self, typedie):

        # if base type, lookup mapping
        if typedie.tag == "DW_TAG_base_type":
            enc = typedie.attributes["DW_AT_encoding"].value
            size = typedie.attributes["DW_AT_byte_size"].value
            
            # void
            if enc == DW_ATE_void:
                return DataTypeVoid()
            # pointer
            elif enc == DW_ATE_address:
                # recursive call to get pointed-to datatype
                basetype = self.get_type_DIE_datatype(self.get_DIE_type_DIE(typedie))
                return DataTypePointer(basetype=basetype, size=size)
                
            # int/char (signed)
            elif enc in [DW_ATE_signed, DW_ATE_signed_char, DW_ATE_signed_fixed]:
                return DataTypeInt(size=size, signed=True)
            # int/char (unsigned)
            # regard bool as unsigned char
            # regard ASCII char as unsigned char
            elif enc in [DW_ATE_unsigned, DW_ATE_unsigned_char, DW_ATE_unsigned_fixed, DW_ATE_boolean, DW_ATE_ASCII]:
                return DataTypeInt(size=size, signed=False)
            # float
            elif enc in [DW_ATE_complex_float, DW_ATE_float, DW_ATE_decimal_float, DW_ATE_imaginary_float]:
                return DataTypeFloat(size=size)
            else:
                return DataTypeUndefined(size=size)

        # qualified types -> treat as their base types
        # how to handle references (in C++)?
        elif typedie.tag in ["DW_TAG_atomic_type", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restricted_type"]:
            return self.get_type_DIE_datatype(self.get_DIE_type_DIE(typedie))

        # pointer type
        elif typedie.tag == "DW_TAG_pointer_type":
            size = typedie.attributes["DW_AT_byte_size"].value
            # recursive call to get pointed-to datatype
            basetype = self.get_type_DIE_datatype(self.get_DIE_type_DIE(typedie))
            return DataTypePointer(basetype=basetype, size=size)

        # array type
        elif typedie.tag == "DW_TAG_array_type":
            # get element type
            basetype = self.get_type_DIE_datatype(self.get_DIE_type_DIE(typedie))
            # get the child subrange DIE object -> specifies the
            # bounds of the array
            rangetypedies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_subrange_type" ]
            length = -1
            size = -1
            if rangetypedies != []:
                rangetypedie = rangetypedies[0]
                length = rangetypedie.attributes["DW_AT_upper_bound"].value + 1
                size = basetype.size * length
            return DataTypeArray(basetype=basetype, length=length, size=size)

        # struct type
        # TODO deal with recursive structs (i.e. pointers to same struct type)
        elif typedie.tag == "DW_TAG_structure_type":
            memberdies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_member" ]
            membertypes = [ self.get_var_DIE_datatype(die) for die in memberdies ]
            name = get_DIE_name(typedie)
            size = sum([ mem.size for mem in membertypes ])
            return DataTypeStruct(name=name, membertypes=membertypes, size=size)

        # union type
        elif typedie.tag == "DW_TAG_union_type":
            memberdies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_member" ]
            membertypes = [ self.get_var_DIE_datatype(die) for die in memberdies ]
            name = get_DIE_name(typedie)
            size = max([ mem.size for mem in membertypes ])
            return DataTypeUnion(name=name, membertypes=membertypes, size=size)

        # typedef -> return the aliased type
        elif typedie.tag == "DW_TAG_typedef":
            basetype = self.get_type_DIE_datatype(self.get_DIE_type_DIE(typedie))
            return basetype

        # TODO implement other cases
        else:
            raise NotImplementedError(typedie.tag)

    # for any variable-like DIE, fetch its type DIE and convert
    # to a DataType object
    def get_var_DIE_datatype(self, vardie):
        return self.get_type_DIE_datatype(self.get_DIE_type_DIE(vardie))

    # given a variable-like DIE, construct a Variable object in the common language
    # involves parsing the datatype (DW_AT_type) and address (DW_AT_location)
    def get_var_DIE_variable(self, vardie, gbl=False):
        name = get_DIE_name(vardie)
        dtype = self.get_var_DIE_datatype(vardie)
        param = (vardie.tag == "DW_TAG_formal_parameter") # is param?
        addr = self.get_var_DIE_addr(vardie)

        # parse the address(es) this variable occupies during its lifetime
        # need to parse the 'DW_AT_location' DWARF expression
        return Variable(
            name=name,
            dtype=dtype,
            addr=addr,
            param=param,
            gbl=gbl
        )

    # given a variable-like DIE with a 'DW_AT_location' attribute,
    # return a list of Address objects specifying where this variable resides
    def get_var_DIE_addr(self, vardie):
        locexpr = vardie.attributes["DW_AT_location"].value
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

    # given a function DIE (DW_TAG_subprogram),
    # build a Function object
    def get_fn_DIE_fn(self, fndie):
        # get function name
        name = get_DIE_name(fndie)

        # get return type
        rettype = self.get_var_DIE_datatype(fndie)

        # get the start address
        lowpc = fndie.attributes["DW_AT_low_pc"].value
        startaddr = Address(addrspace=AddressSpace.GLOBAL, offset=lowpc)

        # get the function's variables (parameters + body vars)
        vardies = get_DIE_child_var_DIEs(fndie)
        vars = [ self.get_var_DIE_variable(vardie, gbl=False) for vardie in vardies ]

        return Function(
            name=name,
            startaddr=startaddr,
            rettype=rettype,
            vars=vars
        )

    # for each function DIE found in DWARF info, create a Function object
    # recursively create Variable & DataType objects
    def get_functions(self):
        # fetch all the function DIEs, then
        # map over each, creating a Function object
        return [
            self.get_fn_DIE_fn(fndie)
            for fndie
            in self.get_function_DIEs()
        ]

    # fetch all the global variable DIEs and convert to a list of Variable objects
    def get_global_vars(self):
        return [
            self.get_var_DIE_variable(vardie, gbl=True)
            for vardie
            in self.get_global_var_DIEs()
        ]


def main():
    objfilepath = "./progs/varcases_debug_O0.bin"
    elffile = mk_ELFFile(objfilepath)
    if elffile is None:
        print("Error: Could not parse ELF info")
        return

    if not elffile.has_dwarf_info():
        print("Error: File has no DWARF info")
        return

    dwarfinfo = elffile.get_dwarf_info()

    if not dwarfinfo.has_debug_info:
        print("Error: DWARF info has no debug info")
        return

    translator = DWARFTranslator(dwarfinfo)

    fns = translator.get_functions()
    gbls = translator.get_global_vars()

    print("----------------GLOBALS----------------------")
    for gbl in gbls:
        print("{} @ {}".format(gbl.name, gbl.addr.offset))


    print("----------------FUNCTIONS--------------------")
    for fn in fns:
        print("{} @ {0:x}".format(fn.name, fn.startaddr.offset))
        for var in fn.vars:
            print("\t{} @ RBP+({})".format(var.name, var.addr.offset))
    
    elffile.stream.close()

if __name__ == "__main__":
    main()
    
