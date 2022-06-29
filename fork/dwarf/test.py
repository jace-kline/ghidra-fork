from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile
from elftools.dwarf.constants import *
from lib import *

def mk_ELFFile(fname):
    try:
        f = open(fname, 'rb')
        elffile = ELFFile(f)
        return elffile
    except:
        return None

## Utility functions

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
            param = (die.tag == "DW_TAG_formal_parameter") # is param?
            vardies.append(die)

        elif die.tag == "DW_TAG_lexical_block": # recurse
            vardies += get_DIE_child_var_DIEs(die)

    return vardies

# extract functions, variables, datatypes from the given DWARF info
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

    # get the DIE for the type representing any other DIE
    # should be accessed by the 'DW_AT_type' attribute
    def get_DIE_type_DIE(self, die, cu=None):
        try:
            return self.dwarfinfo.get_DIE_from_refaddr(die.attributes["DW_AT_type"].value, cu)
        except KeyError:
            return None

    # for each DIE representing a type,
    # return a DataType subclass object
    def get_DIE_datatype(self, typedie):

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
                basetype = self.get_DIE_datatype(self.get_DIE_type_DIE(typedie))
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
            return self.get_DIE_datatype(self.get_DIE_type_DIE(typedie))

        # pointer type
        elif typedie.tag == "DW_TAG_pointer_type":
            size = typedie.attributes["DW_AT_byte_size"].value
            # recursive call to get pointed-to datatype
            basetype = self.get_DIE_datatype(self.get_DIE_type_DIE(typedie))
            return DataTypePointer(basetype=basetype, size=size)

        # array type
        elif typedie.tag == "DW_TAG_array_type":
            # get element type
            basetype = self.get_DIE_datatype(self.get_DIE_type_DIE(typedie))
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
        elif typedie.tag == "DW_TAG_structure_type":
            memberdies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_member" ]
            membertypes = [ self.get_DIE_datatype(die) for die in memberdies ]
            name = self.get_DIE_name(typedie)
            size = sum([ mem.size for mem in membertypes ])
            return DataTypeStruct(name=name, membertypes=membertypes, size=size)

        # union type
        elif typedie.tag == "DW_TAG_union_type":
            raise NotImplementedError()

        # TODO implement other cases

def main():
    objfilepath = "./progs/p0"
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

    t = DWARFTranslator(dwarfinfo)

    # get all DIE objects across all CUs
    fn_dies = t.get_function_DIEs()
    for fndie in fn_dies:
        print(get_DIE_name(fndie))
        for vardie in get_DIE_child_var_DIEs(fndie):
            print("\t{}\n\t{}".format(
                get_DIE_name(vardie),
                t.get_DIE_datatype(t.get_DIE_type_DIE(vardie))
            ))

    # fndie = [ die for die in fn_dies if get_DIE_name(die) == "main" ][0]
    # vardies = get_DIE_child_var_DIEs(fndie)
    # arrdie = [ die for die in vardies if get_DIE_name(die) == "myarr" ][0]
    # arrtypedie = t.get_DIE_type_DIE(arrdie)
    # dtype = t.get_DIE_datatype(arrtypedie)
    # print(dtype.size)
    
    elffile.stream.close()

if __name__ == "__main__":
    main()
    
