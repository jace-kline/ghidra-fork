from elftools.elf.elffile import ELFFile
from dwarf_translate_type import DWARFDataTypeTranslator
from dwarf_translate_addr import DWARFAddressTranslator
from dwarf_translate_util import *
from repr import *

def mk_ELFFile(fname):
    try:
        f = open(fname, 'rb')
        elffile = ELFFile(f)
        return elffile
    except:
        return None



# extract functions, variables, datatypes from the given DWARF info
# for a given debug-compiled executable
class DWARFTranslator:
    def __init__(self, dwarfinfo):
        self.dwarfinfo = dwarfinfo

        # used to store datatype table
        # resolves to DataType object tree on request
        self.type_translator = DWARFDataTypeTranslator(self.dwarfinfo)

        # used to parse and resolve Address objects from DWARF expressions
        self.addr_translator = DWARFAddressTranslator(self.dwarfinfo)

    # given a variable-like DIE, construct a Variable object in the common language
    # involves parsing the datatype (DW_AT_type) and address (DW_AT_location)
    def get_var_DIE_variable(self, vardie, gbl=False):
        name = get_DIE_name(vardie)
        dtype = self.type_translator.get_DIE_datatype(vardie)
        param = (vardie.tag == "DW_TAG_formal_parameter") # is param?
        addr = self.addr_translator.get_DIE_addr(vardie)

        return Variable(
            name=name,
            dtype=dtype,
            addr=addr,
            param=param,
            gbl=gbl
        )

    # # given a function DIE (DW_TAG_subprogram),
    # # build a Function object
    # def get_fn_DIE_fn(self, fndie):
    #     # get function name
    #     name = get_DIE_name(fndie)

    #     # get return type
    #     rettype = self.get_var_DIE_datatype(fndie)

    #     # get the start address
    #     lowpc = fndie.attributes["DW_AT_low_pc"].value
    #     startaddr = Address(addrspace=AddressSpace.GLOBAL, offset=lowpc)

    #     # get the function's variables (parameters + body vars)
    #     vardies = get_DIE_child_var_DIEs(fndie)
    #     vars = [ self.get_var_DIE_variable(vardie, gbl=False) for vardie in vardies ]

    #     return Function(
    #         name=name,
    #         startaddr=startaddr,
    #         rettype=rettype,
    #         vars=vars
    #     )

    # # for each function DIE found in DWARF info, create a Function object
    # # recursively create Variable & DataType objects
    # def get_functions(self):
    #     # fetch all the function DIEs, then
    #     # map over each, creating a Function object
    #     return [
    #         self.get_fn_DIE_fn(fndie)
    #         for fndie
    #         in self.get_function_DIEs()
    #     ]

    # # fetch all the global variable DIEs and convert to a list of Variable objects
    # def get_global_vars(self):
    #     return [
    #         self.get_var_DIE_variable(vardie, gbl=True)
    #         for vardie
    #         in get_global_var_DIEs(self.dwarfinfo)
    #     ]


def setup():
    objfilepath = "./progs/varcases_debug_O0.bin"
    elffile = mk_ELFFile(objfilepath)
    if elffile is None:
        print("Error: Could not parse ELF info")
        return None

    if not elffile.has_dwarf_info():
        print("Error: File has no DWARF info")
        return None

    dwarfinfo = elffile.get_dwarf_info()

    if not dwarfinfo.has_debug_info:
        print("Error: DWARF info has no debug info")
        return None

    return elffile, dwarfinfo

def test():
    elffile, dwarfinfo = setup()
    translator = DWARFTranslator(dwarfinfo)

    fndies = get_function_DIEs(dwarfinfo)
    gbldies = get_global_var_DIEs(dwarfinfo)

    for die in gbldies:
        # refaddr = translator.type_translator._get_DIE_type_refaddr(die)
        # translator.type_translator._update(refaddr)
        dtype = translator.type_translator.get_DIE_datatype(die)
        print(dtype)

    # print(translator.type_translator._map)

def main():
    elffile, dwarfinfo = setup()
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
    test()
    
