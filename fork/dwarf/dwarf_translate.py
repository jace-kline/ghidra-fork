from elftools.elf.elffile import ELFFile
from dwarf_translate_type import DWARFDataTypeTranslator
from dwarf_translate_addr import DWARFAddressTranslator
from dwarf_translate_util import *
from dwarf.translation import *

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
    def get_DIE_variable(self, vardie, function=None):
        name = get_DIE_name(vardie)
        dtype = self.type_translator.get_DIE_datatype(vardie)
        param = (vardie.tag == "DW_TAG_formal_parameter") # is param?
        addr = self.addr_translator.get_DIE_addr(vardie)

        return Variable(
            name=name,
            dtype=dtype,
            addr=addr,
            param=param,
            function=function
        )

    def get_DIE_datatype(self, die):
        return self.type_translator.get_DIE_datatype(die)

    # given a function DIE (DW_TAG_subprogram),
    # build a Function object
    def get_DIE_function(self, fndie):
        # get function name
        name = get_DIE_name(fndie)

        # get return type
        rettype = self.get_DIE_datatype(fndie)

        # get the start address
        lowpc = fndie.attributes["DW_AT_low_pc"].value
        startaddr = Address(addrspace=AddressSpace.GLOBAL, offset=lowpc)

        # get the function's variables (parameters & body vars)
        # temporarily set the vars' 'function' attribute to None
        paramdies, vardies = get_param_var_DIEs(fndie)
        params = [ self.get_DIE_variable(die, function=None) for die in paramdies ]
        vars = [ self.get_DIE_variable(die, function=None) for die in vardies ]

        prototype = DataTypeFunctionPrototype(
            rettype=rettype,
            paramtypes=[ param.dtype for param in params ],
            resolved=True
        )

        fn = Function(
            name=name,
            startaddr=startaddr,
            prototype=prototype,
            params=params,
            vars=vars
        )

        # for each var, point it to its parent function object
        for var in fn.vars:
            var.function = fn

        return fn

    # for each function DIE found in DWARF info, create a Function object
    # recursively create Variable & DataType objects as needed
    def get_functions(self):
        # fetch all the function DIEs, then
        # map over each, creating a Function object
        return [
            self.get_DIE_function(fndie)
            for fndie
            in get_function_DIEs(self.dwarfinfo)
        ]

    # fetch all the global variable DIEs and convert to a list of Variable objects
    def get_global_vars(self):
        return [
            self.get_DIE_variable(vardie, function=None)
            for vardie
            in get_global_var_DIEs(self.dwarfinfo)
        ]

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

# produce a Translation object from the DWARF info
def translate(objfilepath):
    elffile, dwarfinfo = get_elf_dwarf_info(objfilepath)
    translator = DWARFTranslator(dwarfinfo)

    fns = translator.get_functions()
    gbls = translator.get_global_vars()

    return Translation(globals=gbls, functions=fns)
    
