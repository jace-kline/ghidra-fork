from translation import *

from __main__ import * # import all the implicit GhidraScript state & methods
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.app.util.opinion import ElfLoader
from ghidra.program.model.data import Pointer, Structure, DefaultDataType, BuiltInDataType, BooleanDataType, CharDataType, AbstractIntegerDataType, AbstractFloatDataType, AbstractComplexDataType, ArrayDataType, Array, Enum
from ghidra.app.util.bin.format.dwarf4.next import DWARFRegisterMappingsManager

# globals
curr = getCurrentProgram()
IFC = DecompInterface()
IFC.setOptions(DecompileOptions())
IFC.openProgram(currentProgram)

image_base = curr.imageBase.offset
orig_base = ElfLoader.getElfOriginalImageBase(curr)

def generate_register_mappings():
    d2g_mapping = DWARFRegisterMappingsManager.getMappingForLang(curr.language)
    g2d_mapping = {}
    for i in range(DW_FRAME_LAST_REG_NUM):
        reg = d2g_mapping.getGhidraReg(i)
        if reg:
            g2d_mapping[reg.offset] = i
    stack_reg_num = d2g_mapping.DWARFStackPointerRegNum
    stack_reg_dwarf = globals()["DW_OP_breg%d" % stack_reg_num]
    return g2d_mapping, stack_reg_dwarf

# () -> DecompInterface
def generate_decomp_interface():
    decompiler = DecompInterface()
    opts = DecompileOptions()
    opts.grabFromProgram(curr)
    decompiler.setOptions(opts)
    decompiler.toggleCCode(True)
    decompiler.toggleSyntaxTree(True)

    # - decompile -- The main decompiler action
    # - normalize -- Decompilation tuned for normalization
    # - jumptable -- Simplify just enough to recover a jump-table
    # - paramid   -- Simplify enough to recover function parameters
    # - register  -- Perform one analysis pass on registers, without stack variables
    # - firstpass -- Construct the initial raw syntax tree, with no simplification
    decompiler.setSimplificationStyle("decompile")
    decompiler.openProgram(curr)
    return decompiler

# (DecompInterface, Function) -> DecompileResults
def get_decompiled_function(decompiler, func):
    return decompiler.decompileFunction(func, 0, monitor)

# HighFunction -> ???
def get_decompiled_variables(decomp):
    hf = decomp.highFunction
    symbolMap = hf.localSymbolMap
    params = [symbolMap.getParam(i).symbol for i in range(symbolMap.numParams) if symbolMap.getParam(i)]
    for s in symbolMap.symbols:
        yield s.name, s.dataType, s.PCAddress, s.storage, s in params

def get_functions():
    fm = curr.functionManager
    funcs = fm.getFunctions(True)
    return funcs


def get_function_range(func):
    return (resolve_absolute_address(func.entryPoint.offset), resolve_absolute_address(func.body.maxAddress.offset))

def getAllFunctions(): # returns [Function]
    fns = []
    fn = getFirstFunction()
    while fn is not None:
        fns.append(fn)
        fn = getFunctionAfter(fn)
    return fns

# global variables?
def getAllData(): # returns [Data]
    data = []
    datum = getFirstData()
    while datum is not None:
        data.append(datum)
        datum = getDataAfter(datum)
    return data

# str -> Function | None
def getFunctionByName(fname):
    fns = getGlobalFunctions(fname)
    return fns[0] if len(fns) > 0 else None

# Address (Ghidra) -> Function (Ghidra) | None
def getFunctionByStartAddr(addr):
    return getFunctionAt(addr)

# decompile, returning DecompileResults
def decompile(fn): # returns DecompileResults
    """
    fn: Function
        the function object to decompile
    
    returns: DecompileResults
    """
    res = IFC.decompileFunction(fn, 0, monitor) # type: DecompileResults

    # if failed to decompile, print error
    if not res.decompileCompleted():
        print("Error decompiling function")
        print(res.getErrorMessage())
        exit(1)

    return res

# decompile, get C code as raw string
def decompileToRawC(fn): # returns str
    res = decompile(fn) # type: DecompileResults

    # get decompiled code
    decomp = res.getDecompiledFunction() # type: DecompiledFunction

    # from this, get C code as a string
    codestr = decomp.getC()
    return codestr

# decompile, get XML document of results
def decompileXML(fn): # returns ClangTokenGroup
    res = decompile(fn) # type: DecompileResults
    tokgrp = res.getCCodeMarkup() # type: ClangTokenGroup
    return tokgrp

# decompile, get high-level syntax tree
def decompileHighFunction(fn):
    res = decompile(fn)
    hfunc = res.getHighFunction() # type: HighFunction
    return hfunc

def decompileAll():
    return [ decompileHighFunction(fn) for fn in getAllFunctions() ]

# HighFunction -> [HighVariable]
def getHighFunctionGlobalVars(highfn):
    return [ 
        gblsym.getHighVariable() 
        for gblsym in highfn.getGlobalSymbolMap().getSymbols() 
        if gblsym.getHighVariable() is not None    
    ]

def getHighFunctionLocalVars(highfn):
    return [ 
        sym.getHighVariable() 
        for sym in highfn.getLocalSymbolMap().getSymbols() 
        if sym.getHighVariable() is not None
    ]

def getHighFunctionParams(highfn):
    localsymmap = highfn.getLocalSymbolMap()
    return [ 
        localsymmap.getParam(i) 
        for i in range(localsymmap.getNumParams()) 
        if localsymmap.getParam(i) is not None   
    ]

def getHighFunctionLocalVars(highfn):
    return [ 
        sym.getHighVariable() 
        for sym in highfn.getLocalSymbolMap().getSymbols() 
        if (not sym.isParameter()) and (not sym.isGlobal()) and (sym.getHighVariable() is not None)
    ]

# get the Ghidra Address for the start of the HighFunction object
def getHighFunctionStartAddr(highfn):
    fn = highfn.getFunction()
    startaddr = fn.getEntrypoint()
    return startaddr

# get the Ghidra Address for the last native instruction of the HighFunction object
def getHighFunctionEndAddr(highfn):
    offset = 0
    endaddr = None
    for pcodeop in highfn.getPcodeOps().getBasicIter():
        _endaddr = pcodeop.getSeqnum().getTarget()
        _offset = _endaddr.getOffset()
        if _offset > offset:
            offset = _offset
            endaddr = _endaddr
    return endaddr

def flatten(xss):
    return [x for xs in xss for x in xs]

# int -> int
def resolve_absolute_address(absaddr):
    return absaddr - image_base + orig_base

# Convert a Ghidra-represented Address into our Address representation
def get_address(addr):
    addrspace = get_addrtype(addr.getAddressSpace())
    offset = addr.getOffset()

    if addrspace == AddressType.STACK:
        return StackAddress(offset)
    elif addrspace == AddressType.ABSOLUTE:
        return AbsoluteAddress(resolve_absolute_address(offset))
    elif addrspace == AddressType.EXTERNAL:
        return ExternalAddress()
    elif addrspace == AddressType.REGISTER:
        return RegisterAddress(offset)

# Given a Ghidra AddressSpace object, produce an AddressSpace enum int in our own representation
def get_addrtype(addrspace):
    if addrspace.isStackSpace():
        return AddressType.STACK
    elif addrspace.isMemorySpace():
        return AddressType.ABSOLUTE
    elif addrspace.isExternalSpace():
        return AddressType.EXTERNAL
    elif addrspace.isRegisterSpace():
        return AddressType.REGISTER
    else:
        return AddressType.UNKNOWN

# for a given DataType (Ghidra) object, extract its class name
# string and group it into a MetaType category
# Ghidra class hierarchy: https://ghidra.re/ghidra_docs/api/overview-tree.html
# -> types are classes within ghidra.program.model.data & ghidra.program.database.data
def get_metatype(dtype):
    clsname = type(dtype).__name__
    
    # strip the package prefix from the class name for easier comparison
    prefixes = [ "ghidra.program.model.data.", "ghidra.program.database.data." ]
    valid = True
    for prefix in prefixes:
        if clsname.startswith(prefix):
            clsname = clsname[len(prefix):]
            valid = True
            break
    
    if not valid:
        raise NotImplementedError("No metatype translation for class '{}'".format(clsname))

    if clsname in [
        "AbstractFloatDataType",
        "DoubleDataType",
        "Float10DataType",
        "Float16DataType",
        "Float2DataType",
        "Float4DataType",
        "FloatDataType",
        "LongDoubleDataType"
    ]:
        return MetaType.FLOAT
    
    elif clsname in [
        "AbstractIntegerDataType",
        "BooleanDataType",
        "ByteDataType",
        "CharDataType",
        "SignedCharDataType",
        "UnsignedCharDataType",
        "DWordDataType",
        "Integer16DataType",
        "Integer3DataType",
        "Integer5DataType",
        "Integer6DataType",
        "Integer7DataType",
        "IntegerDataType",
        "LongDataType",
        "LongLongDataType",
        "QWordDataType",
        "ShortDataType",
        "SignedByteDataType",
        "SignedDWordDataType",
        "SignedQWordDataType",
        "SignedWordDataType",
        "UnsignedInteger16DataType",
        "UnsignedInteger3DataType",
        "UnsignedInteger5DataType",
        "UnsignedInteger6DataType",
        "UnsignedInteger7DataType",
        "UnsignedIntegerDataType",
        "UnsignedLongDataType",
        "UnsignedLongLongDataType",
        "UnsignedShortDataType",
        "WordDataType"
    ]:
        return MetaType.INT

    elif clsname in [
        "VoidDataType"
    ]:
        return MetaType.VOID

    elif clsname in [
        "PointerDataType",
        "Pointer16DataType",
        "Pointer24DataType",
        "Pointer32DataType",
        "Pointer40DataType",
        "Pointer48DataType",
        "Pointer56DataType",
        "Pointer64DataType",
        "Pointer8DataType",
        "PointerDB"
    ]:
        return MetaType.POINTER

    elif clsname in [
        "StructureDataType",
        "StructureDB"
    ]:
        return MetaType.STRUCT

    elif clsname in [
        "UnionDataType",
        "UnionDB"
    ]:
        return MetaType.UNION

    elif clsname in [
        "ArrayDataType",
        "ArrayDB"
    ]:
        return MetaType.ARRAY

    elif clsname in [
        "FunctionDefinitionDataType",
        "FunctionDefinitionDB"
    ]:
        return MetaType.FUNCTION_PROTOTYPE

    elif clsname in [
        "TypedefDataType",
        "TypedefDB"
    ]:
        return MetaType.TYPEDEF

    elif clsname in [
        "EnumDataType",
        "EnumDB"
    ]:
        return MetaType.ENUM

    elif clsname in [
        "Undefined",
        "Undefined1DataType",
        "Undefined2DataType",
        "Undefined3DataType",
        "Undefined4DataType",
        "Undefined5DataType",
        "Undefined6DataType",
        "Undefined7DataType",
        "Undefined8DataType",
        "DefaultDataType",
        "DwarfEncodingModeDataType",
        "UnsignedLeb128DataType",
        "SignedLeb128DataType"
    ]:
        return MetaType.UNDEFINED

    elif clsname in [
        "AbstractStringDataType",
        "StringDataType"
    ]:
        return MetaType.STRING

    else:
        raise NotImplementedError("No MetaType translation for class {}".format(clsname))