from translation import *

from __main__ import * # import all the implicit GhidraScript state & methods
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface

# globals
IFC = DecompInterface()
IFC.setOptions(DecompileOptions())
IFC.openProgram(currentProgram)

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

def getFunctionByName(fname): # returns Function (or None)
    """
    fname: String
        the desired function's name
    
    returns: Function | None
    """
    fns = getGlobalFunctions(fname)
    return fns[0] if len(fns) > 0 else None

def getFunctionByStartAddr(addr): # returns Function (or None)
    """
    addr: Address
        the start address of the desired function

    returns: Function | None
    """
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

def flatten(xss):
    return [x for xs in xss for x in xs]

# Convert a Ghidra-represented Address into our Address representation
def get_address(addr):
    addrspace = get_addrspace(addr.getAddressSpace())
    offset = addr.getOffset()

    return Address(addrspace=addrspace, offset=offset)

# Given a Ghidra AddressSpace object, produce an AddressSpace enum int in our own representation
def get_addrspace(addrspace):
    if addrspace.isStackSpace():
        return AddressSpace.STACK
    elif addrspace.isMemorySpace():
        return AddressSpace.GLOBAL
    elif addrspace.isExternalSpace():
        return AddressSpace.EXTERNAL
    elif addrspace.isRegisterSpace():
        return AddressSpace.REGISTER
    else:
        return AddressSpace.UNKNOWN

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