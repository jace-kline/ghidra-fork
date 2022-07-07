# ghidra decompile
# @category: Research

# ref: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html

# flat program API
# from ghidra.app.flatapi import FlatProgramAPI

# to decompile
# from dwarf.translation import MetaType
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

def test1():
    # args = getScriptArgs()

    # if len(args) == 0:
    #     print("Error: Supply function name to decompile as script argument")
    #     exit(1)

    fname = "main"
    # fname = args[0] # 1st arg = the function name to decompile

    fn = getFunctionByName(fname) # Function
    # perform decompilation transformations on the low-level function
    hfunc = decompileHighFunction(fn) # HighFunction
    # get the transformed Function object (after decompilation)
    fn = hfunc.getFunction() # Function

    print(fn.getEntryPoint().toString(True, False))
    vars = fn.getAllVariables()
    for var in vars:
        print("{} [{}] {}".format(
            var.getName(),
            var.getStackOffset(),
            var.getDataType().getName())
        )

def test():
    for fn in getAllFunctions():
        test_body(fn)

def test_body(fn):
    # fname = "main"
    # fn = getFunctionByName(fname) # Function
    # perform decompilation transformations on the low-level function
    hfunc = decompileHighFunction(fn) # HighFunction
    # get the transformed Function object (after decompilation)
    fn = hfunc.getFunction() # Function

    # Function
    name = fn.getName() # str
    entrypoint = fn.getEntryPoint() # Address
    params = fn.getParameters() # [Parameter]
    vars = fn.getAllVariables() # [Variable]
    rettype = fn.getReturnType() # DataType

    # DataType
    dtype = rettype
    size = 0 if dtype.isZeroLength() else dtype.getLength() # int (number of bytes)
    # dtypecls = dtype.getValueClass() # the class type of this instance
    # how to get the subtypes of DataType?

    print(name)
    print(rettype)
    print(entrypoint)
    print("PARAMS...")
    for param in params:
        dtype = param.getDataType()
        _cls = type(dtype)
        size = dtype.getLength()
        print("{} | size = {}".format(type(dtype).__name__, size))
        print(dir(dtype))
    print("VARS...")
    for var in vars:
        dtype = var.getDataType()
        _cls = type(dtype)
        size = dtype.getLength()
        print("{} | size = {}".format(type(dtype).__name__, size))
        print(dir(dtype))
    print('\n-----------------------------\n')


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
        return

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
        return 0 # MetaType.FLOAT
    
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
        return 0 # MetaType.INT

    elif clsname in [
        "VoidDataType"
    ]:
        return 0 # MetaType.VOID

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
        return 0 # MetaType.POINTER

    elif clsname in [
        "StructureDataType",
        "StructureDB"
    ]:
        return 0 # MetaType.STRUCT

    elif clsname in [
        "UnionDataType",
        "UnionDB"
    ]:
        return 0 # MetaType.UNION

    elif clsname in [
        "ArrayDataType"
    ]:
        return 0 # MetaType.ARRAY

    elif clsname in [
        "FunctionDefinitionDataType"
    ]:
        return 0 # MetaType.FUNCTION_PROTOTYPE

    elif clsname in [
        "TypedefDataType",
        "TypedefDB"
    ]:
        return 0 # MetaType.TYPEDEF

    elif clsname in [
        "EnumDataType"
    ]:
        return 0 # MetaType.ENUM

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
    ]:
        return 0 # MetaType.UNDEFINED

    else:
        raise NotImplementedError("No MetaType translation for class {}".format(clsname))



if __name__ == "__main__":
    test()