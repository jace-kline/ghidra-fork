# ghidra decompile
# @category: Research

# ref: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html

# flat program API
# from ghidra.app.flatapi import FlatProgramAPI

# to decompile
from lang import *
from resolve import *
from resolve_stubs import *
from parse_ghidra import *
from parse_ghidra_util import *

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

def test_highfns():
    for highfn in decompileAll():
        test_highfn(highfn)

def test_highfn(highfn):

    name = highfn.getFunction().getName()
    rettype = highfn.getFunctionPrototype().getReturnType()
    entrypoint = highfn.getFunction().getEntryPoint()
    params = getHighFunctionParams(highfn) # [HighParam]
    vars = getHighFunctionLocalVars(highfn) # [HighVariable]

    print(name)
    print(rettype)
    print(entrypoint)
    print("PARAMS...")
    for param in params:
        print(param)
    print("VARS...")
    for var in vars:
        print(var)
    print('\n-----------------------------\n')

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

    def print_paramvar_typeinfo(var):
        dtype = var.getDataType()
        _cls = type(dtype)
        size = dtype.getLength()
        typename = type(dtype).__name__
        metatype = get_metatype(dtype)
        metatyperepr = MetaType.repr(metatype)
        uid = dtype.getUniversalID()
        print("{} | size = {} | uid = {} | metatype = {}".format(typename, size, uid, metatyperepr))

    print(name)
    print(rettype)
    print(entrypoint)
    print("PARAMS...")
    for param in params:
        print_paramvar_typeinfo(param)
        # print(dir(dtype))
    print("VARS...")
    for var in vars:
        print_paramvar_typeinfo(var)
        # print(dir(dtype))
    print('\n-----------------------------\n')

def test_parse():
    parser = ParseGhidra()
    proginfo = parser.parse()
    proginfo.print_summary()

if __name__ == "__main__":
    test_parse()