# ghidra decompile
# @category: Research

# ref: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html

# flat program API
# from ghidra.app.flatapi import FlatProgramAPI

# to decompile
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

def main():
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

if __name__ == "__main__":
    main()