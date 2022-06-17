# ghidra decompile
# @category: Research

# ref: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html

# to decompile
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface

# globals
IFC = DecompInterface()
IFC.setOptions(DecompileOptions())
IFC.openProgram(currentProgram)

def getFunctionByName(fname): # returns Function (or None)
    fns = getGlobalFunctions(fname)
    return fns[0] if len(fns) > 0 else None
    
# decompile, returning DecompileResults
def decompile(fname): # returns DecompileResults
    fn = getFunctionByName(fname) # type: Function
    if fn is None:
        print("Error: No function with given name '{}'".format(fname))
        exit(1)
    
    res = IFC.decompileFunction(fn, 0, monitor) # type: DecompileResults

    # if failed to decompile, print error
    if not res.decompileCompleted():
        print("Error decompiling function '{}'".format(fname))
        print(res.getErrorMessage())
        exit(1)

    return res

# decompile, get C code as raw string
def decompileToRawC(fname): # returns str
    res = decompile(fname) # type: DecompileResults

    # get decompiled code
    decomp = res.getDecompiledFunction() # type: DecompiledFunction

    # from this, get C code as a string
    codestr = decomp.getC()
    return codestr

    # # get C code as XML document
    # tokgrp = res.getCCodeMarkup() # type: ClangTokenGroup

    # # get high-level syntax tree
    # hfunc = res.getHighFunction() # type: HighFunction

def main():
    args = getScriptArgs()

    if len(args) == 0:
        print("Error: Supply function name to decompile as script argument")
        exit(1)

    fname = args[0] # 1st arg = the function name to decompile
    codestr = decompileToRawC(fname)
    print(codestr)

if __name__ == "__main__":
    main()