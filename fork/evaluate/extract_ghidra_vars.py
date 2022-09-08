# Extract Ghidra Vars & High-Level Vars for function(s)
# @category: Research

from parse_ghidra_util import *

util = GhidraUtil(getCurrentProgram(), getMonitor())

def indent_print(obj, indent):
    s = ("\t" * indent) + str(obj)
    print(s)

def main():
    target_fn_names = ["main", "myfunc"]
    decomp_highfns = [ highfn for highfn in util.get_decompiled_functions() if highfn.getFunction().getName() in target_fn_names ]

    for highfn in decomp_highfns: # highfn: HighFunction
        fn = highfn.getFunction() # fn: Function
        print("Function: {}".format(fn.getName()))
        indent_print("Variables:", 1)
        for var in fn.getAllVariables(): # var: Variable
            indent_print("Variable: {}".format(var), 2)
            sym = var.getSymbol() # Symbol
            indent_print("Symbol: {}".format(sym), 2)
            var_storage = var.getVariableStorage() # VariableStorage
            varnodes = var_storage.getVarnodes() # Iter[Varnode]
            indent_print("Varnodes:", 2)
            for varnode in varnodes: # Varnode
                highvar = varnode.getHigh() # HighVariable
                indent_print("Varnode: {}".format(varnode), 3)
                indent_print("HighVariable: {}".format(highvar), 3)
                descendants = varnode.getDescendants()
                if descendants:
                    indent_print("Varnode PCode Ops:", 3)
                    for pcodeop in descendants:
                        indent_print(pcodeop, 4)

        
        indent_print("Symbols:", 1)
        symmap = highfn.getLocalSymbolMap() # SymbolMap
        highsyms = symmap.getSymbols() # Iter[HighSymbol]
        for highsym in highsyms: # HighSymbol
            indent_print("HighSymbol: {}".format(highsym.getName()), 2)
            highvar = highsym.getHighVariable() # HighVariable
            indent_print("HighVariable: {}".format(highvar.getName()), 2)
            representative = highvar.getRepresentative() # Varnode
            varnodes = highvar.getInstances() # [Varnode]
            indent_print("Representative Varnode: {}".format(representative), 2)
            indent_print("Varnodes:", 2)
            for varnode in varnodes:
                indent_print("Varnode: {}".format(varnode), 3)
                descendants = varnode.getDescendants()
                if descendants:
                    indent_print("Varnode PCode Ops:", 3)
                    for pcodeop in descendants:
                        indent_print(pcodeop, 4)
            

if __name__ == "__main__":
    main()

