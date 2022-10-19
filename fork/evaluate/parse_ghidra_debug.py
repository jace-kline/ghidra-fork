# Debug script for testing Ghidra API, etc.
# @category: Research

from parse_ghidra import *

parser = ParseGhidra()
util = parser.util

# HighFunction -> List[HighSymbol]
def get_highfn_local_var_highsyms(highfn):
    def is_local_var(sym):
            return not sym.isParameter()

    symmap = highfn.getLocalSymbolMap()
    return [ sym for sym in symmap.getSymbols() if is_local_var(sym) ]

# Is the address a stack, global, or register?
# Address -> bool
def is_valid_address(addr):
    return addr.isConstantAddress() or addr.isMemoryAddress() or addr.isStackAddress() or addr.isRegisterAddress()

def get_highfn_locals_all(highfn):
    fn = highfn.getFunction()
    highvarsyms = get_highfn_local_var_highsyms(highfn)
    lowvars = fn.getAllVariables()
    print(fn)

    print("\thigh-level variables:")
    addrs = []
    for highvarsym in highvarsyms:
        storage = highvarsym.getStorage()
        varnodes = storage.getVarnodes()
        varnode_addrs = [ varnode.getAddress() for varnode in varnodes ]
        addrs += varnode_addrs
        print("\t\t{} @ {}".format(highvarsym.getName(), varnode_addrs))
        

    print("\tlow-level variables:")
    lowvars_keep = []
    for lowvar in lowvars:
        storage = lowvar.getVariableStorage()
        varnodes = storage.getVarnodes()
        varnode_addrs = [ varnode.getAddress() for varnode in varnodes ]
        does_overlap = any([ (varnode_addr in addrs) for varnode_addr in varnode_addrs ])
        print("\t\t{} @ {} -> {}".format(lowvar, varnode_addrs, does_overlap))

highfns = list(util.get_decompiled_functions())
# fns = [ highfn.getFunction() for highfn in highfns ]
# for highfn in highfns:
#     fn = highfn.getFunction()
#     highvars = get_highfn_local_var_highsyms(highfn)
#     lowvars = fn.getAllVariables()
#     print(fn)

#     print("\thigh-level variables:")
#     addrs = []
#     for highvar in highvars:
#         storage = highvar.getStorage()
#         varnodes = storage.getVarnodes()
#         varnode_addrs = [ varnode.getAddress() for varnode in varnodes ]
#         addrs += varnode_addrs
#         print("\t\t{} @ {}".format(highvar.getName(), varnode_addrs))
        

#     print("\tlow-level variables:")
#     for lowvar in lowvars:
#         storage = lowvar.getVariableStorage()
#         varnodes = storage.getVarnodes()
#         varnode_addrs = [ varnode.getAddress() for varnode in varnodes ]
#         does_overlap = any([ (varnode_addr in addrs) for varnode_addr in varnode_addrs ])
#         print("\t\t{} @ {} -> {}".format(lowvar, varnode_addrs, does_overlap))

gblhighsyms = list(util.get_referenced_global_vars())
localhighsyms = sum([ list(util.get_highfn_local_vars(highfn)) for highfn in util.get_decompiled_functions()], [])
highsyms = gblhighsyms + localhighsyms

addrs = []
for highsym in highsyms:
    storage = highsym.getStorage()
    varnodes = storage.getVarnodes()
    varnode_addrs = [ varnode.getAddress() for varnode in varnodes ]
    addrs += varnode_addrs

for addr in addrs:
    space = addr.getAddressSpace()
    spacename = space.getName()
    print("{} in {}".format(
        addr,
        space
    ))
