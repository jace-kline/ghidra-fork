# Debug script for testing Ghidra API, etc.
# @category: Research

from parse_ghidra import *
from parse_ghidra_util import VariableInfo

parser = ParseGhidra()
util = parser.util

# Is the address a stack, global, or register?
# Address -> bool
def is_valid_address(addr):
    return addr.isConstantAddress() or addr.isMemoryAddress() or addr.isStackAddress() or addr.isRegisterAddress()

proginfo = parser.parse()
proginfo.print_summary()

# highfns = list(util.get_decompiled_functions())
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

# for highfn in highfns:
#     fn = highfn.getFunction()
#     paramvars = util.get_highfn_params(highfn)
#     localvars = util.get_highfn_local_vars(highfn)
# #     highsyms = get_highfn_local_var_highsyms(highfn)
# #     lowvars = fn.getAllVariables()

#     print(fn.getName())
#     # print(paramvars)
#     # print(localvars)
    
# #     print(merge_low_high_vars(lowvars, highsyms))
# #     print
#     print("\tparams:")
#     for param in paramvars:
#         print("\t\t{}".format(param))

#     print("\tlocals:")
#     for local in localvars:
#         print("\t\t{}".format(local))

# gblhighsyms = list(util.get_referenced_global_vars())
# localhighsyms = sum([ list(util.get_highfn_local_vars(highfn)) for highfn in util.get_decompiled_functions()], [])
# highsyms = gblhighsyms + localhighsyms

# addrs = []
# for highsym in highsyms:
#     storage = highsym.getStorage()
#     varnodes = storage.getVarnodes()
#     varnode_addrs = [ varnode.getAddress() for varnode in varnodes ]
#     addrs += varnode_addrs

# for addr in addrs:
#     space = addr.getAddressSpace()
#     spacename = space.getName()
#     print("{} in {}".format(
#         addr,
#         space
#     ))
