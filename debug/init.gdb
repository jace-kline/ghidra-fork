# inform the decompiler process that debugger is attached
set variable debug = 1

# set breakpoint at main initialization function
b GhidraDecompCapability::initialize

# set breakpoint at function that handles
# decompiling a function address
b DecompileAt::rawAction
