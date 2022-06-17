# inform the decompiler process that debugger is attached
set variable debug = 1

# set breakpoint at main initialization function
b GhidraDecompCapability::initialize

# set breakpoints at the driver function for each GhidraCommand type
b DecompileAt::rawAction
b DeregisterProgram::rawAction
b FlushNative::rawAction
b RegisterProgram::rawAction
b SetAction::rawAction
b SetOptions::rawAction
b StructureGraph::rawAction
