from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.app.util.opinion import ElfLoader
from ghidra.app.util.bin.format.dwarf4.next import DWARFRegisterMappingsManager
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import Address

# This class tries to encapsulate the inherently stateful properties of
# the Ghidra scripting enviornment to avoid a bunch of global variables
# while also avoiding duplicate computation and unnecessary parameters.
class GhidraUtil(object):
    # perform setup
    def __init__(self, curr, monitor):
        # current Program to act on
        self.curr = curr # getCurrentProgram()
        # the program monitor
        self.monitor = monitor # getMonitor()
        # the FlatProgramAPI
        self.flatapi = FlatProgramAPI(self.curr, self.monitor)

        # self.decompiler :: DecompInterface
        self.decompiler = self._generate_decomp_interface()

        # self.reg_d2g_map :: dict[int->int]
        # self.reg_g2d_map :: dict[int->int]
        # self.dwarf_stack_regnum :: int
        self.reg_d2g_map, self.reg_g2d_map, self.dwarf_stack_regnum = self._generate_register_mappings()

        self.image_base = self.curr.getImageBase().getOffset()
        self.orig_base = ElfLoader.getElfOriginalImageBase(self.curr)

    def _generate_register_mappings(self):
        MAX_REGS = 128
        lang = self.curr.getLanguage()
        d2g_mapping = DWARFRegisterMappingsManager.getMappingForLang(lang)
        reg_d2g_map = {} # map DWARF regnum -> Ghidra regnum (Register.getOffset())
        reg_g2d_map = {} # map Ghidra regnum -> DWARF regnum
        for dwarf_regnum in range(MAX_REGS):
            reg = d2g_mapping.getGhidraReg(dwarf_regnum)
            if reg:
                ghidra_regnum = reg.getOffset()
                reg_d2g_map[dwarf_regnum] = ghidra_regnum
                reg_g2d_map[ghidra_regnum] = dwarf_regnum
        dwarf_stack_regnum = d2g_mapping.getDWARFStackPointerRegNum()
        return reg_d2g_map, reg_g2d_map, dwarf_stack_regnum

    # int -> int | None
    def dwarf2ghidra_register(self, regnum):
        return self.reg_d2g_map.get(regnum, None)

    # int -> int | None
    def ghidra2dwarf_register(self, reg_offset):
        return self.reg_g2d_map.get(reg_offset, None)

    # () -> DecompInterface
    def _generate_decomp_interface(self):
        decompiler = DecompInterface()
        opts = DecompileOptions()
        opts.grabFromProgram(self.curr)
        decompiler.setOptions(opts)
        decompiler.toggleCCode(True)
        decompiler.toggleSyntaxTree(True)
        decompiler.setSimplificationStyle("decompile")
        decompiler.openProgram(self.curr)
        return decompiler

    # int -> int
    def resolve_absolute_address(self, absaddr):
        return absaddr - self.image_base + self.orig_base

    # we want stack frame offsets to be from the Canonical Frame Address (directly below saved RIP)
    # instead of below the saved base pointer
    # int -> int
    def resolve_stack_frame_offset(self, offset):
        return offset - self.curr.getDefaultPointerSize()

    # Function -> DecompileResults
    def decompile_function(self, func):
        return self.decompiler.decompileFunction(func, 0, self.monitor)

    # get HighFunction from DecompileResults by calling .getHighFunction()
    # HighFunction -> Iter<HighSymbol>
    def get_highfn_params(self, highfn):
        symmap = highfn.getLocalSymbolMap()
        return (symmap.getParam(i).getSymbol() for i in range(symmap.getNumParams()) if symmap.getParam(i))

        # HighSymbol info...
        # .getName(), .getDataType(), .getPCAddress(), .getStorage(), .isParameter()

    # get the non-parameter local variables of a HighFunction object
    # HighFunction -> Iter<HighSymbol>
    def get_highfn_local_vars(self, highfn):
        # Is the given HighSymbol a local (non-parameter) variable
        # HighSymbol -> bool
        def is_local_var(sym):
            return not sym.isParameter()

        symmap = highfn.getLocalSymbolMap()
        return (sym for sym in symmap.getSymbols() if is_local_var(sym))

    # Get the global variable HighSymbol objects referenced in this function
    # HighFunction -> Iter<HighSymbol>
    def get_highfn_global_vars(self, highfn):

        # HighSymbol -> bool
        def is_global_var(sym):
            return sym.isGlobal() and sym.getSymbol().getSymbolType() in (SymbolType.GLOBAL_VAR, SymbolType.LABEL)
        
        symmap = highfn.getGlobalSymbolMap()
        return (sym for sym in symmap.getSymbols() if is_global_var(sym))

    # Iterator global variable HighSymbol objects from the target binary that are referenced
    # from at least one of the decompiled functions.
    # () -> Iter<HighSymbol>
    def get_referenced_global_vars(self):
        refs = [] # holds unique ids for each seen global
        for highfn in self.get_decompiled_functions():
            for gblsym in self.get_highfn_global_vars(highfn):
                if id(gblsym) not in refs:
                    refs.append(id(gblsym))
                    yield gblsym
    
    # () -> Iter<Function>
    def get_functions(self, filter=True):
        # names that should be filtered out
        BLACKLIST = [ "_init", "_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "__libc_csu_init", "__libc_csu_fini", "_fini"]

        # Function -> bool
        def valid_fn(fn):
            return True if not filter else not fn.isExternal() and not fn.isThunk() and fn.getName() not in BLACKLIST
        
        fm = self.curr.getFunctionManager()
        funcs = ( fn for fn in fm.getFunctionsNoStubs(True) if valid_fn(fn) )
        return funcs

    # Get the absolute addresses where a Function starts and ends.
    # Function -> (int, int)
    def get_function_pc_range(self, func):
        start = func.getEntryPoint().getOffset()
        end = func.getBody().getMaxAddress().getOffset() + 2 # TODO: figure out how to fix this
        return (
            self.resolve_absolute_address(start),
            self.resolve_absolute_address(end)
        )

    # Does the function range fall within executable sections of the binary?
    # Function -> bool
    def is_function_executable(self, func):
        f_start, f_end = self.get_function_pc_range(func)
        # Check for functions inside executable segments
        for s in self.curr.getMemory().getExecuteSet().getAddressRanges(True):
            if f_start >= self.resolve_absolute_address(s.getMinAddress().getOffset()) and f_end <= self.resolve_absolute_address(s.getMaxAddress().getOffset()):
                return True
        return False

    # str -> Function | None
    def get_function_by_name(self, fname):
        fns = self.curr.getListing().getGlobalFunctions(fname)
        return fns[0] if len(fns) > 0 else None

    # Address (Ghidra) -> Function (Ghidra) | None
    def get_function_by_start_addr(self, addr):
        return self.curr.getListing().getFunctionAt(addr)

    # For each function, decompile and yield the DecompileResults.
    # Consumer should check whether the decompilation succeeded.
    # () -> Iter<DecompileResults>
    def get_decompile_results(self):
        return (self.decompile_function(fn) for fn in self.get_functions())

    # Iterates over DecompileResults for each Function and maps them to their HighFunction.
    # Discards any where decompilation failed/timed out.
    # () -> Iter<HighFunction>
    def get_decompiled_functions(self):

        # DecompileResults -> bool
        def is_decompile_success(res):
            return res.decompileCompleted()

        return (res.getHighFunction() for res in self.get_decompile_results() if is_decompile_success(res))

    # For a given Varnode (P-Code SSA Variable), return the absolute address range it spans during its lifetime.
    # Varnode -> (int, int|None) | None
    def get_varnode_pc_range(self, varnode):
        # get all Pcode instructions that use this Varnode
        pcode_ops = varnode.getDescendants() # Iter<PcodeOp>
        # get native instruction addresses (PCs) for each PcodeOp's sequence number
        op_instr_addrs = ( op.getSeqnum().getTarget() for op in pcode_ops ) if pcode_ops else None
        # we assume that each Address is absolute (if valid) -> grab offset only
        pc_addrs = [ self.resolve_absolute_address(addr.getOffset()) for addr in op_instr_addrs if GhidraUtil.is_valid_address(addr) ] if op_instr_addrs else None

        # select min and max PC addresses, if non-empty list
        startpc = min(pc_addrs) if pc_addrs else None
        endpc = max(pc_addrs) if pc_addrs else None

        # cross check start address via Varnode.getPCAddress()
        # could cause NullPointerException??
        try:
            startaddr = varnode.getPCAddress()
        except:
            startaddr = None
        _startpc = self.resolve_absolute_address(startaddr.getOffset()) if startaddr and self.is_valid_address(startaddr) else None
        startpc = \
            min(startpc, _startpc) if (startpc and _startpc) \
            else \
                (startpc if startpc \
                    else \
                        (_startpc if _startpc else None))

        # if we don't know the start PC, then all is lost -> return None
        if not startpc:
            return None

        # the endpc could be None
        return (startpc, endpc)

    # returns whether a Ghidra Address is considered valid by Ghidra
    # Address (Ghidra) -> bool
    def is_valid_address(self, addr):
        return addr != Address.NO_ADDRESS

