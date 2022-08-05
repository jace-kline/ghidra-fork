## Common variable, function, and datatype representations for DWARF/Ghidra
from lang_address import *
from lang_datatype import *

# hold the results of a translation into this common language
# from either DWARF info or Ghidra decompilation
class ProgramInfo(object):
    def __init__(self, globals=[], functions=[]):
        self.globals = globals
        self.functions = functions

    def get_globals(self):
        return self.globals

    def get_functions(self):
        return self.functions

    def print_summary(self):
        print("----------------GLOBALS----------------------")
        for gbl in self.globals:
            print(gbl)


        print("----------------FUNCTIONS--------------------")
        for fn in self.functions:
            fn.print_summary()

class Function(object):
    """
    Represents the debugging/decompilation information for a function.
    """
    def __init__(self, name=None, startaddr=None, endaddr=None, rettype=None, params=[], vars=[], variadic=False):
        """
        name: str
            The name of the function
        startaddr: Address
            The entrypoint address (global) of the function
        endaddr: Address
            The address of the last instruction in the function.
        proto: DataTypeFunctionPrototype
            The prototype of the function.
            Return type + parameter types.
        params: [Variable]
            A list of the function's parameters.
        vars: [Variable]
            A list of non-parameter variables declared and used within the body of the function.
        """
        self.name = name
        self.startaddr = startaddr
        self.endaddr = endaddr
        self.rettype = rettype
        self.params = params
        self.vars = vars
        self.variadic = variadic

    # if start and end addrs are None, this function is inlined
    # and doesn't occupy its own location in the binary
    def is_inlined(self):
        return self.startaddr is None and self.endaddr is None

    # returns DataTypeFunctionPrototype
    def get_prototype(self):
        return DataTypeFunctionPrototype(
            rettype=self.rettype,
            paramtypes=[ param.dtype for param in self.params ],
            variadic=self.variadic
        )

    def get_pc_range(self):
        return AddressRange(self.startaddr, end=self.endaddr)

    def get_params(self):
        """ Returns the list of parameter Variable objects in the correct order """
        return [ v for v in self.vars if v.is_param() ]

    def same(self, other):
        return self.startaddr == other.startaddr

    def print_summary(self):
        print("{} :: {} @ PC range=({}, {})".format(self.name, self.get_prototype(), self.startaddr, self.endaddr))
        for var in (self.params + self.vars):
            print("\t{}".format(var))

class Variable(object):
    def __init__(self, name=None, dtype=None, liveranges=None, param=False, function=None):
        """
        name: str
            The variable's name
        dtype: DataType
            The data type of the variable
        liveranges: AddressLiveRangeSet
            The location this variable occupies throughout its lifetime.
            In unoptimized compilation, this usually will include only one address.
            However, live ranges and register splitting could be used in optimized compilation.
        param: bool
            Is this variable a parameter?
        function: Function | None
            The parent function, or None if global.
        """
        self.name = name
        self.dtype = dtype
        self.liveranges = liveranges # AddressLiveRangeSet
        self.param = param
        self.function = function

    def is_param(self):
        """ Is this variable a parameter? """
        return self.param

    def is_global(self):
        """ Is this variable a global variable? """
        return self.function is None

    def get_member_as_variable(self):
        pass

    # for the given PC, find the Address where this Variable resides (or None).
    def get_address_at_pc(self, pc):
        if self.is_global():
            return self.liveranges[0].addr
        return self.liveranges.get_address_at_pc(pc)

    def __str__(self):
        lbl = "PARAM" if self.is_param() else "VAR"
        return "<{} {} :: {} @ {}>".format(lbl, self.name, self.dtype, self.liveranges)

