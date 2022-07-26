## Common variable, function, and datatype representations for DWARF/Ghidra

# hold the results of a translation into this common format
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

class Variable(object):
    def __init__(self, name=None, dtype=None, liveranges=[], param=False, function=None):
        """
        name: str
            The variable's name
        dtype: DataType
            The data type of the variable
        liveranges: [AddressLiveRange]
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
        self.liveranges = liveranges
        self.param = param
        self.function = function

    def is_param(self):
        """ Is this variable a parameter? """
        return self.param

    def is_global(self):
        """ Is this variable a global variable? """
        return self.function is None

    def same(self, other):
        """
        Does this variable (self) reference the same underlying variable as the input (other)?
        other: Variable
        return: bool
        """
        pass

    def __str__(self):
        lbl = "PARAM" if self.is_param() else "VAR"
        return "<{} {} :: {} @ {}>".format(lbl, self.name, self.dtype, self.liveranges)

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

    def get_params(self):
        """ Returns the list of parameter Variable objects in the correct order """
        return [ v for v in self.vars if v.is_param() ]

    def same(self, other):
        return self.startaddr == other.startaddr

    def print_summary(self):
        print("{} :: {} @ PC range=({}, {})".format(self.name, self.get_prototype(), self.startaddr, self.endaddr))
        for var in (self.params + self.vars):
            print("\t{}".format(var))

class AddressType:
    ABSOLUTE = 0
    REGISTER = 1
    REGISTER_OFFSET = 2
    EXTERNAL = 3
    UNKNOWN = 4

    @staticmethod
    def to_string(addrtype):
        if addrtype == AddressType.ABSOLUTE:
            return "ABSOLUTE"
        elif addrtype == AddressType.REGISTER:
            return "REGISTER"
        elif addrtype == AddressType.REGISTER_OFFSET:
            return "REGISTER_OFFSET"
        elif addrtype == AddressType.UNKNOWN:
            return "UNKNOWN"
        elif addrtype == AddressType.EXTERNAL:
            return "EXTERNAL"
        else:
            raise Exception("Invalid AddressType specifier {}".format(addrtype))

class Address(object):
    def __init__(self, addrtype):
        self.addrtype = addrtype

    def __str__(self):
        return "<{}>".format(AddressType.to_string(self.addrtype))

class AbsoluteAddress(Address):
    def __init__(self, addr):
        super(AbsoluteAddress, self).__init__(addrtype=AddressType.ABSOLUTE)
        self.addr = addr

    def __str__(self):
        return "<{}:{:#x}>".format(AddressType.to_string(self.addrtype), self.addr)

class RegisterAddress(Address):
    def __init__(self, register):
        super(RegisterAddress, self).__init__(addrtype=AddressType.REGISTER)
        self.register = register

    def __str__(self):
        return "<{}:{}>".format(AddressType.to_string(self.addrtype), self.register)

class RegisterOffsetAddress(Address):
    def __init__(self, register, offset):
        super(RegisterOffsetAddress, self).__init__(addrtype=AddressType.REGISTER_OFFSET)
        self.register = register
        self.offset = offset

    def __str__(self):
        negative = self.offset < 0
        opstr = "-" if negative else "+"
        offsetstr = -1 * self.offset if negative else self.offset
        return "<{}:reg({}){}{:#x}>".format(AddressType.to_string(self.addrtype), self.register, opstr, offsetstr)

class ExternalAddress(Address):
    def __init__(self):
        super(ExternalAddress, self).__init__(addrtype=AddressType.EXTERNAL)

class UnknownAddress(Address):
    def __init__(self):
        super(ExternalAddress, self).__init__(addrtype=AddressType.UNKNOWN)

# defines the mapping from x86-64 register names
# to their associated register numbers
# ref: https://docs.rs/gimli/0.13.0/gimli/struct.UnwindTableRow.html#method.register
class RegsX86_64(object):
    RAX = 0
    RDX = 1
    RCX = 2
    RBX = 3
    RSI = 4
    RDI = 5
    RBP = 6
    RSP = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15
    RA = 16


class AddressLiveRange(object):
    """
    This class represents the association between an Address (stack location, register, etc.)
    and the PC range that it is considered "alive" for a particular variable.
    In unoptimized code, the live range of a local variable should span the entire function
    since it will be placed on the stack.

    addr: Address
        The address where the variable is stored.
    startpc: Address
        The start PC address of the live range.
    endpc: Address
        The address of the PC of the last instruction in the live range.

    """
    def __init__(self, addr=None, startpc=None, endpc=None):
        self.addr = addr
        self.startpc = startpc
        self.endpc = endpc

    # if startpc & endpc are both None, this range is considered global
    def is_global(self):
        return self.startpc.offset is None and self.endpc.offset is None

    def __str__(self):
        return "<AddressLiveRange addr={} startpc={} endpc={}>".format(self.addr, self.startpc, self.endpc)

    def __repr__(self):
        return self.__str__()

# enum of "meta types"
class MetaType:
    """
    Enumeration of "meta types".

    INT: int/char
    FLOAT: float/double
    POINTER: pointer to another type
    ARRAY: a sequence of elements of another type
    UNION: an "either-or" disjunctive type sharing the same memory space
    UNDEFINED: a sized type of unknown classification
    VOID: a 0-sized type
    FUNCTION_PROTOTYPE: a type containing a return type + list of parameter types
    TYPEDEF: a type that exists as an alias of another type
    ENUM: a type consisting of a discrete subset of "tagged" integers
    QUALIFIER: a "wrapper" type that qualifies another type (const, volatile, etc.)
    STRING: a high-level string, usually represented as a char array
    """
    INT = 0
    FLOAT = 1
    POINTER = 2
    ARRAY = 3
    STRUCT = 4
    UNION = 5
    UNDEFINED = 6
    VOID = 7
    FUNCTION_PROTOTYPE = 8
    TYPEDEF = 9
    ENUM = 10
    QUALIFIER = 11
    STRING = 12

    @staticmethod
    def repr(metatype_code):
        metatypes = [
            "INT",
            "FLOAT",
            "POINTER",
            "ARRAY",
            "STRUCT",
            "UNION",
            "UNDEFINED",
            "VOID",
            "FUNCTION_PROTOTYPE",
            "TYPEDEF",
            "ENUM",
            "QUALIFIER",
            "STRING"
        ]
        return metatypes[metatype_code]

class DataType(object):
    """
    The base class for representing a data type.
    Contains a "meta type" and size.
    Subclasses contain more specified information.
    """
    def __init__(self, metatype=None, size=None):
        """
        metatype: field of MetaType class
            The meta type of the datatype.
            options = INT | FLOAT | POINTER | ARRAY | STRUCT | UNION | UNDEFINED | VOID | FUNCTION_PROTOTYPE | TYPEDEF | ENUM | QUALIFIER
        size: int
            The total size of the datatype
        """
        self.metatype = metatype
        self.size = size

    def __str__(self):
        pass # implement in children

class DataTypeFunctionPrototype(DataType):
    """
    Data type representing a function prototype.
    Could be pointed to by function pointer.
    Used as 'proto' argument for creating a Function object.
    """
    def __init__(self, rettype=None, paramtypes=None, variadic=False):
        super(DataTypeFunctionPrototype, self).__init__(
            metatype=MetaType.FUNCTION_PROTOTYPE,
            size=0
        )
        self.rettype = rettype
        self.paramtypes = paramtypes
        self.variadic = variadic

    def __str__(self):
        s = "("
        for i, paramtype in enumerate(self.paramtypes):
            s += str(paramtype)
            if i + 1 < len(self.paramtypes):
                s += ", "
        s += ") -> " + str(self.rettype)
        return s


class DataTypeInt(DataType):
    """
    Data type representing int/char, possibly unsigned.
    """
    def __init__(self, size=None, signed=True):
        super(DataTypeInt, self).__init__(
            metatype=MetaType.INT,
            size=size
        )
        self.signed = signed

    def is_signed(self):
        return self.signed

    def __str__(self):
        s = ""
        if not self.signed:
            s += "unsigned "

        if self.size == 1:
            s += "char"
        else:
            s += "int" + str(self.size)
        return s

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj

class DataTypeFloat(DataType):
    """
    Datatype representing float/double.
    """
    def __init__(self, size=None):
        super(DataTypeFloat, self).__init__(
            metatype=MetaType.FLOAT,
            size=size
        )

    def __str__(self):
        return "float" + str(self.size)

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj

class DataTypeUndefined(DataType):
    """
    A sized but undefined datatype.
    """
    def __init__(self, size=None):
        super(DataTypeUndefined, self).__init__(
            metatype=MetaType.UNDEFINED,
            size=size
        )

    def __str__(self):
        return "undefined" + str(self.size)

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj

class DataTypeVoid(DataType):
    """
    Void datatype (size = 0).
    """
    def __init__(self):
        super(DataTypeVoid, self).__init__(
            metatype=MetaType.VOID,
            size=0
        )
    
    def __str__(self):
        return "void"

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj

class DataTypePointer(DataType):
    """
    Datatype representing a pointer of some base type.
    """
    def __init__(self, basetype=None, size=None, resolved=False):
        """
        basetype: DataType
            The type of the object being pointed to
        """
        super(DataTypePointer, self).__init__(
            metatype=MetaType.POINTER,
            size=size
        )
        self.basetype = basetype

    def __str__(self):
        return str(self.basetype) + " *"

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj


class DataTypeArray(DataType):
    def __init__(self, basetype=None, length=None, size=None):
        """
        basetype: DataType
            The type of the elements in the array
        length: int
            The length of the array. -1 if unknown.
        size: int
            The total number of bytes allocated to the array. -1 if unknown.
        """
        # if size is None:
        #     size = basetype.size * length
        super(DataTypeArray, self).__init__(
            metatype=MetaType.ARRAY,
            size=size
        )
        self.basetype = basetype
        self.length = length

    def length_unknown(self):
        return self.length <= 1 or self.length is None or not self.resolved

    def __str__(self):
        return "<ARRAY (subtype = {}) (length = {})>".format(str(self.basetype), self.size)

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj

class DataTypeStruct(DataType):
    """
    Datatype representing a C struct.
    """
    def __init__(self, name=None, membertypes=None, size=None):
        """
        membertypes: [DataType]
            The data types of the members of the struct.
        cycle: bool
            Does this struct form a recursive/mutually-recursive cycle?
        """
        self.name = name
        self.membertypes = membertypes
        # if size is None: # if explicit size not provided, calculate on our own
        #     size = sum([ mem.size for mem in membertypes ])
        super(DataTypeStruct, self).__init__(
            metatype=MetaType.STRUCT,
            size=size
        )

    def __str__(self):
        s = "<STRUCT "
        if self.name is not None:
            s += self.name

        s += "(members = {}) ".format(len(self.membertypes))
        s += "(size = {})>".format(self.size)

        return s

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj

class DataTypeUnion(DataType):
    """
    Datatype representing a C union type.
    """
    def __init__(self, name=None, membertypes=None, size=None):
        """
        membertypes: [DataType]
            The data types of that could possibly be instantiated in the union.
        """
        self.name = name
        self.membertypes = membertypes
        # if size is None: # if explicit size not provided, calculate on our own
        #     size = max([ mem.size for mem in membertypes ])
        super(DataTypeUnion, self).__init__(
            metatype=MetaType.UNION,
            size=size
        )

    def __str__(self):
        s = "<UNION "
        if self.name is not None:
            s += self.name

        s += "(members = {}) ".format(len(self.membertypes))
        s += "(size = {})>".format(self.size)

        return s

    @classmethod
    def from_DataType(cls, dtype):
        # Create new child obj from DataType base instance
        obj = cls()
        # Copy all values of A to B
        # It does not have any problem since they have common template
        for key, value in dtype.__dict__.items():
            obj.__dict__[key] = value
        return obj

def test():
    pass

if __name__ == "__main__":
    test()