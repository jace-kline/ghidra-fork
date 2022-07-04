## Common variable, function, and datatype representations for DWARF/Ghidra

# hold the results of a translation into this common format
# from either DWARF info or Ghidra decompilation
class Translation:
    def __init__(self, globals=[], functions=[]):
        self.globals = globals
        self.functions = functions

class Variable:
    def __init__(self, name=None, dtype=None, addr=None, param=False, function=None):
        """
        name: str
            The variable's name
        dtype: DataType
            The data type of the variable
        addr: Address
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
        self.addr = addr
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

class Function:
    """
    Represents the debugging/decompilation information for a function.
    """
    def __init__(self, name=None, startaddr=None, prototype=None, params=[], vars=[]):
        """
        name: str
            The name of the function
        startaddr: Address
            The entrypoint address (global) of the function
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
        self.prototype = prototype
        self.params = params
        self.vars = vars

    def get_params(self):
        """ Returns the list of parameter Variable objects in the correct order """
        return [ v for v in self.vars if v.is_param() ]

    def same(self, other):
        return self.startaddr == other.startaddr

class AddressSpace:
    STACK = 0
    HEAP = 1
    GLOBAL = 2
    REGISTER = 3
    UNKNOWN = 4

class Address:
    """
    An Address is defined by the space it lives in (stack, heap, global, register)
    and the offset from the base of that space.
    """
    def __init__(self, addrspace=None, offset=None):
        """
        addrspace: field of AddressSpace
            The address space the address lives in (STACK | HEAP | GLOBAL | REGISTER)
        offset: int
            The offset from the base of the address space...
            If the space=STACK, then offset is from RBP or RSP, depending on compiler and optimization level.
            If the space=HEAP, then the offset is from the malloc'd pointer.
            If the space=GLOBAL, then the offset is the raw address of the variable.
            If the space=REGISTER, then the offset is the register identifier #.
        """
        self.addrspace = addrspace
        self.offset = offset

    def __eq__(self, other):
        return self.addrspace == other.addrspace and self.offset == other.offset

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

class DataType:
    """
    The base class for representing a data type.
    Contains a "meta type" and size.
    Subclasses contain more specified information.
    """
    def __init__(self, metatype=None, size=None, resolved=False):
        """
        metatype: field of MetaType class
            The meta type of the datatype.
            options = INT | FLOAT | POINTER | ARRAY | STRUCT | UNION | UNDEFINED | VOID | FUNCTION_PROTOTYPE
        size: int
            The total size of the datatype
        resolved: bool
            Are all of this datatype's fields filled & subtypes resolved?
        """
        self.metatype = metatype
        self.size = size
        self.resolved = resolved

    def set_resolved(self, b):
        self.resolved = b

class DataTypeFunctionPrototype(DataType):
    """
    Data type representing a function prototype.
    Could be pointed to by function pointer.
    Used as 'proto' argument for creating a Function object.
    """
    def __init__(self, rettype=None, paramtypes=None, resolved=False):
        super().__init__(
            metatype=MetaType.FUNCTION_PROTOTYPE,
            size=0,
            resolved=resolved
        )
        self.rettype = rettype
        self.paramtypes = paramtypes


class DataTypeInt(DataType):
    """
    Data type representing int/char, possibly unsigned.
    """
    def __init__(self, size=None, signed=True):
        super().__init__(
            metatype=MetaType.INT,
            size=size,
            resolved=True
        )
        self.signed = signed

    def is_signed(self):
        return self.signed

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
        super().__init__(
            metatype=MetaType.FLOAT,
            size=size,
            resolved=True
        )

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
        super().__init__(
            metatype=MetaType.UNDEFINED,
            size=size,
            resolved=True
        )

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
        super().__init__(
            metatype=MetaType.VOID,
            size=0,
            resolved=True
        )

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
        super().__init__(
            metatype=MetaType.POINTER,
            size=size,
            resolved=resolved
        )
        self.basetype = basetype

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
    def __init__(self, basetype=None, length=None, size=None, resolved=False):
        """
        basetype: DataType
            The type of the elements in the array
        length: int
            The length of the array. -1 if unknown.
        size: int
            The total number of bytes allocated to the array. -1 if unknown.
        """
        if size is None and resolved:
            size = basetype.size * length
        super().__init__(
            metatype=MetaType.ARRAY,
            size=size,
            resolved=resolved
        )
        self.basetype = basetype
        self.length = length

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
    def __init__(self, name=None, membertypes=None, recursive=False, size=None, resolved=False):
        """
        membertypes: [DataType]
            The data types of the members of the struct.
        cycle: bool
            Does this struct form a recursive/mutually-recursive cycle?
        """
        self.name = name
        self.membertypes = membertypes
        if size is None and resolved: # if explicit size not provided, calculate on our own
            size = sum([ mem.size for mem in membertypes ])
        super().__init__(
            metatype=MetaType.STRUCT,
            size=size,
            resolved=resolved
        )

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
    def __init__(self, name=None, membertypes=None, size=None, resolved=False):
        """
        membertypes: [DataType]
            The data types of that could possibly be instantiated in the union.
        """
        self.name = name
        self.membertypes = membertypes
        if size is None and resolved: # if explicit size not provided, calculate on our own
            size = max([ mem.size for mem in membertypes ])
        super().__init__(
            metatype=MetaType.UNION,
            size=size
        )

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