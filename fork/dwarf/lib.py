## Common variable, function, and datatype representations for DWARF/Ghidra

class Variable:
    def __init__(self, name=None, dtype=None, addr=None, param=False, gbl=False):
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
        gbl: bool
            Is this variable a global variable?
        """
        self.name = name
        self.dtype = dtype
        self.addr = addr
        self.param = param
        self.gbl = gbl

    def is_param(self):
        """ Is this variable a parameter? """
        return self.param

    def is_global(self):
        """ Is this variable a global variable? """
        return self.gbl

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
    def __init__(self, name=None, startaddr=None, rettype=None, vars=None):
        """
        name: str
            The name of the function
        startaddr: Address
            The entrypoint address (global) of the function
        rettype: DataType
            The return type of the function
        vars: [Variable]
            A list of non-parameter variables declared and used within the body of the function
        """
        self.name = name
        self.startaddr = startaddr
        self.rettype = rettype
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
    BOOL: a boolean (0 or 1)
    """
    INT = 0
    FLOAT = 1
    POINTER = 2
    ARRAY = 3
    STRUCT = 4
    UNION = 5
    UNDEFINED = 6
    VOID = 7

class DataType:
    """
    The base class for representing a data type.
    Contains a "meta type" and size.
    Subclasses contain more specified information.
    """
    def __init__(self, metatype=None, size=None):
        """
        metatype: field of MetaType class
            The meta type of the datatype.
            options = INT | FLOAT | POINTER | ARRAY | STRUCT | UNION | UNDEFINED | VOID
        size: int
            The total size of the datatype
        """
        self.metatype = metatype
        self.size = size

class DataTypeInt(DataType):
    """
    Data type representing int/char, possibly unsigned.
    """
    def __init__(self, size=None, signed=True):
        super().__init__(
            metatype=MetaType.INT,
            size=size
        )
        self.signed = signed

    def is_signed(self):
        return self.signed

class DataTypeFloat(DataType):
    """
    Datatype representing float/double.
    """
    def __init__(self, size=None):
        super().__init__(
            metatype=MetaType.FLOAT,
            size=size
        )

class DataTypeUndefined(DataType):
    """
    A sized but undefined datatype.
    """
    def __init__(self, size=None):
        super().__init__(
            metatype=MetaType.UNDEFINED,
            size=size
        )

class DataTypeVoid(DataType):
    """
    Void datatype (size = 0).
    """
    def __init__(self):
        super().__init__(
            metatype=MetaType.VOID,
            size=0
        )

class DataTypePointer(DataType):
    """
    Datatype representing a pointer of some base type.
    """
    def __init__(self, basetype=None, size=None):
        """
        basetype: DataType
            The type of the object being pointed to
        """
        super().__init__(
            metatype=MetaType.POINTER,
            size=size
        )
        self.basetype = basetype

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
        super().__init__(
            metatype=MetaType.ARRAY,
            size=(size if size is not None else (basetype.size * length))
        )
        self.basetype = basetype
        self.length = length

class DataTypeStruct(DataType):
    """
    Datatype representing a C struct.
    """
    def __init__(self, name=None, membertypes=[], size=None):
        """
        membertypes: [DataType]
            The data types of the members of the struct.
        """
        self.name = name
        self.membertypes = membertypes
        if size is None: # if explicit size not provided, calculate on our own
            size = sum([ mem.size for mem in membertypes ])
        super().__init__(
            metatype=MetaType.STRUCT,
            size=size
        )

class DataTypeUnion(DataType):
    """
    Datatype representing a C union type.
    """
    def __init__(self, name=None, membertypes=[], size=None):
        """
        membertypes: [DataType]
            The data types of that could possibly be instantiated in the union.
        """
        self.name = name
        self.membertypes = membertypes
        if size is None: # if explicit size not provided, calculate on our own
            size = max([ mem.size for mem in membertypes ])
        super().__init__(
            metatype=MetaType.UNION,
            size=size
        )

def test():
    pass

if __name__ == "__main__":
    test()