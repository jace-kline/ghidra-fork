## Common variable, function, and datatype representations for DWARF/Ghidra

class Variable:
    def __init__(self, name=None, dtype=None, address=None, function=None, param=False):
        """
        name: str
            The variable's name
        dtype: DataType
            The data type of the variable
        address: Address
            Where the variable lives -> address space + offset
        function: Function
            The parent function of the variable (or None if global variable)
        param: bool
            Is this variable a parameter?
        """
        self.name = name
        self.dtype = dtype
        self.address = address
        self.function = function
        self.param = param

    def is_param(self):
        """ Is this variable a parameter? """
        return self.param

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
    def __init__(self, name=None, startaddr=None, rettype=None, params=None):
        """
        name: str
            The name of the function
        startaddr: Address
            The entrypoint address (global) of the function
        rettype: DataType
            The return type of the function
        params: [Variable]
            A list of variables corresponding to the parameters of the function
        """
        self.name = name
        self.startaddr = startaddr
        self.rettype = rettype
        self.params = params

    def same(self, other):
        return self.startaddr == other.startaddr

class Address:
    """
    An Address is defined by the space it lives in (stack, heap, global, register)
    and the offset from the base of that space.
    """
    def __init__(self, addrspace=None, offset=None):
        """
        addrspace: str
            The address space the address lives in ("stack" | "heap" | "global" | "register")
        offset: int
            The offset from the base of the address space...
            If the space="stack", then offset is from RBP or RSP, depending on compiler and optimization level.
            If the space="heap", then the offset is from the malloc'd pointer.
            If the space="global", then the offset is the raw address of the variable.
            If the space="register", then the offset is the register identifier #.
        """
        self.addrspace = addrspace
        self.offset = offset

    def __eq__(self, other):
        return self.addrspace == other.addrspace and self.offset == other.offset

class DataType:
    """
    
    """
    def __init__(self, classification="undefined", size=None):
        """
        classification: str
            The high-level semantic classification of the datatype.
            options = "int" | "float" | "pointer" | "array" | "struct" | "union" | "undefined" | "void"
        size: int
            The total size of the datatype
        """
        self.classification = classification
        self.size = size

class IntDataType(DataType):
    """
    Data type representing int/char, possibly unsigned.
    """
    def __init__(self, size=None, unsigned=False):
        super().__init__(
            classification="int",
            size=size
        )
        self.unsigned = unsigned

    def is_unsigned(self):
        return self.unsigned

class FloatDataType(DataType):
    """
    Datatype representing float/double.
    """
    def __init__(self, size=None):
        super().__init__(
            classification="float",
            size=size
        )

class UndefinedDataType(DataType):
    """
    Undefined datatype.
    """
    def __init__(self, size=None):
        super().__init__(
            classification="undefined",
            size=size
        )

class VoidDataType(DataType):
    """
    Void datatype (size = 0).
    """
    def __init__(self):
        super().__init__(
            classification="void",
            size=0
        )

class PointerDataType(DataType):
    """
    Datatype representing a pointer of some base type.
    """
    def __init__(self, basetype=None, size=None):
        """
        basetype: DataType
            The type of the object being pointed to
        """
        super().__init__(
            classification="pointer",
            size=size
        )
        self.basetype = basetype

class ArrayDataType(DataType):
    def __init__(self, basetype=None, length=None):
        """
        basetype: DataType
            The type of the elements in the array
        length: int
            The length of the array
        """
        super().__init__(
            classification="array",
            size=(basetype.size * length)
        )
        self.basetype = basetype
        self.length = length

class StructDataType(DataType):
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
            classification="struct",
            size=size
        )

class UnionDataType(DataType):
    """
    Datatype representing a C union type.
    """
    def __init__(self, name=None, opttypes=[], size=None):
        """
        opttypes: [DataType]
            The data types of that could possibly be instantiated in the union.
        """
        self.name = name
        self.opttypes = opttypes
        if size is None: # if explicit size not provided, calculate on our own
            size = max([ mem.size for mem in opttypes ])
        super().__init__(
            classification="union",
            size=size
        )

def test():
    pass

if __name__ == "__main__":
    test()