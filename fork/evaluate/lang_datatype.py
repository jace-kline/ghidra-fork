
# enum of "meta types"
class MetaType(object):
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
    STRING: a high-level string, usually represented as a null-terminated char array
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
            options = INT | FLOAT | POINTER | ARRAY | STRUCT | UNION | UNDEFINED | VOID | FUNCTION_PROTOTYPE | TYPEDEF | ENUM | QUALIFIER | STRING
        size: int
            The total size of the datatype
        """
        self.metatype = metatype
        self.size = size

    # Is this type a complex type? -> Has "sub-components"?
    def is_complex(self):
        return self.metatype in [MetaType.ARRAY, MetaType.STRUCT, MetaType.UNION]

    # If this type is a complex type (containing sub-components),
    # attempt to get the type at the offset.
    # int -> DataType | None
    def get_member_type_at_offset(self, offset):
        return None

    # For complex types, return a list of consituent types with associated offsets.
    # () -> [(offset, DataType)]
    def get_member_type_offsets(self):
        return []

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
        if self.variadic:
            s += "[...]"
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

        # If this type is a complex type (containing sub-components),
    # attempt to get the type at the offset.
    # int -> DataType | None
    def get_member_type_at_offset(self, offset):
        _offset = offset
        for memtype in self.membertypes:
            if _offset == 0:
                return memtype
            
            _offset -= memtype.size
            if _offset < 0:
                break
        return None

    # For complex types, return a list of consituent types with associated offsets.
    # () -> [(offset, DataType)]
    def get_member_type_offsets(self):
        offset_types = []
        offset = 0
        for memtype in self.membertypes:
            offset_types.append((offset, memtype))
            offset += memtype.size
        return offset_types

    def matches_member_type_at_offset(self, offset, dtype):
        memtype = self.get_member_type_at_offset(offset)
        if memtype:
            return memtype == dtype # TODO: should this be strict ==?
        return False

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

    # If this type is a complex type (containing sub-components),
    # attempt to get the type at the offset.
    # int -> DataType | None
    def get_member_type_at_offset(self, offset):
        _offset = offset
        for memtype in self.membertypes:
            if _offset == 0:
                return memtype
            # TODO: what if the member type is itself complex?
            _offset -= memtype.size
            if _offset < 0:
                break
        return None

    # For complex types, return a list of consituent types with associated offsets.
    # () -> [(offset, DataType)]
    def get_member_type_offsets(self):
        offset_types = []
        offset = 0
        for memtype in self.membertypes:
            offset_types.append((offset, memtype))
            offset += memtype.size
        return offset_types

    def matches_member_type_at_offset(self, offset, dtype):
        memtype = self.get_member_type_at_offset(offset)
        if memtype:
            return memtype == dtype # TODO: should this be strict ==?
        return False

    def __str__(self):
        s = "<STRUCT "
        if self.name is not None:
            s += self.name + " "

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

    # For complex types, return a list of consituent types with associated offsets.
    # () -> [(offset, DataType)]
    def get_member_type_offsets(self):
        offset_types = []
        for memtype in self.membertypes:
            offset_types.append((0, memtype))
            offset += memtype.size
        return offset_types

    def matches_member_type_at_offset(self, offset, dtype):
        if offset == 0:
            for memtype in self.membertypes:
                if memtype == dtype:
                    return True
        return False

    def __str__(self):
        s = "<UNION "
        if self.name is not None:
            s += self.name + " "

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