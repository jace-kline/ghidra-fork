
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


# Tracks a path into a recursive data type
# Provides methods for querying information about the path
class DataTypeRecursiveDescent(object):

    # This class holds information about recursive descent of subtypes
    # in a type tree. Captures chain of recurses + offsets.
    class DescentRecord(object):
        def __init__(self, offset, dtype):
            # the DataType of this node
            self.dtype = dtype
            # the offset from the start address of the immediate parent
            self.offset = offset

        def __str__(self):
            return "<DescentRecord dtype={}>".format(self.offset, self.dtype)

        def __repr__(self):
            return self.__str__()

    # path : [(int, DataType)]
    # a list of offsets (in parent) and datatypes
    # front of list is the leaf, back is the parent
    def __init__(self, path):
        # self.root : DescentNode
        self.path = [ DataTypeRecursiveDescent.DescentRecord(offset, dtype) for (offset, dtype) in path ]

    # Create a DataTypeRecursiveDescent object for finding a given type at an offset of a root type
    @staticmethod
    def descend_find_type_at_offset_recursive(root, offset, size=None):
        res = root.get_type_at_offset_recursive(0, offset, size)
        if not res:
            return None
        return DataTypeRecursiveDescent(res)

    def get_path(self):
        return self.path

    def no_descent(self):
        return len(self.path) == 1

    def get_root(self):
        return self.path[-1].dtype
    
    def get_leaf(self):
        return self.path[0].dtype

    def get_total_offset(self):
        return sum(( record.offset for record in self.path ))

    def get_depth(self):
        return len(self.path) - 1

    def add_root(self, dtype):
        self.path = self.path.append(DataTypeRecursiveDescent.DescentRecord(0, dtype))

    def add_leaf(self, offset, dtype):
        self.path = [DataTypeRecursiveDescent.DescentRecord(offset, dtype)] + self.path

    # returns path record at the ith level deep
    # self[i] = self.path[len(self.path) - i - 1]
    def __getitem__(self, i):
        return self.path[len(self.path) - i - 1]


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

    def get_metatype(self):
        return self.metatype

    def get_size(self):
        return self.size

    # Is this type a complex type? -> Has "sub-components"?
    def is_complex(self):
        return self.metatype in [MetaType.ARRAY, MetaType.STRUCT, MetaType.UNION]

    # get the component type that starts at a given offset, possibly restricting size
    # int -> DataType | None
    def get_component_type_at_offset(self, offset, size=None):
        return None

    # get the component type that includes a given offset
    # int -> (offset, DataType) | None
    def get_component_type_containing_offset(self, offset):
        return None

    # get this type (self) OR a component type that starts at a given offset, possibly specifying size
    # recursive -> collects a path into the datatype tree
    # int -> [(int, DataType)] | None
    def get_type_at_offset_recursive(self, offset_in_parent, offset, size=None):
        record = (offset_in_parent, self)

        # base case: offset == 0 and size matches (if size given)
        if offset == 0 and (size is None or size == self.size):
            return [record]

        # otherwise, try to recurse, but only if complex type
        elif not self.is_complex():
            return None

        # self is a complex type with sub-components
        res = self.get_component_type_containing_offset(offset)
        if not res:
            return None
        
        _offset, subtype = res
        recurse_offset = offset - _offset

        rec = subtype.get_type_at_offset_recursive(_offset, recurse_offset, size)
        if rec:
            rec.append(record)
            return rec

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
        return self.length <= 1 or self.length is None

    # get the component type that starts at a given offset, possibly restricting size
    # int -> DataType | None
    def get_component_type_at_offset(self, offset, size=None):
        if offset % self.basetype.size != 0 \
            or (self.length is not None and offset >= self.length) \
            or (size is not None and (size % self.basetype.size != 0 or offset + size > self.size)):
            return None

        # if specified size is a multiple (> 1) of basetype size, then construct a sub array type
        if size is not None:
            sublength = size // self.basetype.size
            return self.basetype if sublength == 1 else DataTypeArray(basetype=self.basetype, length=sublength, size=(self.basetype.size * sublength))
        else:
            return self.basetype

    # get the component type that includes a given offset
    # return the actual offset the component type was found at
    # actual offset <= offset
    # int -> (int, DataType) | None
    def get_component_type_containing_offset(self, offset):
        if not self.length_unknown() and 0 <= offset < self.length:
            _offset = offset - (offset % self.basetype.size)
            return (self.basetype, _offset)
        return None

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

    # get the component type that starts at a given offset, possibly restricting size
    # int -> DataType | None
    def get_component_type_at_offset(self, offset, size=None):
        _offset = 0
        for memtype in self.membertypes:
            if _offset == offset:
                return memtype if size is None or size == self.size else None
            
            _offset += memtype.size
            if _offset > offset:
                break
        return None

    # get the component type that includes a given offset
    # return the actual offset the component type was found at
    # actual offset <= offset
    # int -> (int, DataType) | None
    def get_component_type_containing_offset(self, offset):
        _offset = 0
        for memtype in self.membertypes:
            if _offset <= offset < memtype.size:
                return (_offset, memtype)
            _offset += memtype.size
        return None

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

    # get this type (self) OR a component type that starts at a given offset, possibly specifying size
    # recursive -> collects a path into the datatype tree
    # int -> [(int, DataType)] | None
    def get_type_at_offset_recursive(self, offset_in_parent, offset, size=None):
        record = (offset_in_parent, self)

        # if offset == 0 and size not specified, return the entire union
        if offset == 0 and size is None:
            return [record]

        # self is a complex type with sub-components
        res = self.get_component_type_containing_offset(offset)
        if not res:
            return None

        # try a recursive descent on each of the members (they all have offset 0)
        # take the first one that matches
        for memtype in self.membertypes:
            rec = memtype.get_type_at_offset_recursive(0, offset, size)
            if rec:
                rec.append(record)
                return rec

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