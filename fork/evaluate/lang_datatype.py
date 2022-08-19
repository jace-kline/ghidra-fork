
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

    # the relationship a record has to its parent (or ROOT)
    class Relationship(object):
        ELEMENT = 0 # element of parent array
        MEMBER = 1 # member of parent struct / union
        SUBSET = 2 # a subarray, partial struct, etc.

        @staticmethod
        def to_string(code):
            _cls = DataTypeRecursiveDescent.Relationship
            _map = {
                _cls.ELEMENT: "ELEMENT",
                _cls.MEMBER: "MEMBER",
                _cls.SUBSET: "SUBSET"
            }
            return _map[code]

    # This class holds information about recursive descent of subtypes
    # in a type tree. Captures chain of recurses + offsets.
    class DescentRecord(object):
        def __init__(self, relationship, offset, dtype):
            # the relationship tag (int) that relates this type to its parent
            self.relationship = relationship
            # the DataType of this node
            self.dtype = dtype
            # the offset from the start address of the immediate parent type
            self.offset = offset

        def get_relationship(self):
            return self.relationship

        def get_datatype(self):
            return self.dtype

        def get_offset(self):
            return self.offset

        def __str__(self):
            return "<DescentRecord {} offset={} dtype={}>".format(
                DataTypeRecursiveDescent.Relationship.to_string(self.code),
                self.offset,
                self.dtype
            )

        def __repr__(self):
            return self.__str__()

    # root : DataType (the root datatype to recurse into)
    # path : [DescentRecord] (possibly empty list if root matched)
    def __init__(self, root, path):
        # self.root: DataType
        self.root = root
        # self.path: [DescentRecord]
        self.path = [ DataTypeRecursiveDescent.DescentRecord(relationship, offset, dtype) for (relationship, offset, dtype) in path ]

    # Create a DataTypeRecursiveDescent object for finding a given type at an offset of a root type
    @staticmethod
    def descend_find_type_at_offset_recursive(root, offset, size=None):
        res = root.get_type_at_offset_recursive(offset, size)
        return DataTypeRecursiveDescent(root, res) if res is not None else None

    def get_path(self):
        return self.path

    def no_descent(self):
        return len(self.path) == 0

    def get_root(self):
        return self.root
    
    def get_leaf(self):
        return self.path[-1]

    def get_total_offset(self):
        return sum(( record.offset for record in self.path ))

    def get_depth(self):
        return len(self.path)

    # returns path record at the ith level deep
    def __getitem__(self, i):
        return self.path[i]


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
    # int -> DescentRecord | None
    # DescentRecord ~= (relationship, offset_to_subtype, subtype)
    def get_component_type_at_offset(self, offset, size=None):
        return None

    # get the component type that includes a given offset
    # int -> DescentRecord | None
    # DescentRecord ~= (relationship, offset_to_subtype, subtype)
    def get_component_type_containing_offset(self, offset):
        return None

    # Get a path (list) of DescentRecord objects that represent
    # "nesting into" this particular type such that the leaf record
    # sufficiently satisfies the offset and possibly match_type conditions.
    # If this type itself matches, return an empty path [].
    def get_type_at_offset_recursive(self, offset, match_type=None, exact_match=False):
        # base case: offset == 0 and size matches (if size given)
        # return empty path since we didn't have to recurse at all
        if offset == 0 \
            and (match_type is None \
                or self == match_type \
                or (not exact_match and self.rough_match(match_type))
            ):
            return []


        # otherwise, try to recurse, but only if complex type
        elif not self.is_complex():
            return None

        # if we are here, we know that self is a complex type with sub-components
        # record: DescentRecord | None

        # try to get component type at exact offset (more precise, size specified)
        size = match_type.get_size() if match_type is not None else None
        record = self.get_component_type_at_offset(offset, size=size)
        # if that fails, get the component type containing the offset
        record = record if record is not None else self.get_component_type_containing_offset(offset)
        if record is None:
            return None
        
        # the remainder of the offset that must be handled by the subtype recursive call
        recurse_offset = offset - record.get_offset()

        # recurse : [DescentRecord] | None
        recurse = record.get_datatype().get_type_at_offset_recursive(recurse_offset, match_type, exact_match)
        if recurse is not None:
            # add the record to the top of the descent path and return
            return [record] + recurse

        return None

    # rough equality
    # we consider DataType objects to be a "rough match" if they have the same metatype and size
    def rough_match(self, other):
        return self.get_metatype() == other.get_metatype() and self.get_size() == other.get_size()

    # exact equality
    # override in child classes
    def __eq__(self, other):
        return self.rough_match(other)

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

    def __eq__(self, other):
        return self.rough_match(other) \
            and self.rettype == other.rettype \
            and self.paramtypes == other.paramtypes \
            and self.variadic == other.variadic

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

    def __eq__(self, other):
        return self.rough_match(other) and self.signed == other.signed

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

    def __eq__(self, other):
        return self.rough_match(other) and self.basetype == other.basetype

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
    # int -> DescentRecord | None
    def get_component_type_at_offset(self, offset, size=None):

        # check for alignment, size, etc.
        if offset % self.basetype.size != 0 \
            or (self.length is not None and offset >= self.length) \
            or (size is not None and (size % self.basetype.size != 0 or offset + size > self.size)):
            return None

        # default scenario is that we are nesting into element of the array
        relationship = DataTypeRecursiveDescent.Relationship.ELEMENT
        subtype = self.basetype

        # if specified size is a multiple (> 1) of basetype size, then construct a sub array type
        if size is not None:
            sublength = size // self.basetype.size
            if sublength > 1:
                relationship = DataTypeRecursiveDescent.Relationship.SUBSET
                subtype = DataTypeArray(basetype=self.basetype, length=sublength, size=(self.basetype.size * sublength))
            
        return DataTypeRecursiveDescent.DescentRecord(relationship, offset, subtype)
            

    # get the component type that includes a given offset
    # return the actual offset the component type was found at
    # actual offset <= offset
    # int -> DescentRecord | None
    def get_component_type_containing_offset(self, offset):
        
        # checks
        if self.length_unknown() or not (0 <= offset < self.length):
            return None

        # actual_offset = the actual offset to the desired element
        actual_offset = offset - (offset % self.basetype.size)
        return DataTypeRecursiveDescent.DescentRecord(
            DataTypeRecursiveDescent.Relationship.ELEMENT,
            actual_offset,
            self.basetype
        )

    def __eq__(self, other):
        return self.rough_match(other) \
            and self.basetype == other.basetype \
            and self.length == other.length

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
        self.name = name
        self.membertypes = membertypes
        # if size is None: # if explicit size not provided, calculate on our own
        #     size = sum([ mem.size for mem in membertypes ])
        super(DataTypeStruct, self).__init__(
            metatype=MetaType.STRUCT,
            size=size
        )

    # get the component type that starts at a given offset, possibly restricting size
    # int -> DescentRecord | None
    def get_component_type_at_offset(self, offset, size=None):
        _offset = 0
        for memtype in self.membertypes:
            if _offset == offset:
                return DataTypeRecursiveDescent.DescentRecord(
                    DataTypeRecursiveDescent.Relationship.MEMBER,
                    offset,
                    memtype
                ) if size is None or size == self.size else None
            
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
                return DataTypeRecursiveDescent.DescentRecord(
                    DataTypeRecursiveDescent.Relationship.MEMBER,
                    offset - _offset,
                    memtype
                )
            _offset += memtype.size
        return None

    def __eq__(self, other):
        return self.rough_match(other) and self.membertypes == other.membertypes

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

    # offset = the offset into this datatype to find match for
    # offset_to_subtype = the actual offset of the direct subtype in recursion
    # TODO: size parameter should be changed to 'match_dtype' so we can check type equality instead of just size
    def get_type_at_offset_recursive(self, offset, match_type=None, exact_match=False):
        # base case: offset == 0 and size matches (if size given)
        # return empty path since we didn't have to recurse at all
        if offset == 0 \
            and (match_type is None \
                or self == match_type \
                or (not exact_match and self.rough_match(match_type))
            ):
            return []

        # try to match on each member type iteratively
        # if one matches, then terminate
        # offset to all members is 0
        for memtype in self.membertypes:
            # recurse: [DescentNode]
            recurse = memtype.get_type_at_offset_recursive(offset, match_type=match_type, exact_match=exact_match)
            if recurse is not None:
                record = DataTypeRecursiveDescent.DescentRecord(
                    DataTypeRecursiveDescent.Relationship.MEMBER,
                    0, # offset to each member is 0
                    memtype
                )
                return [record] + recurse

        return None

    def __eq__(self, other):
        return self.rough_match(other) and self.membertypes == other.membertypes

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