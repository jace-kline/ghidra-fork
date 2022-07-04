from elftools.dwarf.constants import *
from dwarf_translate_util import *
from dwarf.translation import *

REMOVE = -1
NOREF = -1

# for type aliases (typedef) OR
# for "qualified" dtypes (const, volatile, etc.)
# that aren't pertinent/inferrable by decompiler
class DataTypeRemoveStub:
    def __init__(self, refaddr):
        self.refaddr = refaddr
        self.metatype = REMOVE
        self.resolved = False

# builds a map from refaddr->DataTypeStub
# augments the map as new requests come in
# produces "resolved" DataType objects on request
class DWARFDataTypeTranslator:
    def __init__(self, dwarfinfo):
        self.dwarfinfo = dwarfinfo
        # the map of refaddr->DataType
        self._map = {}

    def _lookup(self, refaddr):
        return self._map.get(refaddr, None)

    def _exists(self, refaddr):
        return self._lookup(refaddr) is not None

    def _set(self, refaddr, dtype):
        self._map[refaddr] = dtype

    # mark the existence of a refaddr while deferring the
    # construction of the actual datatype
    def _mark_existence(self, refaddr):
        self._map[refaddr] = True

    # get the type DIE referenced by the input DIE
    # should be accessed only if the die possesses the 'DW_AT_type' attribute
    def _get_DIE_type_DIE(self, die, cu=None):
        try:
            refaddr = self._get_DIE_type_refaddr(die)
            return self.dwarfinfo.get_DIE_from_refaddr(refaddr, cu) if refaddr is not None else None
        except KeyError:
            return None

    # get the reference address to the input DIE's
    # referenced datatype DIE
    def _get_DIE_type_refaddr(self, die):
        try:
            return die.attributes["DW_AT_type"].value
        except KeyError:
            return None

    # For given input refaddr and associated type DIE,
    # find its type DataType (or stub) and update the map.
    # Call recursively for sub-types referenced by this type.
    # Does not rectify "unresolved" types / complete cycles
    def _update(self, refaddr):

        # Recursively update, assuming the input DIE
        # is a child or the original typedie.
        # Extracts the refaddr & referenced DIE, then recurses.
        # Returns the new refaddr
        def recurse(die):
            _refaddr = self._get_DIE_type_refaddr(die)

            # if the given DIE does not have a 'DW_AT_type' field,
            # return a signal indicating that the type field is nonexistent
            if _refaddr is None:
                return NOREF

            self._update(_refaddr)
            return _refaddr

        # If refaddr already exists in the internal map OR it is a bad reference, exit the procedure.
        # Otherwise, mark the existence of this refaddr in the map.
        if self._exists(refaddr) or refaddr == NOREF or refaddr is None:
            return
        
        self._mark_existence(refaddr)
        # fetch the type DIE from the refaddr
        typedie = self.dwarfinfo.get_DIE_from_refaddr(refaddr)

        # if base type, lookup mapping
        if typedie.tag == "DW_TAG_base_type":
            # get type's encoding and size
            enc = typedie.attributes["DW_AT_encoding"].value
            size = typedie.attributes["DW_AT_byte_size"].value
            
            # void
            if enc == DW_ATE_void:
                self._set(refaddr, DataTypeVoid())

            # pointer
            elif enc == DW_ATE_address:
                # recurse on referenced type
                _refaddr = recurse(typedie)

                basetype = None
                resolved = None
                if _refaddr == NOREF:
                    basetype = DataTypeVoid()
                    resolved = True
                else:
                    basetype = _refaddr
                    resolved = False

                # set unresolved pointer
                self._set(refaddr, DataTypePointer(basetype=basetype, size=size, resolved=resolved))
                
            # int/char (signed)
            elif enc in [DW_ATE_signed, DW_ATE_signed_char, DW_ATE_signed_fixed]:
                self._set(refaddr, DataTypeInt(size=size, signed=True))
            
            # int/char (unsigned)
            # regard bool as unsigned char
            # regard ASCII char as unsigned char
            elif enc in [DW_ATE_unsigned, DW_ATE_unsigned_char, DW_ATE_unsigned_fixed, DW_ATE_boolean, DW_ATE_ASCII]:
                self._set(refaddr, DataTypeInt(size=size, signed=False))

            # float
            elif enc in [DW_ATE_complex_float, DW_ATE_float, DW_ATE_decimal_float, DW_ATE_imaginary_float]:
                self._set(refaddr, DataTypeFloat(size=size))

            # anything else?
            else:
                self._set(refaddr, DataTypeUndefined(size=size))

        # qualified types -> treat as their base types
        elif typedie.tag in ["DW_TAG_atomic_type", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restricted_type"]:
            _refaddr = recurse(typedie)
            self._set(refaddr, DataTypeRemoveStub(_refaddr))

        # pointer type
        elif typedie.tag == "DW_TAG_pointer_type":
            size = typedie.attributes["DW_AT_byte_size"].value

            # recurse on referenced type
            _refaddr = recurse(typedie)

            basetype = None
            resolved = None
            if _refaddr == NOREF:
                basetype = DataTypeVoid()
                resolved = True
            else:
                basetype = _refaddr
                resolved = False

            # set unresolved pointer
            self._set(refaddr, DataTypePointer(basetype=basetype, size=size, resolved=resolved))

        # array type
        elif typedie.tag == "DW_TAG_array_type":
            # recurse to insert element datatype into map
            _refaddr = recurse(typedie)
            # get the child subrange DIE object -> specifies the
            # bounds of the array
            rangetypedies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_subrange_type" ]
            length = None
            size = None
            if rangetypedies != []:
                rangetypedie = rangetypedies[0]
                upbound = rangetypedie.attributes.get("DW_AT_upper_bound", 0)
                length = upbound.value + 1 if upbound != 0 else 0

            basetype = None
            resolved = None
            if _refaddr == NOREF:
                basetype = DataTypeVoid()
                resolved = True
            else:
                basetype = _refaddr
                resolved = False
            
            self._set(refaddr, DataTypeArray(basetype=basetype, length=length, size=size, resolved=resolved))

        # struct type
        # TODO deal with recursive structs (i.e. pointers to same struct type OR mutual recursion)
        elif typedie.tag == "DW_TAG_structure_type":

            memberdies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_member" ]

            # update the map for each child member DIE type
            # returns list of refaddrs corresponding to each member type
            # performs side effects!
            member_refaddrs = [ recurse(die) for die in memberdies ]
            name = get_DIE_name(typedie)
            size = None
            self._set(refaddr, DataTypeStruct(name=name, membertypes=member_refaddrs, size=size, resolved=False))

        # union type
        elif typedie.tag == "DW_TAG_union_type":
            # mark this type's existence
            self._mark_existence(refaddr)

            memberdies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_member" ]

            # update the map for each child member DIE type
            # returns list of refaddrs corresponding to each member type
            # performs side effects!
            member_refaddrs = [ recurse(die) for die in memberdies ]
            name = get_DIE_name(typedie)
            size = None
            self._set(refaddr, DataTypeUnion(name=name, membertypes=member_refaddrs, size=size, resolved=False))

        # typedef
        elif typedie.tag == "DW_TAG_typedef":
            _refaddr = recurse(typedie)

            if _refaddr == NOREF:
                self._set(refaddr, DataTypeVoid())
            else:
                self._set(refaddr, DataTypeRemoveStub(_refaddr))

        # function prototype (pointed to by pointer)
        elif typedie.tag == "DW_TAG_subroutine_type":
            _refaddr = recurse(typedie)

            # if no ref, assume void return type
            rettype = DataTypeVoid() if _refaddr == NOREF else _refaddr

            # get the children parameter DIEs and recursively update the map
            paramdies = [ die for die in typedie.iter_children() if die.tag == "DW_TAG_formal_parameter" ]
            param_refs = [ recurse(die) for die in paramdies ]

            self._set(refaddr, DataTypeFunctionPrototype(rettype=rettype, paramtypes=param_refs, resolved=False))

        # other cases?
        else:
            raise NotImplementedError(typedie.tag)


    # Given a "root" refaddr, resolve itself and all referenced types, recursively.
    # For cycles, form a circular data structure with the datatype objects.
    # Assumed that the _update() method has been called already.
    def _resolve(self, refaddr):

        # Start from root and resolve the datatypes recursively.
        # Assign the referencer's fields to the sub-datatypes
        # found in the map, recursively.
        # Set `resolved = true` when visiting each node.
        # We detect cycle/termination for a path when we hit a node with resolved=True.

        # look up the DataType object associated with the refaddr
        dtype = self._lookup(refaddr)

        # if resolved, return
        # any "primitive" types should be caught by this check
        if dtype.resolved:
            return

        dtype.resolved = True

        # special case = typedef or qualified type node
        # replace the entry by the datatype object it points to
        if dtype.metatype == REMOVE:
            self._set(refaddr, self._lookup(dtype.refaddr))

        elif dtype.metatype == MetaType.POINTER:
            _refaddr = dtype.basetype
            dtype.basetype = self._lookup(_refaddr)
            self._resolve(_refaddr)
            
        elif dtype.metatype == MetaType.ARRAY:
            _refaddr = dtype.basetype
            dtype.basetype = self._lookup(_refaddr)
            self._resolve(_refaddr)

            # fix the size of the array type
            dtype.size = dtype.length * dtype.basetype.size

        elif dtype.metatype == MetaType.UNION or dtype.metatype == MetaType.STRUCT:
            _refaddrs = dtype.membertypes
            for _refaddr in _refaddrs:
                self._resolve(_refaddr)

        elif dtype.metatype == MetaType.FUNCTION_PROTOTYPE:
            # resolve return type
            _refaddr_ret = dtype.rettype
            dtype.rettype = self._lookup(_refaddr_ret)
            self._resolve(_refaddr_ret)

            # resolve parameter types
            _refaddrs = dtype.paramtypes
            for _refaddr in _refaddrs:
                self._resolve(_refaddr)

        else:
            raise NotImplementedError(dtype.metatype)

    # method to update, resolve, & return a DataType object
    # when given an input refaddr
    def _get_refaddr_datatype(self, refaddr):
        self._update(refaddr)
        self._resolve(refaddr)
        return self._lookup(refaddr)

    # For the given input DIE, find the DataType referenced by it
    # That is, the input DIE is a DIE that points to a type DIE
    # via the 'DW_AT_type' attribute.
    # Update the internal map & resolve cycles as needed.
    # If no 'DW_AT_type' attribute, return void type
    def get_DIE_datatype(self, die):
        refaddr = self._get_DIE_type_refaddr(die)
        return DataTypeVoid() if refaddr is None else self._get_refaddr_datatype(refaddr)


