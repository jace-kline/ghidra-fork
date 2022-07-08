from elftools.dwarf.constants import *
from resolve import *
from resolve_stubs import *
from parse_dwarf_util import *

class ParseDWARFException(Exception):
    pass

class ParseDWARF:
    def __init__(self, dwarfinfo):
        self.dwarfinfo = dwarfinfo
        # holds {ref: DIE} mappings
        self.diemap = {}
        # holds {ref: stub} mappings
        self.db = ResolverDatabase()

    def generate_unique_key(self):
        MAXKEY = 999999
        for k in range(0, MAXKEY):
            if (not self.db.exists(k)) and (k not in self.diemap):
                return k

    # Generate a key for the stub, then insert into the DB as a record.
    # Return the new key created.
    def make_stub(self, stub):
        key = self.generate_unique_key()
        self.db.make_record(key, stub)
        return key

    # For a given ref in the diemap, recursively generate the associated stub(s)
    # and add to the resolver database.
    # Returns nothing, only updates the internal DB.
    def generate_DIE_stubs(self, ref):
        if self.db.exists(ref):
            return

        die = self.diemap.get(ref, None)
        if die is None:
            raise ParseDWARFException(
                "Attempted to reference unknown key {}"
                .format(ref)
            )

        subrefs = []
        stub = None

        # Function-like DIE
        if die.tag == "DW_TAG_subprogram":
            name = get_DIE_name(die)
            addrexp = get_DIE_attr(die, "DW_AT_low_pc")
            startaddr = Address(addrspace=AddressSpace.GLOBAL, offset=addrexp) if addrexp is not None else Address(addrspace=AddressSpace.EXTERNAL, offset=0)
            startaddrref = self.make_stub(AddressStub.from_Address(startaddr))
            # get basetype ref
            rettyperef = get_DIE_attr(die, "DW_AT_type")
            # if basetype ref is None, generate a VoidDataTypeStub in the DB to point to
            if rettyperef is None:
                rettyperef = self.make_stub(DataTypeVoidStub())
            
            paramdies, vardies = get_param_var_DIEs(die)
            paramrefs = [ die.offset for die in paramdies ]
            varrefs = [ die.offset for die in vardies ]

            stub = FunctionStub(
                    name=name,
                    startaddrref=startaddrref,
                    rettyperef=rettyperef,
                    paramrefs=paramrefs,
                    varrefs=varrefs
                )

            subrefs += paramrefs + varrefs + [rettyperef]

        elif die.tag in ["DW_TAG_variable", "DW_TAG_formal_parameter"]:
            name = get_DIE_name(die)
            param = die.tag == "DW_TAG_formal_parameter"
            dtyperef = get_DIE_attr(die, "DW_AT_type")
            addrexp = get_DIE_attr(die, "DW_AT_location")
            if type(addrexp) == int:
                raise Exception("{} -> type = {}".format(addrexp, type(addrexp)))
            addr = parse_dwarf_addr(addrexp) if addrexp is not None else Address(addrspace=AddressSpace.EXTERNAL, offset=0)
            addrref = self.make_stub(AddressStub.from_Address(addr))

            stub = VariableStub(
                    name=name,
                    dtyperef=dtyperef,
                    addrref=addrref,
                    param=param,
                    functionref=None
                )

            subrefs.append(dtyperef)

        # if base type, lookup mapping
        elif die.tag == "DW_TAG_base_type":
            # get type's encoding and size
            enc = get_DIE_attr(die, "DW_AT_encoding")
            size = get_DIE_attr(die, "DW_AT_byte_size")
            
            # void
            if enc == DW_ATE_void:
                self.db.make_record(ref, DataTypeVoidStub())

            # pointer
            elif enc == DW_ATE_address:
                # get basetype ref
                basetyperef = get_DIE_attr(die, "DW_AT_type")
                # if basetype ref is None, generate a VoidDataTypeStub in the DB to point to
                if basetyperef is None:
                    basetyperef = self.make_stub(DataTypeVoidStub())

                stub = DataTypePointerStub(basetyperef=basetyperef, size=size)
                subrefs.append(basetyperef)
                
            # int/char (signed)
            elif enc in [DW_ATE_signed, DW_ATE_signed_char, DW_ATE_signed_fixed]:
                stub = DataTypeIntStub(size=size, signed=True)
            
            # int/char (unsigned)
            # regard bool as unsigned char
            # regard ASCII char as unsigned char
            elif enc in [DW_ATE_unsigned, DW_ATE_unsigned_char, DW_ATE_unsigned_fixed, DW_ATE_boolean, DW_ATE_ASCII]:
                stub = DataTypeIntStub(size=size, signed=False)

            # float
            elif enc in [DW_ATE_complex_float, DW_ATE_float, DW_ATE_decimal_float, DW_ATE_imaginary_float]:
                stub = DataTypeFloatStub(size=size)

            # anything else?
            else:
                stub = DataTypeUndefinedStub(size=size)

        # qualified types -> treat as their base types
        elif die.tag in ["DW_TAG_atomic_type", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restricted_type"]:
            # get basetype ref
            basetyperef = get_DIE_attr(die, "DW_AT_type")
            # if basetype ref is None, generate a VoidDataTypeStub in the DB to point to
            if basetyperef is None:
                basetyperef = self.make_stub(DataTypeVoidStub())
            stub = DataTypeQualifierStub(basetyperef=basetyperef)
            subrefs.append(basetyperef)

        # pointer type
        elif die.tag == "DW_TAG_pointer_type":
            size = get_DIE_attr(die, "DW_AT_byte_size")
            basetyperef = get_DIE_attr(die, "DW_AT_type")
            # if basetype ref is None, generate a VoidDataTypeStub in the DB to point to
            if basetyperef is None:
                basetyperef = self.make_stub(DataTypeVoidStub())

            # set unresolved pointer
            stub = DataTypePointerStub(basetyperef=basetyperef, size=size)
            subrefs.append(basetyperef)

        # array type
        elif die.tag == "DW_TAG_array_type":
            # get the child subrange DIE object -> specifies the
            # bounds of the array
            rangedies = [ die for die in die.iter_children() if die.tag == "DW_TAG_subrange_type" ]
            length = None
            if len(rangedies) > 0:
                rangedie = rangedies[0]
                upbound = rangedie.attributes.get("DW_AT_upper_bound", 0)
                length = upbound.value + 1 if upbound != 0 else 0
            
            basetyperef = get_DIE_attr(die, "DW_AT_type")
            assert(basetyperef is not None)

            stub = DataTypeArrayStub(
                    basetyperef=basetyperef,
                    length=length
                )
            subrefs.append(basetyperef)

        # struct type
        elif die.tag == "DW_TAG_structure_type":

            membertyperefs = [ get_DIE_attr(die, "DW_AT_type") for die in die.iter_children() if die.tag == "DW_TAG_member" ]
            name = get_DIE_name(die)
            size = get_DIE_attr(die, "DW_AT_byte_size")

            stub = DataTypeStructStub(
                    name=name,
                    membertyperefs=membertyperefs,
                    size=size
                )

            subrefs += membertyperefs

        # union type
        elif die.tag == "DW_TAG_union_type":
            
            membertyperefs = [ get_DIE_attr(die, "DW_AT_type") for die in die.iter_children() if die.tag == "DW_TAG_member" ]
            name = get_DIE_name(die)
            size = get_DIE_attr(die, "DW_AT_byte_size")

            stub = DataTypeUnionStub(
                    name=name,
                    membertyperefs=membertyperefs,
                    size=size
                )

            subrefs += membertyperefs

        # typedef
        elif die.tag == "DW_TAG_typedef":
            basetyperef = get_DIE_attr(die, "DW_AT_type")
            if basetyperef is None:
                basetyperef = self.make_stub(DataTypeVoidStub())
            name = get_DIE_name(die)

            stub = DataTypeTypedefStub(
                    name=name,
                    basetyperef=basetyperef
                )
            
            subrefs.append(basetyperef)

        # function prototype
        elif die.tag == "DW_TAG_subroutine_type":

            # if no ref, assume void return type
            rettyperef = get_DIE_attr(die, "DW_AT_type")
            if rettyperef is None:
                rettyperef = self.make_stub(DataTypeVoidStub())

            paramtyperefs = [ get_DIE_attr(die, "DW_AT_type") for die in die.iter_children() if die.tag == "DW_TAG_formal_parameter" ]

            stub = DataTypeFunctionPrototypeStub(
                    rettyperef=rettyperef,
                    paramtyperefs=paramtyperefs
                )
            
            subrefs += paramtyperefs + [rettyperef]

        # enum
        elif die.tag == "DW_TAG_enumeration_type":
            # get basetype ref
            basetyperef = get_DIE_attr(die, "DW_AT_type")
            assert(basetyperef is not None)
            # if basetype ref is None, generate a VoidDataTypeStub in the DB to point to
            if basetyperef is None:
                basetyperef = self.make_stub(DataTypeVoidStub())
            stub = DataTypeEnumStub(basetyperef=basetyperef)
            subrefs.append(basetyperef)
            
        # other cases?
        else:
            raise NotImplementedError(die.tag)

        # Now that we have constructed the stub,
        # add corresponding record to the database
        self.db.make_record(ref, stub)

        # Recurse on sub-references
        for subref in subrefs:
            self.generate_DIE_stubs(subref)


    def parse(self):
        # map each DIE to its (ref, DIE)
        self.diemap = dict([ (die.offset, die) for die in get_all_DIEs(self.dwarfinfo) ])

        # create a "root" ProgramInfoStub object
        globalrefs = [ die.offset for die in get_global_var_DIEs(self.dwarfinfo) ]
        functionrefs = [ die.offset for die in get_function_DIEs(self.dwarfinfo) ]
        rootkey = self.make_stub(
            ProgramInfoStub(
                globalrefs=globalrefs,
                functionrefs=functionrefs
            )
        )
        self.db.set_root_key(rootkey)

        # map the DIEs to the Resolver stubs in the DB (recursively)
        for ref in (globalrefs + functionrefs):
            self.generate_DIE_stubs(ref)

        # make each variable/parameter point back to its parent function key
        for functionref in functionrefs:
            functionstub = self.db.lookup(functionref).stub
            for varref in (functionstub.paramrefs + functionstub.varrefs):
                self.db.lookup(varref).stub.functionref = functionref

        # resolve the functions, variables, & types -> ProgramInfo
        proginfo = self.db.resolve_root()
        return proginfo


def parse_from_dwarfinfo(dwarfinfo):
    parser = ParseDWARF(dwarfinfo)
    return parser.parse()

# produce a Translation object from the DWARF info
def parse_from_objfile(objfilepath):
    elffile, dwarfinfo = get_elf_dwarf_info(objfilepath)
    return parse_from_dwarfinfo(dwarfinfo)
    