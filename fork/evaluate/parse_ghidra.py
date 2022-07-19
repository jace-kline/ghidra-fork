from parse_ghidra_util import *
from resolve import *
from resolve_stubs import *
from translation import *

class ParseGhidraException(Exception):
    pass

class ParseGhidra:
    def __init__(self):
        # holds {ref: obj} mappings
        # obj is a Ghidra type (DataType, Variable, Address, etc)
        self.objmap = {}
        # holds {ref: stub} mappings
        self.db = ResolverDatabase()

    # place a ghidra object in the objmap
    # referenced by its Python object address
    def register_obj(self, obj):
        k = id(obj)
        if (not self.db.exists(k)) and (k not in self.objmap):
            self.objmap[k] = obj
        return k

    def generate_unique_key(self):
        MAXKEY = 999999
        for k in range(0, MAXKEY):
            if (not self.db.exists(k)) and (k not in self.objmap):
                return k

    # Generate a key for the stub, then insert into the DB as a record.
    # Return the new key created.
    def make_stub(self, stub):
        key = self.generate_unique_key()
        self.db.make_record(key, stub)
        return key

    def parse(self):
        self.generate_proginfo_stub()
        proginfo = self.db.resolve_root()
        return proginfo

    def generate_proginfo_stub(self):
        ref = self.generate_unique_key()

        # collect all functions and perform decompilation on each
        # should we iterate this until it reaches fixpoint?
        fns = [ decompileFunction(fn) for fn in getAllFunctions() ]
        functionrefs = [ self.register_obj(fn) for fn in fns ]

        gbls = getAllData()
        globalrefs = [ self.register_obj(gbl) for gbl in gbls ]

        stub = ProgramInfoStub(
            globalrefs=globalrefs,
            functionrefs=functionrefs
        )

        self.db.make_record(ref, stub)
        self.db.set_root_key(ref)

        for functionref in functionrefs:
            self.generate_function_stub(functionref)

        for globalref in globalrefs:
            self.generate_globaldata_stub(globalref)


    def generate_function_stub(self, ref):
        # if this ref is already in the db, do nothing
        if self.db.exists(ref):
            return

        # try to lookup in objmap
        # if not found, raise error
        fn = self.objmap.get(ref, None)
        if fn is None:
            raise ParseGhidraException("Function object does not exist in map")

        name = fn.getName() # str

        entrypoint = fn.getEntryPoint() # Address
        startaddrref = self.register_obj(entrypoint)

        params = fn.getParameters() # [Parameter]
        paramrefs = [ self.register_obj(v) for v in params ]

        vars = fn.getLocalVariables() # [Variable]
        varrefs = [ self.register_obj(v) for v in vars ]

        rettype = fn.getReturnType() # DataType
        rettyperef = self.register_obj(rettype)

        stub = FunctionStub(
            name=name,
            startaddrref=startaddrref,
            rettyperef=rettyperef,
            paramrefs=paramrefs,
            varrefs=varrefs
        )

        # insert this record
        self.db.make_record(ref, stub)

        # recurse on sub components of this function
        self.generate_address_stub(startaddrref)

        for paramref in paramrefs:
            self.generate_var_stub(paramref, param=True, functionref=ref)

        for varref in varrefs:
            self.generate_var_stub(varref, param=False, functionref=ref)

        self.generate_dtype_stubs(rettyperef)

    def generate_address_stub(self, ref):
        # if this ref is already in the db, do nothing
        if self.db.exists(ref):
            return

        # try to lookup in objmap
        # if not found, raise error
        addr = self.objmap.get(ref, None)
        if addr is None:
            raise ParseGhidraException("Address object does not exist in map")

        # convert Ghidra AddressSpace -> our AddressSpace
        addr = get_address(addr)
        stub = AddressStub(
            addrspace=addr.addrspace,
            offset=addr.offset
        )
        self.db.make_record(ref, stub)

    def generate_globaldata_stub(self, ref):
        # if this ref is already in the db, do nothing
        if self.db.exists(ref):
            return

        # try to lookup in objmap
        # if not found, raise error
        var = self.objmap.get(ref, None)
        if var is None:
            raise ParseGhidraException("Variable/Parameter object does not exist in map")

        name = var.getLabel()

        dtype = var.getDataType()
        dtyperef = self.register_obj(dtype)
        
        addr = var.getMinAddress()
        addrref = self.register_obj(addr)

        stub = VariableStub(
            name=name,
            dtyperef=dtyperef,
            addrref=addrref,
            param=False,
            functionref=None
        )

        self.db.make_record(ref, stub)

        # recurse on sub components
        self.generate_dtype_stubs(dtyperef)
        self.generate_address_stub(addrref)

    def generate_var_stub(self, ref, param=False, functionref=None):
        # if this ref is already in the db, do nothing
        if self.db.exists(ref):
            return

        # try to lookup in objmap
        # if not found, raise error
        var = self.objmap.get(ref, None)
        if var is None:
            raise ParseGhidraException("Variable/Parameter object does not exist in map")

        name = var.getName()

        dtype = var.getDataType()
        dtyperef = self.register_obj(dtype)
        
        addr = var.getMinAddress()
        addrref = self.register_obj(addr)

        stub = VariableStub(
            name=name,
            dtyperef=dtyperef,
            addrref=addrref,
            param=param,
            functionref=functionref
        )

        self.db.make_record(ref, stub)

        # recurse on sub components
        self.generate_dtype_stubs(dtyperef)
        self.generate_address_stub(addrref)

    # For a given Ghidra DataType object, generate the correct
    # associated data type stub(s) and add to the database
    def generate_dtype_stubs(self, ref):
        # if this ref is already in the db, do nothing
        if self.db.exists(ref):
            return

        # try to lookup in objmap
        # if not found, raise error
        dtype = self.objmap.get(ref, None)
        if dtype is None:
            raise ParseGhidraException("DataType object does not exist in map")

        # extract the metatype & size from the dtype
        metatype = get_metatype(dtype)
        size = 0 if dtype.isZeroLength() else dtype.getLength()

        # we want to create a stub & recursively capture sub-types to resolve
        stub = None
        subtyperefs = []

        # switch on the metatype & generate correct stub
        # possibly recursive if complex data type
        if metatype == MetaType.INT:
            signed = dtype.isSigned()

            stub = DataTypeIntStub(
                size=size,
                signed=signed
            )

        elif metatype == MetaType.FLOAT:
            stub = DataTypeFloatStub(
                size=size
            )

        elif metatype == MetaType.POINTER:
            basetype = dtype.getDataType()
            basetyperef = self.register_obj(basetype)

            stub = DataTypePointerStub(
                basetyperef=basetyperef,
                size=size
            )
            subtyperefs.append(basetyperef)

        elif metatype == MetaType.ARRAY:
            basetype = dtype.getDataType()
            basetyperef = self.register_obj(basetype)
            length = dtype.getNumElements()

            stub = DataTypeArrayStub(
                basetyperef=basetyperef,
                length=length
            )
            subtyperefs.append(basetyperef)

        elif metatype == MetaType.STRUCT:
            name = dtype.getName()
            membertypes = [ mem.getDataType() for mem in dtype.getComponents() ]
            membertyperefs = [ self.register_obj(memtype) for memtype in membertypes ]

            stub = DataTypeStructStub(
                name=name,
                membertyperefs=membertyperefs,
                size=size
            )
            subtyperefs += membertyperefs

        elif metatype == MetaType.UNION:
            name = dtype.getName()
            membertypes = [ mem.getDataType() for mem in dtype.getComponents() ]
            membertyperefs = [ self.register_obj(memtype) for memtype in membertypes ]

            stub = DataTypeUnionStub(
                name=name,
                membertyperefs=membertyperefs,
                size=size
            )
            subtyperefs += membertyperefs

        elif metatype == MetaType.UNDEFINED:
            stub = DataTypeUndefinedStub(size=size)

        elif metatype == MetaType.VOID:
            stub = DataTypeVoidStub()

        elif metatype == MetaType.FUNCTION_PROTOTYPE:
            rettype = dtype.getReturnType()
            rettyperef = self.register_obj(rettype)

            variadic = dtype.hasVarArgs()
            paramdefs = dtype.getArguments() # [ParameterDefinition]
            paramtypes = [ paramdef.getDataType() for paramdef in paramdefs ]
            paramtyperefs = [ self.register_obj(paramtype) for paramtype in paramtypes ]

            stub = DataTypeFunctionPrototypeStub(
                rettyperef=rettyperef,
                paramtyperefs=paramtyperefs,
                variadic=variadic
            )
            subtyperefs += paramtyperefs

        elif metatype == MetaType.TYPEDEF:
            name = dtype.getName()
            basetype = dtype.getDataType()
            basetyperef = self.register_obj(basetype)

            stub = DataTypeTypedefStub(
                name=name,
                basetyperef=basetyperef
            )
            subtyperefs.append(basetyperef)

        elif metatype == MetaType.ENUM:
            # create and add stub for the underlying integer type
            basetyperef = self.make_stub(DataTypeIntStub(size=size, signed=True))

            stub = DataTypeEnumStub(basetyperef=basetyperef)

        elif metatype == MetaType.STRING:
            # convert "strings" to char array
            basetyperef = self.make_stub(DataTypeIntStub(size=1, signed=True))
            length = dtype.getLength()

            stub = DataTypeArrayStub(
                basetyperef=basetyperef,
                length=length
            )
            subtyperefs.append(basetyperef)

        else:
            raise NotImplementedError("MetaType code does not exist")

        # insert this stub into DB
        self.db.make_record(ref, stub)

        # Recurse on sub-refs
        for subtyperef in subtyperefs:
            self.generate_dtype_stubs(subtyperef)
