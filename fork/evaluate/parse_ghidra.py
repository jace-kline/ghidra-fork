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

        # collect all Function and perform decompilation on each
        # get list of HighFunction objects
        # should we iterate this until it reaches fixpoint?
        highfns = [ decompileHighFunction(fn) for fn in getAllFunctions() ]
        functionrefs = [ self.register_obj(highfn) for highfn in highfns ]

        # for each HighFunction, extract the global high variables referenced
        globalvars = flatten([
            getHighFunctionGlobalVars(highfn)
            for highfn in highfns 
        ])
        globalrefs = [ self.register_obj(var) for var in globalvars ]

        stub = ProgramInfoStub(
            globalrefs=globalrefs,
            functionrefs=functionrefs
        )

        self.db.make_record(ref, stub)
        self.db.set_root_key(ref)

        for functionref in functionrefs:
            self.generate_function_stub(functionref)

        for globalref in globalrefs:
            self.generate_var_stub(globalref, param=False, functionref=None)


    # ref to a HighFunction object
    def generate_function_stub(self, ref):
        # if this ref is already in the db, do nothing
        if self.db.exists(ref):
            return

        # try to lookup in objmap
        # if not found, raise error
        highfn = self.objmap.get(ref, None)
        if highfn is None:
            raise ParseGhidraException("HighFunction object does not exist in map")

        name = highfn.getFunction().getName() # str

        # get Address objects
        startaddr = get_address(getHighFunctionStartAddr(highfn))
        endaddr = get_address(getHighFunctionEndAddr(highfn))

        params = getHighFunctionParams(highfn) # [HighParam]
        paramrefs = [ self.register_obj(v) for v in params ]

        vars = getHighFunctionLocalVars(highfn) # [HighVariable]
        varrefs = [ self.register_obj(v) for v in vars ]

        fnproto = highfn.getFunctionPrototype()
        rettyperef = self.make_stub(DataTypeVoidStub()) if fnproto.hasNoReturn() else self.register_obj(fnproto.getReturnType())

        stub = FunctionStub(
            name=name,
            startaddr=startaddr,
            endaddr=endaddr,
            rettyperef=rettyperef,
            paramrefs=paramrefs,
            varrefs=varrefs
        )

        # insert this record
        self.db.make_record(ref, stub)

        # recurse on sub components of this function
        for paramref in paramrefs:
            self.generate_var_stub(paramref, param=True, functionref=ref)

        for varref in varrefs:
            self.generate_var_stub(varref, param=False, functionref=ref)

        self.generate_dtype_stubs(rettyperef)

    # ref to a HighVariable / HighParam object
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
        
        varnode_instances = var.getInstances()
        varnode_representative = var.getRepresentative()
        addr = varnode_representative.getAddress()
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

    # ref to a Ghidra DataType object
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
