
from lang_variable import *
from lang_datatype import *
from lang_address import *
from compare_variable import *
from compare_datatype import *

class Filter(object):
    def __call__(self, obj) -> bool:
        # [(attr val, attr method)]
        pairs = []
        instance_dict = self.__dict__
        class_dict = self.__class__.__dict__
        for attr, val in instance_dict.items():
            methodname = '_' + attr
            if methodname in class_dict:
                pairs.append((val, class_dict[methodname]))
        return all(( (True if val is None else fn(self, obj)) for val, fn in pairs ))

class FilterDataType(Filter):
    filter_cls: type = DataType

    def __init__(
        self,
        primitive: bool = None, # bool|None
        complex: bool = None, # bool|None
        sized: bool = None, # bool|None
        metatype: int = None, # int|None
        min_size: int = None,
        max_size: int = None,
        size: int = None,
        composition_level = None, # int|None
        custom = None
    ):
        self.primitive = primitive
        self.complex = complex
        self.sized = sized
        self.metatype = metatype
        self.min_size = min_size
        self.max_size = max_size
        self.size = size
        self.composition_level = composition_level
        self.custom = custom

    def _primitive(self, dtype: DataType) -> bool:
        return self.primitive == dtype.is_primitive()

    def _complex(self, dtype: DataType) -> bool:
        return self.complex == dtype.is_complex()

    def _sized(self, dtype: DataType) -> bool:
        return self.sized == dtype.get_size() is not None and dtype.get_size() > 0

    def _metatype(self, dtype: DataType) -> bool:
        return self.metatype == dtype.get_metatype()

    def _min_size(self, dtype: DataType) -> bool:
        return dtype.get_size() >= self.min_size

    def _max_size(self, dtype: DataType) -> bool:
        return dtype.get_size() <= self.max_size

    def _size(self, dtype: DataType) -> bool:
        return dtype.get_size() == self.size

    def _composition_level(self, dtype: DataType) -> bool:
        return dtype.composition_level() == self.composition_level

    def _custom(self, dtype: DataType) -> bool:
        return self.custom(dtype)

class FilterDataTypePrimitiveCompare2(Filter):
    filter_cls = DataTypePrimitiveCompare2

    def __init__(
        self,
        min_compare_level: int = None, # DataTypePrimitiveCompareLevel
        max_compare_level: int = None, # DataTypePrimitiveCompareLevel
        compare_levels: List[int] = None, # DataTypePrimitiveCompareLevel
        compare_codes: List[int] = None, # DataTypePrimitiveCompareCode
        custom = None # DataTypePrimitiveCompare2
    ):
        self.min_compare_level = min_compare_level
        self.max_compare_level = max_compare_level
        self.compare_levels = compare_levels
        self.compare_codes = compare_codes
        self.custom = custom

    def _min_compare_level(self, cmp: DataTypePrimitiveCompare2) -> bool:
        return cmp.get_compare_level() >= self.min_compare_level
    
    def _max_compare_level(self, cmp: DataTypePrimitiveCompare2) -> bool:
        return cmp.get_compare_level() <= self.max_compare_level

    def _compare_levels(self, cmp: DataTypePrimitiveCompare2) -> bool:
        return cmp.get_compare_level() in self.compare_levels

    def _compare_codes(self, cmp: DataTypePrimitiveCompare2) -> bool:
        return cmp.get_compare_code() in self.compare_codes

    def _custom(self, cmp: DataTypePrimitiveCompare2) -> bool:
        return self.custom(cmp)

class FilterDataTypeCompare2(Filter):
    filter_cls = DataTypeCompare2

    def __init__(
        self,
        min_compare_level: int = None, # DataTypeCompareLevel
        max_compare_level: int = None, # DataTypeCompareLevel
        compare_levels: List[int] = None, # [DataTypeCompareLevel]
        compare_codes: List[int] = None, # [DataTypeCompareCode]
        start_aligned: bool = None,
        same_size: bool = None,
        same_metatype: bool = None,
        exact_match: bool = None,
        left_dtype_filter: FilterDataType = None,
        right_dtype_filter: FilterDataType = None,
        primitive_compare2_filter: FilterDataTypePrimitiveCompare2 = None,
        custom = None # DataTypeCompare2 -> bool
    ):
        self.min_compare_level = min_compare_level
        self.max_compare_level = max_compare_level
        self.compare_levels = compare_levels
        self.compare_codes = compare_codes
        self.start_aligned = start_aligned
        self.same_size = same_size
        self.same_metatype = same_metatype
        self.exact_match = exact_match
        self.left_dtype_filter = left_dtype_filter
        self.right_dtype_filter = right_dtype_filter
        self.primitive_compare2_filter = primitive_compare2_filter
        self.custom = custom

    def _min_compare_level(self, cmp: DataTypeCompare2) -> bool:
        return cmp.get_compare_level() >= self.min_compare_level

    def _max_compare_level(self, cmp: DataTypeCompare2) -> bool:
        return cmp.get_compare_level() <= self.max_compare_level

    def _compare_levels(self, cmp: DataTypeCompare2) -> bool:
        return cmp.get_compare_level() in self.compare_levels

    def _compare_codes(self, cmp: DataTypeCompare2) -> bool:
        return cmp.get_compare_code() in self.compare_codes

    def _start_aligned(self, cmp: DataTypeCompare2) -> bool:
        return self.start_aligned == cmp.start_aligned()

    def _same_size(self, cmp: DataTypeCompare2) -> bool:
        return self.same_size == cmp.same_size()

    def _same_metatype(self, cmp: DataTypeCompare2) -> bool:
        return self.same_metatype == cmp.same_metatype()

    def _exact_match(self, cmp: DataTypeCompare2) -> bool:
        return self.exact_match == cmp.exact_match()

    def _left_dtype_filter(self, cmp: DataTypeCompare2) -> bool:
        return self.left_dtype_filter(cmp.get_left())

    def _right_dtype_filter(self, cmp: DataTypeCompare2) -> bool:
        return self.right_dtype_filter(cmp.get_right())

    def _primitive_compare2_filter(self, cmp: DataTypeCompare2) -> bool:
        return cmp.get_primitive_comparison() is not None and self.primitive_compare_filter(cmp.get_primitive_comparison())

    def _custom(self, cmp: DataTypeCompare2) -> bool:
        return self.custom(cmp)

class FilterAddress(Filter):
    filter_cls = Address

    def __init__(
        self,
        addrtypes: List[int] = None, # [AddressType] to allow
        rangeable: bool = None, # is the address space a "range"?
        known: bool = None, # is this a precise address? or is it unknown/external?
        custom = None # Address -> bool
    ):
        self.addrtypes = addrtypes
        self.rangeable = rangeable
        self.known = known
        self.custom = custom

    def _addrtypes(self, addr: Address) -> bool:
        return addr.get_addrtype() in self.addrtypes

    def _rangeable(self, addr: Address) -> bool:
        return self.rangeable == addr.rangeable()

    def _known(self, addr: Address) -> bool:
        return self.known == addr.get_region().is_known()

    def _custom(self, addr: Address) -> bool:
        return self.custom(addr)

class FilterVariable(Filter):
    filter_cls = Variable

    def __init__(
        self,
        gbl: bool = None,
        param: bool = None,
        local: bool = None,
        name: str = None,
        has_location: bool = None, # has 1+ associated liveranges
        locations: int = None, # number of liveranges
        dtype_filter: FilterDataType = None,
        address_filter: FilterAddress = None, # apply to each Address in liveranges
        custom = None # Variable -> bool
    ):
        self.gbl = gbl
        self.param = param
        self.local = local
        self.name = name
        self.has_location = has_location
        self.locations = locations
        self.dtype_filter = dtype_filter
        self.address_filter = address_filter
        self.custom = custom # Variable -> bool

    def _gbl(self, var: Variable) -> bool:
        return self.gbl == var.is_global()

    def _param(self, var: Variable) -> bool:
        return self.param == var.is_param()

    def _local(self, var: Variable) -> bool:
        return self.local == var.is_local()

    def _name(self, var: Variable) -> bool:
        return self.name == var.get_name()

    def _has_location(self, var: Variable) -> bool:
        return self.has_location == var.has_location()

    def _dtype_filter(self, var: Variable) -> bool:
        return self.dtype_filter(var.get_datatype())

    def _address_filter(self, var: Variable) -> bool:
        return all(( self.address_filter(liverange.get_addr()) for liverange in var.get_liveranges() ))

    def _custom(self, variable: Variable) -> bool:
        return self.custom(variable)

class FilterVarnode(Filter):
    filter_cls = Varnode

    def __init__(
        self,
        dtype_filter: FilterDataType = None,
        address_filter: FilterAddress = None,
        custom = None # Varnode -> bool
    ):
        self.dtype_filter = dtype_filter
        self.address_filter = address_filter
        self.custom = custom

    def _dtype_filter(self, varnode: Varnode) -> bool:
        return self.dtype_filter(varnode.get_datatype())

    def _address_filter(self, varnode: Varnode) -> bool:
        return self.address_filter(varnode.get_addr())

    def _custom(self, varnode: Varnode) -> bool:
        return self.custom(varnode)

class FilterFunction(Filter):
    filter_cls = Function

    def __init__(
        self,
        names: List[str] = None,
        params_filter: FilterVariable = None,
        locals_filter: FilterVariable = None,
        variadic: bool = None,
        custom = None # Function -> bool
    ):
        self.names = names
        self.params_filter = params_filter
        self.locals_filter = locals_filter
        self.variadic = variadic
        self.custom = custom

    def _names(self, fn: Function) -> bool:
        return fn.get_name() in self.names

    def _variadic(self, fn: Function) -> bool:
        return fn.is_variadic() == self.variadic

    

class FilterVarnodeCompare2(Filter):
    filter_cls = VarnodeCompare2

    def __init__(
        self,
        compare_levels: List[int] = None, # VarnodeCompareLevel
        compare_codes: List[int] = None, # VarnodeCompare2Code
        start_aligned: bool = None,
        same_size: bool = None,
        left_varnode_filter: FilterVarnode = None,
        right_varnode_filter: FilterVarnode = None,
        dtype_compare2_filter: FilterDataTypeCompare2 = None,
        custom = None # VarnodeCompare2 -> bool
    ):
        self.compare_levels = compare_levels
        self.compare_codes = compare_codes
        self.start_aligned = start_aligned
        self.same_size = same_size
        self.left_varnode_filter = left_varnode_filter
        self.right_varnode_filter = right_varnode_filter
        self.dtype_compare2_filter = dtype_compare2_filter
        self.custom = custom # VarnodeCompare2 -> bool

    def _compare_levels(self, cmp: VarnodeCompare2) -> bool:
        return cmp.get_compare_level() in self.compare_levels

    def _compare_codes(self, cmp: VarnodeCompare2) -> bool:
        return cmp.get_compare_code() in self.compare_codes

    def _start_aligned(self, cmp: VarnodeCompare2) -> bool:
        return cmp.is_start_aligned()

    def _same_size(self, cmp: VarnodeCompare2) -> bool:
        return cmp.is_same_size()

    def _left_varnode_filter(self, cmp: VarnodeCompare2) -> bool:
        return self.left_varnode_filter(cmp.get_left())

    def _right_varnode_filter(self, cmp: VarnodeCompare2) -> bool:
        return self.right_varnode_filter(cmp.get_right())

    def _dtype_compare2_filter(self, cmp: VarnodeCompare2) -> bool:
        return self.dtype_compare2_filter(cmp.get_datatype_comparison())

    def _custom(self, cmp: VarnodeCompare2) -> bool:
        return self.custom(cmp)

class FilterVarnodeCompareRecord(Filter):
    filter_cls = VarnodeCompareRecord

    def __init__(
        self,
        min_compare_level: int = None, # VarnodeCompareLevel
        max_compare_level: int = None, # VarnodeCompareLevel
        compare_levels: List[int] = None, # [VarnodeCompareLevel]
        compare_codes: List[int] = None, # [VarnodeCompareStatus]
        min_compared_with: int = None,
        max_compared_with: int = None,
        varnode_compare2_filter: FilterVarnodeCompare2 = None,
        custom = None
    ):
        self.min_compare_level = min_compare_level
        self.max_compare_level = max_compare_level
        self.compare_levels = compare_levels
        self.compare_codes = compare_codes
        self.min_compared_with = min_compared_with
        self.max_compared_with = max_compared_with
        self.varnode_compare2_filter = varnode_compare2_filter
        self.custom = custom # VarnodeCompareRecord -> bool

    def _min_compare_level(self, cmp: VarnodeCompareRecord) -> bool:
        return cmp.get_compare_level() >= self.min_compare_level

    def _max_compare_level(self, cmp: VarnodeCompareRecord) -> bool:
        return cmp.get_compare_level() <= self.max_compare_level

    def _compare_levels(self, cmp: VarnodeCompareRecord) -> bool:
        return cmp.get_compare_level() in self.compare_levels

    def _compare_codes(self, cmp: VarnodeCompareRecord) -> bool:
        return cmp.get_status() in self.compare_codes

    def _min_compared_with(self, cmp: VarnodeCompareRecord) -> bool:
        return len(cmp.get_varnode_comparison_map()) >= self.min_compared_with

    def _max_compared_with(self, cmp: VarnodeCompareRecord) -> bool:
        return len(cmp.get_varnode_comparison_map()) <= self.max_compared_with

    def _varnode_compare2_filter(self, cmp: VarnodeCompareRecord) -> bool:
        return all(( self.varnode_compare2_filter(cmp2) for cmp2 in cmp.get_comparisons() ))

    def _custom(self, cmp: VarnodeCompareRecord) -> bool:
        return self.custom(cmp)

    