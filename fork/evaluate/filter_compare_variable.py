
from lang_variable import *
from compare_variable import *
from filter_compare_datatype import *

class FilterVariable(object):
    def __init__(
        self,
        gbl: bool = False, # must be a global variable?
        param: bool = False, # must be a param?
        local: bool = False, # must be a local? (not global or param)
        has_location: bool = False, # has 1+ associated liveranges
        dtype_filter: FilterDataType = FilterDataType()
    ):
        self.gbl = gbl
        self.param = param
        self.local = local
        self.has_location = has_location
        self.dtype_filter = dtype_filter

    def __call__(self, var: Variable) -> bool:
        ret = True
        
        if self.gbl:
            ret = ret and var.is_global()

        if self.param:
            ret = ret and var.is_param()

        if self.local:
            ret = ret and var.is_local()

        if self.has_location:
            ret = ret and var.has_location()

        if self.dtype_filter:
            ret = ret and self.dtype_filter(var.dtype)

        return ret

class FilterVarnode(object):
    def __init__(
        self,
        dtype_filter: FilterDataType = FilterDataType()
    ):
        self.dtype_filter = dtype_filter

    def __call__(self, varnode: Varnode) -> bool:
        ret = True

        if self.dtype_filter:
            ret = ret and self.dtype_filter(varnode.get_datatype())

        return ret

class FilterVarnodeCompare2(object):
    def __init__(
        self,
        min_compare_level: int = VarnodeCompareLevel.NO_MATCH,
        max_compare_level: int = VarnodeCompareLevel.MATCH,
        start_aligned: bool = False,
        same_size: bool = False,
        varnode_filter: FilterVarnode = FilterVarnode(),
        dtype_compare_filter: FilterDataTypeCompare2 = FilterDataTypeCompare2()
    ):
        self.min_compare_level = min_compare_level
        self.max_compare_level = max_compare_level
        self.start_aligned = start_aligned
        self.same_size = same_size
        self.varnode_filter = varnode_filter
        self.dtype_compare_filter = dtype_compare_filter

    def __call__(self, cmp: VarnodeCompare2) -> bool:
        ret = True

        ret = ret and cmp.get_compare_level() >= self.min_compare_level and cmp.get_compare_level() <= self.max_compare_level

        if self.start_aligned:
            ret = ret and cmp.is_start_aligned()

        if self.same_size:
            ret = ret and cmp.is_same_size()

        if self.varnode_filter:
            ret = ret and self.varnode_filter(cmp.get_left()) and self.varnode_filter(cmp.get_right())

        if self.dtype_compare_filter and cmp.get_datatype_comparison() is not None:
            ret = ret and self.dtype_compare_filter(cmp.get_datatype_comparison())

        return ret


class FilterVarnodeCompareRecord(object):
    def __init__(
        self,
        min_compare_level: int = VarnodeCompareLevel.NO_MATCH,
        max_compare_level: int = VarnodeCompareLevel.MATCH,
        min_compared_with: int = 0,
        max_compared_with: int = 9999999,
        varnode_compare2_filter: FilterVarnodeCompare2 = FilterVarnodeCompare2()
    ):
        self.min_compare_level = min_compare_level
        self.max_compare_level = max_compare_level
        self.min_compared_with = min_compared_with
        self.max_compared_with = max_compared_with
        self.varnode_compare2_filter = varnode_compare2_filter

    def __call__(self, record: VarnodeCompareRecord) -> bool:
        ret = True

        ret = ret and record.get_compare_level() >= self.min_compare_level \
            and record.get_compare_level() <= self.max_compare_level \
            and record.compared_with() >= self.min_compared_with \
            and record.compared_with() <= self.max_compared_with

        if self.varnode_compare2_filter:
            ret = ret and all((self.varnode_compare2_filter(cmp) for cmp in record.get_varnode_comparison_map().values()))

        return ret