
from lang_datatype import *
from compare_datatype import *

class FilterDataType(object):
    def __init__(
        self,
        primitive: bool = False,
        complex: bool = False,
        sized: bool = False
    ):
        self.primitive = primitive
        self.complex = complex
        self.sized = sized

    def __call__(self, dtype: DataType) -> bool:
        ret = True

        if self.primitive:
            ret = ret and dtype.is_primitive()

        if self.complex:
            ret = ret and dtype.is_complex()

        if self.sized:
            ret = ret and dtype.is_sized()

        return ret

class FilterDataTypePrimitiveCompare2(object):
    def __init__(
        self,
        min_compare_level: int = DataTypePrimitiveCompareLevel.NO_MATCH,
        max_compare_level: int = DataTypePrimitiveCompareLevel.MATCH
    ):
        self.min_compare_level = min_compare_level
        self.max_compare_level = max_compare_level

    def __call__(self, cmp: DataTypePrimitiveCompare2) -> bool:
        ret = True

        ret = ret and cmp.get_compare_level() >= self.min_compare_level and cmp.get_compare_level() <= self.max_compare_level

        return ret

class FilterDataTypeCompare2(object):
    def __init__(
        self,
        min_compare_level: int = DataTypeCompareLevel.NO_MATCH,
        max_compare_level: int = DataTypeCompareLevel.MATCH,
        start_aligned: bool = False,
        same_size: bool = False,
        same_metatype: bool = False,
        exact_match: bool = False,
        dtype_filter: FilterDataType = FilterDataType(),
        primitive_compare_filter: FilterDataTypePrimitiveCompare2 = FilterDataTypePrimitiveCompare2()
    ):
        self.min_compare_level = min_compare_level
        self.max_compare_level = max_compare_level
        self.start_aligned = start_aligned
        self.same_size = same_size
        self.same_metatype = same_metatype
        self.exact_match = exact_match
        self.dtype_filter = dtype_filter
        self.primitive_compare_filter = primitive_compare_filter

    def __call__(self, cmp: DataTypeCompare2) -> bool:
        ret = True

        ret = ret and cmp.get_compare_level() >= self.min_compare_level and cmp.get_compare_level() <= self.max_compare_level

        if self.start_aligned:
            ret = ret and cmp.start_aligned()

        if self.same_size:
            ret = ret and cmp.same_size()

        if self.same_metatype:
            ret = ret and cmp.same_metatype()

        if self.exact_match:
            ret = ret and cmp.exact_match()

        if self.dtype_filter:
            ret = ret and self.dtype_filter(cmp.get_left()) and self.dtype_filter(cmp.get_right())

        if self.primitive_compare_filter and cmp.get_primitive_comparison() is not None:
            ret = ret and self.primitive_compare_filter(cmp.get_primitive_comparison())

        return ret
