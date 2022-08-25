from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

from compare_variable import *
from compare_scope import *

class UnoptimizedProgramInfo(object):
    def __init__(self, proginfo: ProgramInfo):
        self.proginfo: ProgramInfo = proginfo
        
        # maps function start address to UnoptimizedFunction object
        self.unoptimized_functions: dict[AbsoluteAddress, UnoptimizedFunction] \
            = self._make_unoptimized_functions()

        # the set of global variables (converted to Varnodes)
        self.globals_set: ConstPCVariableSetSnapshot = self._make_unoptimized_globals_set()

    def _make_unoptimized_functions(self) -> 'dict[AbsoluteAddress, UnoptimizedFunction]':
        _map = {}
        for function in self.get_proginfo().get_functions():
            _map[function.get_start_pc()] = UnoptimizedFunction(function)
        return _map

    def _make_unoptimized_globals_set(self) -> ConstPCVariableSetSnapshot:
        varnodes = [ varnode for varnode in 
            [ Varnode.from_single_location_variable(var) for var in globals ]
            if varnode is not None
        ]
        return ConstPCVariableSetSnapshot(varnodes)

    def get_proginfo(self) -> ProgramInfo:
        return self.proginfo

class UnoptimizedProgramInfoCompare2(object):
    def __init__(self,
        left: UnoptimizedProgramInfo,
        right: UnoptimizedProgramInfo
    ):
        self.left = left
        self.right = right

    def get_left(self) -> UnoptimizedProgramInfo:
        return self.left

    def get_right(self) -> UnoptimizedProgramInfo:
        return self.right

    def flip(self) -> 'UnoptimizedProgramInfoCompare2':
        return __class__(self.right, self.left)

    def make_left_compare_record(self) -> 'UnoptimizedProgramInfoCompareRecord':
        return UnoptimizedProgramInfoCompareRecord(self.left, self)

    def make_right_compare_record(self) -> 'UnoptimizedProgramInfoCompareRecord':
        return self.flip().make_left_compare_record()

# wraps an UnoptimizedProgramInfo object
# exposes info about the comparison between this proginfo and another
class UnoptimizedProgramInfoCompareRecord(object):
    def __init__(self,
        unoptimized_proginfo: UnoptimizedProgramInfo,
        comparison: UnoptimizedProgramInfoCompare2
    ):
        self.unoptimized_proginfo = unoptimized_proginfo
        self.comparison = comparison

        # ensure the comparison aligns with the proginfo
        assert( self.unoptimized_proginfo is self.comparison.get_left() )

# A wrapper around a Function object that assumes that all variables
# & params have only 1 location throughout the course of the function.
class UnoptimizedFunction(object):
    def __init__(self, function: Function):
        self.function = function

    def get_function(self) -> Function:
        return self.function

    def get_pc_range(self) -> AddressRange:
        return self.function.get_pc_range()

    def get_param_varnodes(self) -> List[Varnode]:
        pass

    def get_variable_varnodes(self) -> List[Varnode]:
        pass

class UnoptimizedFunctionCompare2(object):
    def __init__(self,
        left: UnoptimizedFunction,
        right: UnoptimizedFunction
    ):
        self.left = left
        self.right = right

        self.pc_range_overlap = AddressRangeOverlap(self.left.get_pc_range(), self.right.get_pc_range())

        # only if start PC of functions is equal do we compare the variables/params
        if self.pc_range_start_aligned():
            # TODO: compare param/variable sets
            pass

    def get_left(self) -> UnoptimizedFunction:
        return self.left

    def get_right(self) -> UnoptimizedFunction:
        return self.right

    def does_pc_range_overlap(self) -> bool:
        return self.pc_range_overlap.does_overlap()

    def pc_range_start_aligned(self) -> bool:
        return self.pc_range_overlap.start_aligned()

    def pc_range_end_aligned(self) -> bool:
        return self.pc_range_overlap.end_aligned()

    def pc_range_match(self) -> bool:
        return self.left.get_pc_range() == self.right.get_pc_range()

    def pc_range_bytes_overlapped(self) -> int:
        return self.pc_range_overlap.bytes_overlapped()

    def flip(self) -> 'UnoptimizedFunctionCompare2':
        return __class__(self.right, self.left)

# Wraps an UnoptimizedFunction object.
# Stores and exposes information about this function's comparison
# with 0+ other functions.
class UnoptimizedFunctionCompareRecord(object):
    def __init__(self,
        unoptimized_function: UnoptimizedFunction,
        comparison: Union[UnoptimizedFunctionCompare2, None]
    ):
        self.unoptimized_function = unoptimized_function
        self.comparison = comparison

    def get_unoptimized_function(self) -> UnoptimizedFunction:
        return self.unoptimized_function

    def get_comparison(self) -> Union[UnoptimizedFunctionCompare2, None]:
        return self.comparison

# Holds information about the comparison between 2 unoptimized functions.
class UnoptimizedFunctionCompare2(object):
    def __init__(self,
        left: UnoptimizedFunction,
        right: UnoptimizedFunction
    ):
        self.left = left
        self.right = right

    def get_left(self) -> UnoptimizedFunction:
        return self.left

    def get_right(self) -> UnoptimizedFunction:
        return self.right

    


