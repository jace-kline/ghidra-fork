from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

from compare_scope import *

class UnoptimizedProgramInfo(object):
    def __init__(self, proginfo: ProgramInfo):
        self.proginfo: ProgramInfo = proginfo
        
        # maps function start address to UnoptimizedFunction object
        self.unoptimized_functions: dict[AbsoluteAddress, UnoptimizedFunction] \
            = self._make_unoptimized_functions()

    def _make_unoptimized_functions(self) -> 'dict[AbsoluteAddress, UnoptimizedFunction]':
        _map = {}
        for function in self.get_proginfo().get_functions():
            _map[function.get_start_pc()] = UnoptimizedFunction(function)
        return _map

    def _make_varnode_globals(self):
        pass

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

# Wraps an UnoptimizedFunction object.
# Stores and exposes information about this function's comparison
# with 0+ other functions.
class UnoptimizedFunctionCompareRecord(object):
    def __init__(self, unoptimized_function: UnoptimizedFunction):
        self.unoptimized_function = unoptimized_function

# Holds information about the comparison between 2 unoptimized functions.
class UnoptimizedFunctionCompare2(object):
    def __init__(self,
        left: UnoptimizedFunction,
        right: UnoptimizedFunction,
        exact_match: bool = False
    ):
        self.left = left
        self.right = right
        self.exact_match = exact_match

    def get_left(self) -> UnoptimizedFunction:
        return self.left

    def get_right(self) -> UnoptimizedFunction:
        return self.right

    


