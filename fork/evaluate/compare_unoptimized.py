from typing import List, Tuple, Union
from lang import *
from lang_address import *
from lang_datatype import *
from util import *

class UnoptimizedProgramInfoCompareRecord(object):
    def __init__(self, proginfo: ProgramInfo, truth: bool = True):
        self.proginfo: ProgramInfo = proginfo
        self.truth: bool = truth # is this program info considered the "truth"?

    def get_proginfo(self) -> ProgramInfo:
        return self.proginfo

class UnoptimizedFunctionCompareRecord(object):
    pass

