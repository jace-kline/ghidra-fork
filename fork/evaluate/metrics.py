# This module is meant to be a place to define metrics/stats/etc
from lang import *
from compare_unoptimized import *

class ProgramInfoComparisonMetrics(object):
    def __init__(self, cmp: ProgramInfo):
        self.cmp = cmp
        