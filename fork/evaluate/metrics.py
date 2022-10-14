# This module is meant to be a place to define metrics/stats/etc
import array
from locale import normalize
from statistics import mean
from typing import Callable
from lang import *
from compare_unoptimized import *
from filter import *

class Metric(object):
    
    def __init__(
        self,
        id_name: str,
        display_name: str,
        compute: Callable, # UnoptimizedProgramInfoCompare2 -> Any
        description: str = "",
        tags: List[str] = []
    ):
        self.id_name = id_name
        self.display_name = display_name
        self.compute = compute
        self.description = description
        self.tags = tags

    def get_id_name(self) -> str:
        return self.id_name

    def get_display_name(self) -> str:
        return self.display_name

    def get_compute_function(self) -> Callable:
        return self.compute

    def get_description(self) -> str:
        return self.description

    def get_tags(self) -> str:
        return self.tags

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def __call__(self, cmp: UnoptimizedProgramInfoCompare2) -> Any:
        return self.compute(cmp)

    def __str__(self) -> str:
        return "<Metric id_name={}>".format(self.id_name)

    def __repr__(self) -> str:
        return self.__str__()

def make_metrics() -> 'dict[str, Metric]':
    _map = {}

    def _add_metric(
        id_name: str,
        display_name: str,
        compute: Callable, # UnoptimizedProgramInfoCompare2 -> Any
        description: str = "",
        tags: List[str] = []
    ):
        _map[id_name] = Metric(
            id_name,
            display_name,
            compute,
            description=description,
            tags=tags
        )

    # Data bytes metrics
    _add_metric(
        "bytes_truth",
        "Ground truth data bytes",
        bytes_truth,
        description="Data bytes captured in ground truth"
    )

    _add_metric(
        "bytes_decomp",
        "Decompiler data bytes",
        bytes_decomp,
        description="Data bytes inferred by the decompiler"
    )

    _add_metric(
        "bytes_found",
        "Overlapped data bytes",
        bytes_found,
        description="Data bytes present in ground truth that are found by decompiler"
    )

    _add_metric(
        "bytes_missed",
        "Missed data bytes",
        bytes_missed,
        description="Data bytes present in ground truth that are not found by decompiler"
    )

    _add_metric(
        "bytes_extraneous",
        "Extraneous decompiler data bytes",
        bytes_extraneous,
        description="Data bytes inferred by decompiler that are not present in ground truth"
    )

    # Function metrics
    _add_metric(
        "functions_truth",
        "Ground truth functions",
        lambda cmp: len(functions_truth(cmp)),
        description="Functions captured in ground truth"
    )

    _add_metric(
        "functions_decomp",
        "Decompiler functions",
        lambda cmp: len(functions_decomp(cmp)),
        description="Functions inferred by the decompiler"
    )

    _add_metric(
        "functions_found",
        "Found functions",
        lambda cmp: len(functions_found(cmp)),
        description="Functions present in ground truth that are found by decompiler, based on function entry point address"
    )

    _add_metric(
        "functions_missed",
        "Missed functions",
        lambda cmp: len(functions_missed(cmp)),
        description="Functions present in ground truth that are not found by decompiler"
    )

    _add_metric(
        "functions_extraneous",
        "Extraneous decompiler functions",
        lambda cmp: len(functions_extraneous(cmp)),
        description="Functions inferred by decompiler that are not present in ground truth"
    )

    # High-level Varnode metrics
    _add_metric(
        "varnodes_truth",
        "Ground truth varnodes",
        lambda cmp: len(varnodes_truth(cmp)),
        description="High-level variable instances (varnodes) present in ground truth"
    )

    _add_metric(
        "varnodes_decomp",
        "Decompiler varnodes",
        lambda cmp: len(varnodes_decomp(cmp)),
        description="High-level variable instances (varnodes) inferred by decompiler"
    )

    for compare_level in VarnodeCompareLevel.range():
        compare_level_str = VarnodeCompareLevel.to_string(compare_level)
        _add_metric(
            "varnodes_matched_at_above_{}".format(compare_level_str),
            "Varnodes matched @ or above level={}".format(compare_level_str),
            lambda cmp: len(varnode_compare_records_matched_at_above_level(cmp, compare_level))
        )

    _add_metric(
        "varnodes_missed",
        "Missed varnodes",
        lambda cmp: len(varnodes_missed(cmp)),
        description="High-level variable instances (varnodes) present in ground truth that are not overlapped by decompiler"
    )

    _add_metric(
        "varnodes_extraneous",
        "Extraneous decompiler varnodes",
        lambda cmp: len(varnodes_extraneous(cmp)),
        description="High-level variable instances (varnodes) inferred by decompiler but not present in ground truth"
    )

    _add_metric(
        "varnodes_avg_compare_score",
        "Average high-level varnode comparison score [0,1]",
        varnodes_avg_compare_score,
        description="Average high-level varnode comparison score [0,1] for comparisons of each ground truth varnode"
    )


    # Primitive Varnode metrics
    _add_metric(
        "primitive_varnodes_truth",
        "Ground truth decomposed (primitive) varnodes",
        lambda cmp: len(varnodes_truth(cmp, primitive=True)),
        description="Decomposed primitive variable instances (varnodes) present in ground truth"
    )

    _add_metric(
        "primitive_varnodes_decomp",
        "Decompiler decomposed (primitive) varnodes",
        lambda cmp: len(varnodes_decomp(cmp, primitive=True)),
        description="Decomposed (primitive) variable instances (varnodes) inferred by decompiler"
    )

    for compare_level in VarnodeCompareLevel.range():
        compare_level_str = VarnodeCompareLevel.to_string(compare_level)
        _add_metric(
            "primitive_varnodes_matched_at_above_{}".format(compare_level_str),
            "Decomposed (primitive) varnodes matched @ or above level={}".format(compare_level_str),
            lambda cmp: len(varnode_compare_records_matched_at_above_level(cmp, compare_level, primitive=True))
        )

    _add_metric(
        "primitive_varnodes_missed",
        "Missed decomposed (primitive) varnodes",
        lambda cmp: len(varnodes_missed(cmp, primitive=True)),
        description="Decomposed (primitive) variable instances (varnodes) present in ground truth that are not overlapped by decompiler"
    )

    _add_metric(
        "primitive_varnodes_extraneous",
        "Extraneous decomposed (primitive) decompiler varnodes",
        lambda cmp: len(varnodes_extraneous(cmp, primitive=True)),
        description="Decomposed (primitive) variable instances (varnodes) inferred by decompiler but not present in ground truth"
    )

    _add_metric(
        "primitive_varnodes_avg_compare_score",
        "Average decomposed (primitive) varnode comparison score [0,1]",
        lambda cmp: varnodes_avg_compare_score(cmp, primitive=True),
        description="Average decomposed (primitive) varnode comparison score [0,1] for comparisons of each ground truth varnode"
    )

    # MetaType-specific Varnode metrics
    for metatype in [MetaType.INT, MetaType.FLOAT, MetaType.POINTER, MetaType.ARRAY, MetaType.STRUCT, MetaType.UNION, MetaType.UNDEFINED]:
        metatype_str = MetaType.repr(metatype)
        _add_metric(
            "varnodes_truth_metatype_{}".format(metatype_str),
            "Ground truth varnodes w/ metatype={}".format(metatype_str),
            lambda cmp: len(varnodes_truth_metatype(cmp, metatype))
        )

        _add_metric(
            "varnodes_decomp_metatype_{}".format(metatype_str),
            "Decompiler varnodes w/ metatype={}".format(metatype_str),
            lambda cmp: len(varnodes_decomp_metatype(cmp, metatype))
        )

        _add_metric(
            "varnodes_missed_metatype_{}".format(metatype_str),
            "Missed varnodes w/ metatype={}".format(metatype_str),
            lambda cmp: len(varnodes_missed_metatype(cmp, metatype))
        )

        for compare_level in VarnodeCompareLevel.range():
            compare_level_str = VarnodeCompareLevel.to_string(compare_level)
            _add_metric(
                "varnodes_matched_at_above_{}_metatype_{}".format(compare_level_str, metatype_str),
                "Decompiler varnodes w/ metatype={} matched @ or above level={}".format(metatype_str, compare_level_str),
                lambda cmp: len(varnodes_decomp_metatype(cmp, metatype))
            )

        _add_metric(
            "varnodes_avg_compare_score_metatype_{}".format(metatype_str),
            "Average varnode compare score [0,1] w/ metatype={}".format(metatype_str),
            lambda cmp: len(varnodes_avg_compare_score_metatype(cmp, metatype))
        )

    # Array comparison metrics
    _add_metric(
        "array_comparisons",
        "Array comparisons",
        lambda cmp: len(array_comparisons(cmp))
    )

    _add_metric(
        "array_length_avg_diff",
        "Array length average difference (ground truth length - decompiler length)",
        mean_over_array_comparisons(array_elements_diff)
    )

    _add_metric(
        "array_length_avg_error",
        "Array length average absolute error",
        mean_over_array_comparisons(array_elements_error)
    )

    _add_metric(
        "array_length_avg_error_ratio",
        "Array length average absolute error ratio (length error / ground truth length)",
        mean_over_array_comparisons(array_elements_error_ratio)
    )

    _add_metric(
        "array_size_avg_diff",
        "Array size average difference (ground truth size - decompiler size)",
        mean_over_array_comparisons(array_size_diff)
    )

    _add_metric(
        "array_size_avg_error",
        "Array size average absolute error",
        mean_over_array_comparisons(array_size_error)
    )

    _add_metric(
        "array_size_avg_error_ratio",
        "Array size average absolute error ratio (size error / ground truth size)",
        mean_over_array_comparisons(array_size_error_ratio)
    )

# Utility stuff / shared functions

# from a range, constructs a function that maps a member in that range
# to a number in continuous range [0,1]
def normalize_range(r: range) -> Callable:
    def inner(x) -> float:
        return (x - r.start) / (r.stop - r.step - r.start)
    return inner

def varnode_compare_level_to_normalized_score(lvl) -> float:
    return normalize_range(VarnodeCompareLevel.range())(lvl)

def datatype_compare_level_to_normalized_score(lvl) -> float:
    return normalize_range(DataTypeCompareLevel.range())(lvl)

# FunctionCompareRecord base filter
# return True if the function comparison is not None
def _function_compare_record_compared_filter(fn_cmp: UnoptimizedFunctionCompareRecord) -> bool:
    return fn_cmp.is_comparison()

# Variable base filter
# variable is not a parameter & has single location associated with it
def _variable_base_filter(var: Variable) -> bool:
    parent_fn = var.get_parent_function()
    return not var.is_param() \
        and var.is_single_loc()

# Varnode base filter
# varnode lives in a rangeable address region (stack, global, or register offset)
# & its parent variable matches the variable base filter
def _varnode_base_filter(varnode: Varnode) -> bool:
    parent_var = varnode.get_var()
    return varnode.get_addr().get_region().is_range() \
        and (_variable_base_filter(parent_var) if parent_var is not None else True)

# VarnodeCompareRecord base filter
# record's varnode satisfies the Varnode base filter
def _varnode_compare_record_base_filter(record: VarnodeCompareRecord) -> bool:
    return _varnode_base_filter(record.get_varnode())

# select all varnodes (possibly primitive) from either the left or right program info objects
# that satisfy the Varnode base filter
def _select_base_varnodes(cmp: UnoptimizedProgramInfoCompare2, left: bool = True, primitive: bool = False) -> List[Varnode]:
    proginfo = cmp.get_left() if left else cmp.get_right()
    method = proginfo.select_primitive_varnodes if primitive else proginfo.select_varnodes
    return method(variable_cond=_variable_base_filter, varnode_cond=_varnode_base_filter)

# select all VarnodeCompareRecord objects (possibly primitive) from either the left or right program info objects
# that satisfy the VarnodeCompareRecord base filter
def _select_base_varnode_compare_records(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> List[VarnodeCompareRecord]:
    method = cmp.select_primitive_varnode_compare_records if primitive else cmp.select_varnode_compare_records
    return method(varnode_cmp_record_cond=_varnode_compare_record_base_filter)

# select all VarnodeCompareRecord objects (possibly primitive) that match the base filters
# & contain a varnode that is either a global OR appears in a found/comparable function
def _select_comparable_varnode_compare_records(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> List[VarnodeCompareRecord]:
    method = cmp.select_primitive_varnode_compare_records if primitive else cmp.select_varnode_compare_records
    return method(
        function_cmp_record_cond=_function_compare_record_compared_filter,
        varnode_cmp_record_cond=_varnode_compare_record_base_filter
    )

# select all Varnode objects (possibly primitive) that match the base filters
# & are either globals OR appear in found functions
def _select_comparable_varnodes(cmp: UnoptimizedProgramInfoCompare2, left: bool = True, primitive: bool = False) -> List[Varnode]:
    _cmp = cmp if left else cmp.flip()
    return [ record.get_varnode() for record in _select_comparable_varnode_compare_records(_cmp, primitive=primitive) ]

# --------------------- BYTES --------------------------
# Ground-truth data bytes
def bytes_truth(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return sum([ varnode.get_size() for varnode in varnodes_truth(cmp) ])

# Decompiler data bytes
def bytes_decomp(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return sum([ varnode.get_size() for varnode in varnodes_decomp(cmp) ])

# Found bytes (in ground-truth & decompiler)
def bytes_found(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return sum([ cmp2.bytes_overlapped() for cmp2 in cmp.select_varnode_comparisons() ])

# Missed bytes (in ground-truth, not in decompiler)
def bytes_missed(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return bytes_truth(cmp) - bytes_found(cmp)

# Extraneous bytes (in decompiler, not in ground-truth)
def bytes_extraneous(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return bytes_decomp(cmp) - bytes_found(cmp)

# -------------------- FUNCTIONS -----------------------
# Ground-truth functions
def functions_truth(cmp: UnoptimizedProgramInfoCompare2) -> List[UnoptimizedFunction]:
    return list(cmp.get_left().get_unoptimized_functions().values())

# Decompiler functions
def functions_decomp(cmp: UnoptimizedProgramInfoCompare2) -> List[UnoptimizedFunction]:
    return list(cmp.get_right().get_unoptimized_functions().values())

# Found functions (in ground-truth & decompiler)
def functions_found(cmp: UnoptimizedProgramInfoCompare2) -> List[UnoptimizedFunction]:
    return [ record.get_unoptimized_function() for record in cmp.select_function_compare_records() if record.is_comparison() ]

# Missed functions (in ground-truth, not in decompiler)
def functions_missed(cmp: UnoptimizedProgramInfoCompare2) -> List[UnoptimizedFunction]:
    return [ record.get_unoptimized_function() for record in cmp.select_function_compare_records() if not record.is_comparison() ]

# Extraneous functions (in decompiler, not in ground-truth)
def functions_extraneous(cmp: UnoptimizedProgramInfoCompare2) -> List[UnoptimizedFunction]:
    return functions_missed(cmp.flip())

# ------------------ HIGH-LEVEL VARNODES -------------------
# Ground-truth high-level varnodes that are globals OR found in compared functions
def varnodes_truth(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> List[Varnode]:
    return _select_comparable_varnodes(cmp, left=True, primitive=primitive)

# Decompiler high-level varnodes that are globals OR found in compared functions
def varnodes_decomp(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> List[Varnode]:
    return _select_comparable_varnodes(cmp, left=False, primitive=primitive)

def _varnodes_missed(varnode_cmp_records: List[VarnodeCompareRecord]) -> List[Varnode]:
    return [ record.get_varnode() for record in _varnode_compare_records_match_levels(varnode_cmp_records, [VarnodeCompareLevel.NO_MATCH]) ]

# Missed high-level varnodes (ground-truth varnodes not compared with any decomp varnodes)
def varnodes_missed(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> List[Varnode]:
    return [ record.get_varnode() for record in varnode_compare_records_match_levels(cmp, [VarnodeCompareLevel.NO_MATCH], primitive=primitive) ]

# Overlapped ground-truth high-level varnodes

def _varnode_compare_records_match_levels(varnode_cmp_records: List[VarnodeCompareRecord], levels: List[int]) -> List[VarnodeCompareRecord]:
    return [ record for record in varnode_cmp_records if record.get_compare_level() in levels ]

def _varnode_compare_records_matched_at_above_level(varnode_cmp_records: List[VarnodeCompareRecord], level: int) -> List[VarnodeCompareRecord]:
    return [ record for record in varnode_cmp_records if record.get_compare_level() >= level ]

# Ground-truth high-level varnodes matched @ or above <TAG>
def varnode_compare_records_match_levels(cmp: UnoptimizedProgramInfoCompare2, levels: List[int], primitive: bool = False) -> List[VarnodeCompareRecord]:
    return _varnode_compare_records_match_levels(_select_comparable_varnode_compare_records(cmp, primitive=primitive))

def varnode_compare_records_matched_at_above_level(cmp: UnoptimizedProgramInfoCompare2, level: int, primitive: bool = False) -> List[VarnodeCompareRecord]:
    return _varnode_compare_records_matched_at_above_level(_select_comparable_varnode_compare_records(cmp, primitive=primitive))

# Extraneous high-level varnodes (in decompiler, not overlapped with ground truth)
def varnodes_extraneous(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> List[Varnode]:
    return varnodes_missed(cmp.flip(), primitive=primitive)

def _varnodes_avg_compare_level(varnode_cmp_records: List[VarnodeCompareRecord]) -> float:
    return mean([ record.get_compare_level() for record in varnode_cmp_records ])

# map each VarnodeCompareLevel into its integer encoding and find the average across all compare records
def varnodes_avg_compare_level(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> float:
    return _varnodes_avg_compare_level(_select_comparable_varnode_compare_records(cmp, primitive=primitive))

def varnodes_avg_compare_score(cmp: UnoptimizedProgramInfoCompare2, primitive: bool = False) -> float:
    return varnode_compare_level_to_normalized_score(varnodes_avg_compare_level(cmp, primitive=primitive))

# --------------- TYPE-SPECIFIC VARNODE COMPARISONS --------------------
def _select_comparable_varnodes_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int, left: bool = True, primitive: bool = False) -> List[Varnode]:
    return [ varnode for varnode in _select_comparable_varnodes(cmp, left=left, primitive=primitive) if varnode.get_datatype().get_metatype() == metatype ]

def _select_comparable_varnode_compare_records_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int, primitive: bool = False) -> List[VarnodeCompareRecord]:
    return [ record for record in _select_comparable_varnode_compare_records(cmp, primitive=primitive) if record.get_varnode().get_datatype().get_metatype() == metatype ]

# Ground-truth varnodes w/ metatype
def varnodes_truth_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int, primitive: bool = False) -> List[Varnode]:
    return _select_comparable_varnodes_metatype(cmp, metatype, left=True, primitive=primitive)

# Decompiler varnodes w/ metatype
def varnodes_decomp_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int, primitive: bool = False) -> List[Varnode]:
    return _select_comparable_varnodes_metatype(cmp, metatype, left=False, primitive=primitive)

def varnodes_missed_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int, primitive: bool = False) -> List[Varnode]:
    return _varnodes_missed(_select_comparable_varnode_compare_records_metatype(cmp, metatype, primitive=primitive))

def varnodes_avg_compare_level_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int, primitive: bool = False) -> float:
    return _varnodes_avg_compare_level(_select_comparable_varnode_compare_records_metatype(cmp, metatype, primitive=primitive))

def varnodes_avg_compare_score_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int, primitive: bool = False) -> float:
    return varnode_compare_level_to_normalized_score(varnodes_avg_compare_level_metatype(cmp, metatype, primitive=primitive))

# Recovered ARRAY varnodes (in ground-truth & in decompiler - overlapped & same metatype)
def array_comparisons(cmp: UnoptimizedProgramInfoCompare2) -> List[VarnodeCompare2]:
    return cmp.select_varnode_comparisons(varnode_cmp_record_cond=_varnode_compare_record_base_filter, varnode_cmp2_cond=lambda record: record.get_left().get_datatype().get_metatype() == MetaType.ARRAY and record.get_right().get_datatype().get_metatype() == MetaType.ARRAY)

# f: VarnodeCompare2 -> int
# return: UnoptimizedProgramInfoCompare2 -> float
def mean_over_array_comparisons(f: Callable) -> Callable:
    return lambda cmp: mean([ f(cmp2) for cmp2 in array_comparisons(cmp) ])

## length inaccuracy (elements) of an array comparison
def array_elements_diff(cmp: VarnodeCompare2) -> int:
    return cmp.get_left().get_datatype().get_num_elements() - cmp.get_right().get_datatype().get_num_elements()

def array_elements_error(cmp: VarnodeCompare2) -> int:
    return abs(array_elements_diff(cmp))

## length inaccuracy ratio of an array comparison
def array_elements_error_ratio(cmp: VarnodeCompare2) -> float:
    return array_elements_error(cmp) / cmp.get_left().get_datatype().get_num_elements()

## size inaccuracy (bytes) of an array comparison
def array_size_diff(cmp: VarnodeCompare2) -> int:
    return cmp.get_left().get_size() - cmp.get_right().get_size()

def array_size_error(cmp: VarnodeCompare2) -> int:
    return abs(array_size_diff(cmp))

## size inaccuracy ratio of an array comparison
def array_size_error_ratio(cmp: VarnodeCompare2) -> float:
    return array_size_error(cmp) / cmp.get_left().get_size()

def _subtype_comparisons(cmps: List[VarnodeCompare2]) -> List[DataTypeCompare2]:
    def subtype_comparison(cmp: VarnodeCompare2) -> DataTypeCompare2:
        left_subtype = cmp.get_left().get_datatype().get_basetype()
        right_subtype = cmp.get_right().get_datatype().get_basetype()
        return DataTypeCompare2(left_subtype, right_subtype, 0)

    return [ subtype_comparison(cmp) for cmp in cmps ]

## subtype match % -> how many of the array comparisons had matching subtypes?
def _array_subtype_match_ratio(cmps: List[VarnodeCompare2], level: int = DataTypeCompareLevel.MATCH) -> float:
    subtype_matches = len([ cmp for cmp in _subtype_comparisons(cmps) if cmp.get_compare_level() >= level ])
    return subtype_matches / len(cmps)

def array_subtype_match_ratio(cmp: UnoptimizedProgramInfoCompare2, level: int = DataTypeCompareLevel.MATCH) -> float:
    return _array_subtype_match_ratio(array_comparisons(cmp), level=level)

def _array_subtype_avg_compare_level(cmps: List[VarnodeCompare2]) -> float:
    return mean([ cmp2.get_compare_level() for cmp2 in _subtype_comparisons(cmps) ])

def array_subtype_avg_compare_level(cmp: UnoptimizedProgramInfoCompare2) -> float:
    return _array_subtype_avg_compare_level(array_comparisons(cmp))

def _array_subtype_avg_compare_score(cmps: List[VarnodeCompare2]) -> float:
    return datatype_compare_level_to_normalized_score(_array_subtype_avg_compare_level(cmps))

def array_subtype_avg_compare_score(cmp: UnoptimizedProgramInfoCompare2) -> float:
    return _array_subtype_avg_compare_score(array_comparisons(cmp))

## correct dimension % -> how many of the array comparisons had matching number of dimensions?
def _array_dimension_match_ratio(cmps: List[VarnodeCompare2]) -> float:
    dim_matches = 0
    for cmp in cmps:
        left_dims = cmp.get_left().get_datatype().num_dimensions()
        right_dims = cmp.get_right().get_datatype().num_dimensions()
        if left_dims == right_dims:
            dim_matches += 1

    return dim_matches / len(cmps)

# Recovered STRUCT varnodes (in ground-truth & in decompiler - overlapped & same metatype)
## average size inaccuracy (bytes)
## average size inaccuracy %
## average member type match %

# Ground-truth STRUCT varnodes matched @ or above <TAG>

# Extraneous STRUCT varnodes

def _mk_metrics(cmp: UnoptimizedProgramInfoCompare2) -> dict:
    METRICS = {
        "BYTES" : {
            "bytes - ground truth" : bytes_truth(cmp),
            "bytes - decompiler" : bytes_decomp(cmp),
            "bytes found" : bytes_found(cmp),
            "bytes missed" : bytes_missed(cmp),
            "bytes extraneous" : bytes_extraneous(cmp),
            "bytes found %" : 100.0 * (bytes_found(cmp) / bytes_truth(cmp))
        },
        "FUNCTIONS" : {
            "functions - ground truth" : len(functions_truth(cmp)),
            "functions - decompiler": len(functions_decomp(cmp)),
            "functions found" : len(functions_found(cmp)),
            "functions missed" : len(functions_missed(cmp)),
            "functions extraneous" : len(functions_extraneous(cmp)),
            "functions found %" : 100.0 * (len(functions_found(cmp)) / len(functions_truth(cmp)))
        },
    }

    varnodes_group = {}
    _varnodes_truth = len(varnodes_truth(cmp))
    varnodes_group["varnodes - ground truth"] = _varnodes_truth
    varnodes_group["varnodes - decompiler"] = len(varnodes_decomp(cmp))
    for level in range(VarnodeCompareLevel.NO_MATCH, VarnodeCompareLevel.MATCH + 1):
        varnodes_group["varnodes matched @ or above {}".format(VarnodeCompareLevel.to_string(level))] = len(varnode_compare_records_matched_at_above_level(cmp, level))
    varnodes_group["varnodes missed"] = len(varnodes_missed(cmp))
    varnodes_group["varnodes extraneous"] = len(varnodes_extraneous(cmp))
    varnodes_group["varnodes match %"] = 100.0 * (len(varnode_compare_records_matched_at_above_level(cmp, VarnodeCompareLevel.MATCH)) / _varnodes_truth)
    METRICS["VARNODES"] = varnodes_group

    primitives_group = {}
    _primitives_truth = len(varnodes_truth(cmp, primitive=True))
    primitives_group["primitive varnodes - ground truth"] = _primitives_truth
    primitives_group["primitive varnodes - decompiler"] = len(varnodes_decomp(cmp, primitive=True))
    for level in range(VarnodeCompareLevel.NO_MATCH, VarnodeCompareLevel.MATCH + 1):
        primitives_group["primitive varnodes matched @ or above {}".format(VarnodeCompareLevel.to_string(level))] = len(varnode_compare_records_matched_at_above_level(cmp, level, primitive=True))
    primitives_group["primitive varnodes missed"] = len(varnodes_missed(cmp, primitive=True))
    primitives_group["primitive varnodes extraneous"] = len(varnodes_extraneous(cmp, primitive=True))
    primitives_group["primitive varnodes match %"] = 100.0 * (len(varnode_compare_records_matched_at_above_level(cmp, VarnodeCompareLevel.MATCH, primitive=True)) / _primitives_truth)
    METRICS["PRIMITIVE VARNODES"] = primitives_group

    # parameters_group = {}
    # params_truth = cmp.get_left().select_varnodes(variable_cond=lambda var: var.is_param())
    # parameters_group["parameter varnodes - ground truth"] = params_truth
    # params_decomp = cmp.get_right().select_varnodes(variable_cond=lambda var: var.is_param())
    # parameters_group["parameter varnodes - decompiler"] = params_decomp
    # param_overlaps = cmp.select_varnode_compare_records(varnode_cmp_record_cond=lambda record: record.get_var() is not None and record.get_var().is_param() and record.get_compare_level() > VarnodeCompareLevel.NO_MATCH)
    # parameters_group["parameter overlaps"] = param_overlaps
    # METRICS["PARAMETER VARNODES"] = parameters_group

    for metatype in [MetaType.INT, MetaType.FLOAT, MetaType.POINTER, MetaType.ARRAY, MetaType.STRUCT, MetaType.UNION, MetaType.UNDEFINED]:
        metatype_group = {}
        truth = len(varnodes_truth_metatype(cmp, metatype))
        metatype_group["(metatype = {}) varnodes - ground truth".format(MetaType.repr(metatype))] = truth
        metatype_group["(metatype = {}) varnodes - decompiler".format(MetaType.repr(metatype))] = len(varnodes_decomp_metatype(cmp, metatype))
        metatype_group["(metatype = {}) varnodes missed".format(MetaType.repr(metatype))] = len([ record for record in varnode_compare_records_match_levels(cmp, [VarnodeCompareLevel.NO_MATCH]) if record.get_varnode().get_datatype().get_metatype() == metatype ])

        aligned = len([ record for record in varnode_compare_records_matched_at_above_level(cmp, VarnodeCompareLevel.ALIGNED) if record.get_varnode().get_datatype().get_metatype() == metatype ])
        metatype_group["(metatype = {}) varnodes matched @ or above ALIGNED".format(MetaType.repr(metatype))] = aligned

        matched = len([ record for record in varnode_compare_records_matched_at_above_level(cmp, VarnodeCompareLevel.MATCH) if record.get_varnode().get_datatype().get_metatype() == metatype ])
        metatype_group["(metatype = {}) varnodes matched @ MATCH".format(MetaType.repr(metatype))] = matched
        if truth > 0:
            metatype_group["(metatype = {}) varnodes match %".format(MetaType.repr(metatype))] = 100.0 * (matched / truth)
        METRICS["METATYPE SUMMARY ({})".format(MetaType.repr(metatype))] = metatype_group

    array_group = {}
    array_cmps = array_comparisons(cmp)
    array_group["array comparisons"] = len(array_cmps)
    array_group["arrays missed"] = len([ record for record in varnode_compare_records_match_levels(cmp, [VarnodeCompareLevel.NO_MATCH]) if record.get_varnode().get_datatype().get_metatype() == MetaType.ARRAY ])
    if array_cmps:
        array_group["array - avg elements error"] = mean([ array_elements_error(array_cmp) for array_cmp in array_cmps ])
        array_group["array - avg elements error %"] = 100 * mean([ array_elements_error_ratio(array_cmp) for array_cmp in array_cmps ])
        array_group["array - avg size error (bytes)"] = mean([ array_size_error(array_cmp) for array_cmp in array_cmps ])
        array_group["array - avg size error (bytes) %"] = 100 * mean([ array_size_error_ratio(array_cmp) for array_cmp in array_cmps ])
        array_group["array - subtype match %"] = 100 * _array_subtype_match_ratio(array_cmps)
        array_group["array - # of dimensions match %"] = 100 * _array_dimension_match_ratio(array_cmps)

    METRICS["ARRAY RECOVERY"] = array_group

    return METRICS


def display_metrics(cmp: UnoptimizedProgramInfoCompare2):
    _map = _mk_metrics(cmp)

    for grp, metric in _map.items():
        print("{} {} {}".format("-"*10, grp, "-"*10))
        for lbl, val in metric.items():
            print("{} : {}".format(lbl, val))
        print(),

        