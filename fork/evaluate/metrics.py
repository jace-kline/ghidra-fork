# This module is meant to be a place to define metrics/stats/etc
from statistics import mean
from typing import Callable
from lang import *
from compare_unoptimized import *
from filter import *

# --------------------- BYTES --------------------------
# Ground-truth bytes
def bytes_truth(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return sum([ varnode.get_size() for varnode in varnodes_truth(cmp) ])

# Decompiler bytes
def bytes_decomp(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return sum([ varnode.get_size() for varnode in varnodes_decomp(cmp) ])

# Found bytes (in ground-truth & decompiler)
def bytes_found(cmp: UnoptimizedProgramInfoCompare2) -> int:
    return cmp.bytes_overlapped()

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
# Ground-truth high-level varnodes
def varnodes_truth(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return cmp.get_left().select_varnodes(variable_cond=lambda var: not var.is_param())

# Decompiler high-level varnodes
def varnodes_decomp(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return cmp.get_right().select_varnodes(variable_cond=lambda var: not var.is_param())

# Missed high-level varnodes (ground-truth varnodes not compared with any decomp varnodes)
def varnodes_missed(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return [ record.get_varnode() for record in varnodes_match_levels(cmp, [VarnodeCompareLevel.NO_MATCH]) ]

# Overlapped ground-truth high-level varnodes

# Ground-truth high-level varnodes matched @ or above <TAG>
def varnodes_match_levels(cmp: UnoptimizedProgramInfoCompare2, levels: List[int]) -> List[VarnodeCompareRecord]:
    return cmp.select_varnode_compare_records(varnode_cmp_record_cond=lambda record: (record.get_var() is None or not record.get_var().is_param()) and record.get_compare_level() in levels)

def varnodes_matched_at_above_level(cmp: UnoptimizedProgramInfoCompare2, level: int) -> List[VarnodeCompareRecord]:
    return cmp.select_varnode_compare_records(varnode_cmp_record_cond=lambda record: (record.get_var() is None or not record.get_var().is_param()) and record.get_compare_level() >= level)

# Extraneous high-level varnodes (in decompiler, not overlapped with ground truth)
def varnodes_extraneous(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return varnodes_missed(cmp.flip())


# ---------- PRIMITIVE (DECOMPOSED) VARNODES ----------------
# Ground-truth primitive (flattened/decomposed) varnodes
def primitive_varnodes_truth(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return cmp.get_left().select_primitive_varnodes(variable_cond=lambda var: not var.is_param())

# Decompiler primitive varnodes
def primitive_varnodes_decomp(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return cmp.get_right().select_primitive_varnodes(variable_cond=lambda var: not var.is_param())

# Missed primitive varnodes
def primitive_varnodes_missed(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return [ record.get_varnode() for record in primitive_varnodes_match_levels(cmp, [VarnodeCompareLevel.NO_MATCH]) ]

# Overlapped ground-truth primitive varnodes

# Ground-truth primitive variables matched @ or above <TAG>
def primitive_varnodes_match_levels(cmp: UnoptimizedProgramInfoCompare2, levels: List[int]) -> List[VarnodeCompareRecord]:
    return cmp.select_primitive_varnode_compare_records(varnode_cmp_record_cond=lambda record: (record.get_var() is None or not record.get_var().is_param()) and record.get_compare_level() in levels)

def primitive_varnodes_matched_at_above_level(cmp: UnoptimizedProgramInfoCompare2, level: int) -> List[VarnodeCompareRecord]:
    return cmp.select_primitive_varnode_compare_records(varnode_cmp_record_cond=lambda record: (record.get_var() is None or not record.get_var().is_param()) and record.get_compare_level() >= level)

# Extraneous primitive varnodes (in decompiler, not overlapped with ground truth)
def primitive_varnodes_extraneous(cmp: UnoptimizedProgramInfoCompare2) -> List[Varnode]:
    return primitive_varnodes_missed(cmp.flip())

# --------------- TYPE-SPECIFIC VARNODE COMPARISONS --------------------
def _varnodes_metatype(proginfo: UnoptimizedProgramInfo, metatype: int) -> List[Varnode]:
    return proginfo.select_varnodes(varnode_cond=lambda varnode: varnode.get_datatype().get_metatype() == metatype)

# Ground-truth varnodes w/ metatype
def varnodes_truth_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int) -> List[Varnode]:
    return _varnodes_metatype(cmp.get_left(), metatype)

# Decompiler varnodes w/ metatype
def varnodes_decomp_metatype(cmp: UnoptimizedProgramInfoCompare2, metatype: int) -> List[Varnode]:
    return _varnodes_metatype(cmp.get_right(), metatype)


# Recovered ARRAY varnodes (in ground-truth & in decompiler - overlapped & same metatype)
def array_comparisons(cmp: UnoptimizedProgramInfoCompare2) -> List[VarnodeCompare2]:
    return cmp.select_varnode_comparisons(varnode_cmp2_cond=lambda record: record.get_left().get_datatype().get_metatype() == MetaType.ARRAY and record.get_right().get_datatype().get_metatype() == MetaType.ARRAY)

## average length inaccuracy (elements)
def array_elements_error(cmp: VarnodeCompare2) -> int:
    return abs(cmp.get_left().get_datatype().get_num_elements() - cmp.get_right().get_datatype().get_num_elements())

## average length inaccuracy %
def array_elements_error_percentage(cmp: VarnodeCompare2) -> float:
    return 100.0 * (array_elements_error(cmp) / cmp.get_left().get_datatype().get_num_elements())

## average size inaccuracy (bytes)
def array_size_error(cmp: VarnodeCompare2) -> int:
    return abs(cmp.get_left().get_size() - cmp.get_right().get_size())

## average size inaccuracy %
def array_size_error_percentage(cmp: VarnodeCompare2) -> float:
    return 100.0 * (array_size_error(cmp) / cmp.get_left().get_size())

## subtype match % -> how many of the array comparisons had matching subtypes?
def array_subtype_match_percentage(cmps: List[VarnodeCompare2], level: int = DataTypeCompareLevel.MATCH) -> float:
    subtype_matches = 0
    for cmp in cmps:
        left_subtype = cmp.get_left().get_datatype().get_basetype()
        right_subtype = cmp.get_right().get_datatype().get_basetype()
        dtype_cmp = DataTypeCompare2(left_subtype, right_subtype, 0)
        if dtype_cmp.get_compare_level() >= level:
            subtype_matches += 1

    return 100.0 * (subtype_matches / len(cmps))
    
## correct dimension % -> how many of the array comparisons had matching number of dimensions?
def array_dimension_match_percentage(cmps: List[VarnodeCompare2]) -> float:
    dim_matches = 0
    for cmp in cmps:
        left_dims = cmp.get_left().get_datatype().num_dimensions()
        right_dims = cmp.get_right().get_datatype().num_dimensions()
        if left_dims == right_dims:
            dim_matches += 1

    return 100.0 * (dim_matches / len(cmps))

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
        varnodes_group["varnodes matched @ or above {}".format(VarnodeCompareLevel.to_string(level))] = len(varnodes_matched_at_above_level(cmp, level))
    varnodes_group["varnodes missed"] = len(varnodes_missed(cmp))
    varnodes_group["varnodes extraneous"] = len(varnodes_extraneous(cmp))
    varnodes_group["varnodes match %"] = 100.0 * (len(varnodes_matched_at_above_level(cmp, VarnodeCompareLevel.MATCH)) / _varnodes_truth)
    METRICS["VARNODES"] = varnodes_group

    primitives_group = {}
    _primitives_truth = len(primitive_varnodes_truth(cmp))
    primitives_group["primitive varnodes - ground truth"] = _primitives_truth
    primitives_group["primitive varnodes - decompiler"] = len(primitive_varnodes_decomp(cmp))
    for level in range(VarnodeCompareLevel.NO_MATCH, VarnodeCompareLevel.MATCH + 1):
        primitives_group["primitive varnodes matched @ or above {}".format(VarnodeCompareLevel.to_string(level))] = len(primitive_varnodes_matched_at_above_level(cmp, level))
    primitives_group["primitive varnodes missed"] = len(primitive_varnodes_missed(cmp))
    primitives_group["primitive varnodes extraneous"] = len(primitive_varnodes_extraneous(cmp))
    primitives_group["primitive varnodes match %"] = 100.0 * (len(primitive_varnodes_matched_at_above_level(cmp, VarnodeCompareLevel.MATCH)) / _primitives_truth)
    METRICS["PRIMITIVE VARNODES"] = primitives_group

    parameters_group = {}
    params_truth = cmp.get_left().select_varnodes(variable_cond=lambda var: var.is_param())
    parameters_group["parameter varnodes - ground truth"] = params_truth
    params_decomp = cmp.get_right().select_varnodes(variable_cond=lambda var: var.is_param())
    parameters_group["parameter varnodes - decompiler"] = params_decomp
    param_overlaps = cmp.select_varnode_compare_records(varnode_cmp_record_cond=lambda record: record.get_var() is not None and record.get_var().is_param() and record.get_compare_level() > VarnodeCompareLevel.NO_MATCH)
    parameters_group["parameter overlaps"] = param_overlaps
    METRICS["PARAMETER VARNODES"] = parameters_group

    for metatype in [MetaType.INT, MetaType.FLOAT, MetaType.POINTER, MetaType.ARRAY, MetaType.STRUCT, MetaType.UNION, MetaType.UNDEFINED]:
        metatype_group = {}
        truth = len(varnodes_truth_metatype(cmp, metatype))
        metatype_group["(metatype = {}) varnodes - ground truth".format(MetaType.repr(metatype))] = truth
        metatype_group["(metatype = {}) varnodes - decompiler".format(MetaType.repr(metatype))] = len(varnodes_decomp_metatype(cmp, metatype))
        metatype_group["(metatype = {}) varnodes missed".format(MetaType.repr(metatype))] = len([ record for record in varnodes_match_levels(cmp, [VarnodeCompareLevel.NO_MATCH]) if record.get_varnode().get_datatype().get_metatype() == metatype ])

        aligned = len([ record for record in varnodes_matched_at_above_level(cmp, VarnodeCompareLevel.ALIGNED) if record.get_varnode().get_datatype().get_metatype() == metatype ])
        metatype_group["(metatype = {}) varnodes matched @ or above ALIGNED".format(MetaType.repr(metatype))] = aligned

        matched = len([ record for record in varnodes_matched_at_above_level(cmp, VarnodeCompareLevel.MATCH) if record.get_varnode().get_datatype().get_metatype() == metatype ])
        metatype_group["(metatype = {}) varnodes matched @ MATCH".format(MetaType.repr(metatype))] = matched
        if truth > 0:
            metatype_group["(metatype = {}) varnodes match %".format(MetaType.repr(metatype))] = 100.0 * (matched / truth)
        METRICS["METATYPE SUMMARY ({})".format(MetaType.repr(metatype))] = metatype_group

    array_group = {}
    array_cmps = array_comparisons(cmp)
    array_group["array comparisons"] = len(array_cmps)
    array_group["arrays missed"] = len([ record for record in varnodes_match_levels(cmp, [VarnodeCompareLevel.NO_MATCH]) if record.get_varnode().get_datatype().get_metatype() == MetaType.ARRAY ])
    if array_cmps:
        array_group["array - avg elements error"] = mean([ array_elements_error(array_cmp) for array_cmp in array_cmps ])
        array_group["array - avg elements error %"] = mean([ array_elements_error_percentage(array_cmp) for array_cmp in array_cmps ])
        array_group["array - avg size error (bytes)"] = mean([ array_size_error(array_cmp) for array_cmp in array_cmps ])
        array_group["array - avg size error (bytes) %"] = mean([ array_size_error_percentage(array_cmp) for array_cmp in array_cmps ])
        array_group["array - subtype match %"] = array_subtype_match_percentage(array_cmps)
        array_group["array - # of dimensions match %"] = array_dimension_match_percentage(array_cmps)

    METRICS["ARRAY RECOVERY"] = array_group

    return METRICS


def display_metrics(cmp: UnoptimizedProgramInfoCompare2):
    _map = _mk_metrics(cmp)

    for grp, metric in _map.items():
        print("{} {} {}".format("-"*10, grp, "-"*10))
        for lbl, val in metric.items():
            print("{} : {}".format(lbl, val))
        print(),

        