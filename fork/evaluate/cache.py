# from functools import wraps
import time
from functools import wraps
from rediscache import SimpleCache, cache_it
from build_parse import *

# SimpleCache(
#     limit=10000,
#     expire=DEFAULT_EXPIRY, # = 60 * 60 * 24
#     hashkeys=False,
#     host="localhost",
#     port=6379,
#     db=0,
#     password=None,
#     namespace="SimpleCache"
# )

# get the current system timestamp in nanoseconds
def get_timestamp_ns() -> int:
    nano = 10 ** 9
    return round(time.time() * nano)

# get a path (file) modification time in nanoseconds
def last_modification_ns(p: Path) -> int:
        res = p.stat().st_mtime_ns
        return res if res else -1

# Does the target path exist & is it newer than the modification dates of all deps?
def up_to_date(path: Path, deps: List[Path]) -> bool:

    if not path.exists():
        return False

    target_mtime_ns = last_modification_ns(path)
    return target_mtime_ns > 0 and all([ target_mtime_ns > last_modification_ns(dep) > 0 for dep in deps ])

class CacheObjectWrapper(object):
    def __init__(self, obj: Any):
        self.obj = obj
        self.timestamp: int = get_timestamp_ns()

    def is_up_to_date(self, deps: List[Path]) -> bool:
        return all([ up_to_date(p) for p in deps ])

    def get_obj(self):
        return self.obj

CACHE = SimpleCache(
    expire=0, # keys never expire
    hashkeys=True # uses hashes instead of pickled objects as keys
)

# def path_dependent_cacher(paths: List[Path]):
#     def recache_callback(wrapper: CacheObjectWrapper) -> bool:
#         return not wrapper.is_up_to_date(paths)

#     return cache_it(cache=CACHE, recache_callback=recache_callback)

# def path_dependency_injector(paths: List[Path]) -> Callable:

#     def decorator(fn) -> Callable:
#         # recompute on every run of the decorator
#         path_mod_times = tuple([ last_modification_ns(dep) for dep in paths ])

#         @wraps(fn)
#         def with_modtime_args(
#             *args, # ordered args of original function
#             _path_mod_times: Tuple[int] = path_mod_times, # custom kwarg that we inject
#             **kwargs # rest of kwargs of original function
#         ):
#             return fn(*args, **kwargs)

#         return with_modtime_args

#     return decorator

# def path_dependency_cacher(paths: List[Path]) -> Callable:
#     return cacher(path_dependency_injector(paths))

# # wrapper decorator function around Redis cacher decorator
# # checks the modification status of the path_deps list
# # if any dependency paths have been modified (newer than stored object),
# # then recompute & recache
# def path_dependent_cacher(fn: Callable, path_deps: List[Path]) -> Callable:

#     path_mod_times = tuple([ last_modification_ns(dep) for dep in path_deps ])

#     # make the path_deps modification times an argument so that cache_it will recache
#     # if a modification time has changed
#     @wraps(fn)
#     def path_dependent_func(
#         path_mod_times: Tuple[int] = path_mod_times,
#         *args, **kwargs
#     ):
#         return fn(*args, **kwargs)

#     return cacher(path_dependent_func)

# dwarf_parser_deps = LANG_DEPS + [ CODEDIR.joinpath(p) for p in ["parse_dwarf.py", "parse_dwarf_util.py"] ]
# parse_dwarf_cacher = path_dependency_cacher(dwarf_parser_deps)(parse_dwarf_proginfo)

# ghidra_parser_deps = LANG_DEPS + [ CODEDIR.joinpath(p) for p in ["parse_ghidra.py", "parse_ghidra_util.py"] ]
# parse_ghidra_cacher = path_dependency_cacher(ghidra_parser_deps)(parse_ghidra_proginfo)

# prognames = [ "ndarray", "typecases", "p0", "structcases" ]
# progs = [ ToyProgram(progname) for progname in prognames ]
# opts = BuildOptions()
# dwarf_opts = BuildOptions(debug=True, strip=False, optimization=opts.optimization)

# for prog in progs:
#     prog.build_if_not_valid(opts)
#     prog.build_if_not_valid(dwarf_opts)

# dwarf_binpaths = [ prog.get_binary_path(dwarf_opts) for prog in progs ]
# ghidra_binpaths = [ prog.get_binary_path(opts) for prog in progs ]


# for prog in progs:
#     dwarf = parse_dwarf_cacher(prog.get_binary_path(dwarf_opts))
#     ghidra = parse_ghidra_cacher(prog.get_binary_path(opts))
#     print(dwarf)
#     print(ghidra)