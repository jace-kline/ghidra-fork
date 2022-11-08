from typing import List, Any
import time
from pathlib import Path
from functools import lru_cache
from rediscache import SimpleCache, cache_it

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

class CacheObjectWrapper(object):
    def __init__(self, obj: Any):
        self.obj = obj
        self.timestamp: int = get_timestamp_ns()

    def is_up_to_date(self, deps: List[Path]) -> bool:
        return self.timestamp > 0 and all([ dep.exists() and (self.timestamp > last_modification_ns(dep) > 0) for dep in deps ])

    def get_obj(self):
        return self.obj

CACHE = SimpleCache(
    expire=0, # keys never expire
    hashkeys=True # uses hashes instead of pickled objects as keys
)

# caches function call to local Redis database
redis_cacher = cache_it(cache=CACHE)

# caches function call to local Redis database
# checks dependency paths on load to determine whether to recompute, similar to Makefile
def redis_path_dependent_cacher(paths: List[Path]):
    def recache_callback(wrapper: CacheObjectWrapper) -> bool:
        return not wrapper.is_up_to_date(paths)

    return cache_it(
        cache=CACHE,
        recache_callback=recache_callback,
        store_transform=lambda obj: CacheObjectWrapper(obj),
        load_transform=lambda wrapper: wrapper.get_obj()
    )

# a cache decorator for intra-run caching (not persisted to Redis)
cache = lru_cache(maxsize=None)
