from collections import namedtuple
from dataclasses import dataclass
from pathlib import Path, PosixPath
from secrets import token_urlsafe
from typing import Union

BuildOptions = namedtuple("BuildOptions", ("debug", "strip", "optimization"), defaults=(False, False, 0))

# mangle the build options into an appropriate binary name
def mangle(progname: str, opts: BuildOptions) -> str:
    s = "{}_O{}".format(progname, opts.optimization)
    if opts.debug:
        s += "_debug"
    if opts.strip:
        s += "_strip"
    return s

class Program(object):
    def __init__(
        self,
        name: str,
        dir: Path # path to directory where the binaries will live
    ):
        self.name = name
        self.dir = dir

    # mangle the options into the correct binary name
    def get_binary_name(self, opts: BuildOptions) -> str:
        return mangle(self.name, opts)

    # returns a Path object pointing to the path of the target binary compiled with given options
    def get_binary_path(self, opts: BuildOptions) -> Union[Path, None]:
        return self.dir.joinpath(self.get_binary_name(opts))

    # given build options, returns whether the corresponding binary exists at the expected path and is valid
    def valid_build(self, opts: BuildOptions) -> bool:
        path = self.get_binary_path(opts)
        return path is not None and path.exists() and path.is_file()

    def __hash__(self) -> int:
        return hash((self.name, self.dir))
        
    def __str__(self) -> str:
        return "<Program name={} dir={}>".format(self.name, self.dir)

    def __repr__(self) -> str:
        return self.__str__()

class CoreutilsProgram(Program):
    COREUTILS_SRC_PATH: PosixPath = Path("/home/jacekline/dev/research/programs/coreutils-9.1/src/").resolve()

    def __init__(
        self,
        name: str
    ):
        super(__class__, self).__init__(name, __class__.COREUTILS_SRC_PATH)

class ToyProgram(Program):
    TOY_PROGS_PATH: PosixPath = Path("../progs/").resolve()

    def __init__(
        self,
        name: str
    ):
        super(__class__, self).__init__(name, __class__.TOY_PROGS_PATH.joinpath(name))

    # mangle the options into the correct binary name
    def get_binary_name(self, opts: BuildOptions) -> str:
        return mangle(self.name, opts) + ".bin"
