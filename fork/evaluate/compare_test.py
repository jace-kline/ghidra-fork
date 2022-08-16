from lang import *
from lang_address import *
from lang_datatype import *
from compare import *
from util import *
from build import *

def test_make_StaticPCVariable():
    dwarf_proginfo, ghidra_proginfo = build2("../progs/typecases", 0)
    print(dwarf_proginfo)
    print(ghidra_proginfo)

if __name__ == "__main__":
    test_make_StaticPCVariable()