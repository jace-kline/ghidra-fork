import pickle
from translation import *

# str -> ProgramInfo
def load_proginfo(picklepath):
    infile = open(picklepath, 'rb')
    proginfo = pickle.load(infile)
    infile.close()
    return proginfo

def test():
    picklepath_dwarf = "../progs/typecases_splitobjs/typecases_splitobjs_O0_debug.dwarf.pickle"
    picklepath_ghidra = "../progs/typecases_splitobjs/typecases_splitobjs_O0.ghidra.pickle"
    proginfo = load_proginfo(picklepath_ghidra)
    proginfo.print_summary()

if __name__ == "__main__":
    test()
