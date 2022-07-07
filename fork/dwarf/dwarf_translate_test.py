import sys
from dwarf_translate import translate

def test(objfilepath):
    trans = translate(objfilepath)

    print("----------------GLOBALS----------------------")
    for gbl in trans.globals:
        print("{} @ {:x}".format(gbl.name, gbl.addr.offset))


    print("----------------FUNCTIONS--------------------")
    for fn in trans.functions:
        print("{} @ {:x}".format(fn.name, fn.startaddr.offset))
        for var in (fn.params + fn.vars):
            print("\t{} -- {} @ RBP+({:x})".format(var.dtype, var.name, var.addr.offset))

def main():
    defaultobj = "../progs/typecases_debug_O0.bin"
    objfilepath = sys.argv[1] if len(sys.argv) >= 2 else defaultobj
    test(objfilepath)

if __name__ == "__main__":
    main()