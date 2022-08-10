from resolve import *
from resolve_stubs import *
from parse_dwarf_util import *
from parse_dwarf import *
from util import OrderedZipper

def modify(record):
    record.obj = "Hello World"

def test():
    s0 = DataTypeStructStub(
            name="mystruct",
            membertyperefs=[1,2],
            size=None
        )

    s1 = DataTypeIntStub(
        size=4,
        signed=False
    )

    s2 = DataTypePointerStub(
        basetyperef=0, # recursive pointer
        size=8
    )

    db = ResolverDatabase()
    db.make_record(0, s0)
    db.make_record(1, s1)
    db.make_record(2, s2)

    dtype = db.resolve(0)
    for i in range(0, 3):
        print(db.lookup(i).obj)
        print(db.lookup(i).tag)

    assert(db.lookup(0).obj == db.lookup(2).obj.basetype)

    dtype = db.resolve(0)
    for i in range(0, 3):
        print(db.lookup(i).obj)
        print(db.lookup(i).tag)

    # print(db.lookup(1).obj)
    # modify(db.lookup(1))
    # print(db.lookup(1).obj)

def print_die_attrs():
    _, dwarfinfo = get_elf_dwarf_info("../progs/typecases_debug_O0.bin")
    diemap = dict([ (die.offset, die) for die in get_all_DIEs(dwarfinfo) ])
    print(len(diemap))

    globaldies = get_global_var_DIEs(dwarfinfo)
    globalrefs = [ die.offset for die in globaldies ]
    functiondies = get_function_DIEs(dwarfinfo)
    functionrefs = [ die.offset for die in functiondies ]
    print(globalrefs)
    print(functionrefs)

def test_parse_dwarf():
    proginfo = parse_from_objfile("../progs/typecases_debug_O0.bin")
    proginfo.print_summary()

def test_addr_parse():
    _, dwarfinfo = get_elf_dwarf_info("../progs/typecases_debug_O0.bin")
    fndies = get_function_DIEs(dwarfinfo)
    for fndie in fndies:
        pass

def test_key_type():
    mydict = {
        (1, 2): "hello",
        (2, 3): "world"
    }

    print(mydict[(1, 2)])

def test_genexp():
    def mygenexpfn():
        return (x ** 2 for x in range(10))

    for x in mygenexpfn():
        print(x)

def test_iter():
    ls = iter([1,2,3,4,5])
    print(next(ls))
    print(next(ls))
    print(next(ls))
    print(next(ls))
    print(next(ls))
    print(next(ls))

def test_iter2():
    def _next(_iter):
        try:
            return next(_iter)
        except StopIteration:
            return None

    ls = iter([1,2,3,4,5])
    print(_next(ls))
    print(_next(ls))
    for l in ls:
        print(l)

def test_ordered_zipper():
    l1 = range(0,10,1)
    l2 = range(0,20,2)
    for res in OrderedZipper(l1, l2):
        print("{}, idx={}".format(res, res.get_idx()))

    for res in OrderedZipper(l2, l1):
        print("{}, idx={}".format(res, res.get_idx()))

def test_count():
    l1 = range(0,10,1)
    print(count(l1))

def test_set():
    xs = [5,4,3,2,1]

if __name__ == "__main__":
    test_count()