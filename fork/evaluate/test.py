from resolve import *
from resolve_stubs import *
from parse_dwarf_util import *
from parse_dwarf import *
from util import *

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

def test_set():
    xs = [5,4,3,2,1]

class A(object):
    class Nested(object):
        FIELD0 = 0
        FIELD1 = 1
        FIELD2 = 2

        @staticmethod
        def to_string(code):
            _cls = A.Nested
            _map = {
                _cls.FIELD0: "FIELD0",
                _cls.FIELD1: "FIELD1",
                _cls.FIELD2: "FIELD2"
            }
            return _map[code]

def test_nested():
    print(A.Nested.to_string(A.Nested.FIELD0))

def test_tree():
    root = Tree.Node(0, children=[
        Tree.Node(1, children=[
            Tree.Node(2)
        ]),
        Tree.Node(3, children=[
            Tree.Node(4)
        ]),
        Tree.Node(5, children=[
            Tree.Node(6, children=[
                Tree.Node(7)
            ]),
            Tree.Node(8)
        ])
    ])
    
    tree = Tree(root=root)
    print("Height: {}".format(tree.height()))
    leaf = tree.root.children[2].children[0].children[0]
    other = tree.root.children[0]
    assert(leaf.common_root(other) is root)

    other = tree.root.children[2].children[1]
    assert(leaf.common_root(other) is tree.root.children[2])

class Filter(object):
    def __init__(self):
        # store (attr name, attr val, method) when attr matches method name
        self.triples = self._build_triples()

    def _build_triples(self):
        triples = []
        instance_dict = self.__dict__
        class_dict = self.__class__.__dict__
        for attr, val in instance_dict.items():
            if attr in class_dict:
                triples.append((attr, val, class_dict[attr]))
        return triples

    def __call__(self, obj) -> bool:
        return all(( (True if val is None else fn(self, obj)) for _, val, fn in self.triples ))

class FilterDataType(Filter):
    filter_cls: type = DataType

    def __init__(
        self,
        primitive = None, # bool|None
        complex = None, # bool|None
        sized = None, # bool|None
        metatype = None, # int|None
        size_range = None, # (min: int, max: int)|None
        composition_level = None # int|None
    ):
        self.primitive = primitive
        self.complex = complex
        self.sized = sized
        self.metatype = metatype
        self.size_range = size_range
        self.composition_level = composition_level
        super(FilterDataType, self).__init__()

    def primitive(self, dtype: DataType) -> bool:
        return self.primitive == dtype.is_primitive()

    def complex(self, dtype: DataType) -> bool:
        return self.complex == dtype.is_complex()

    def sized(self, dtype: DataType) -> bool:
        return self.sized == dtype.get_size() is not None and dtype.get_size() > 0

    def metatype(self, dtype: DataType) -> bool:
        return self.metatype == dtype.get_metatype()

    def size_range(self, dtype: DataType) -> bool:
        _min, _max = self.size_range
        return dtype.get_size() >= _min and dtype.get_size() <= _max

    def composition_level(self, dtype: DataType) -> bool:
        return dtype.composition_level() == self.composition_level

def test_class_attr_access():
    dtype_filter: FilterDataType = FilterDataType(
        primitive=False
    )
    # print(dtype_filter.__dict__)
    # print(dtype_filter.__class__.__dict__)

    obj = DataTypeInt(size=4)
    print(dtype_filter(obj))

if __name__ == "__main__":
    test_class_attr_access()