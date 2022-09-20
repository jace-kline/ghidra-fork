from build import build_dwarf
from type_lattice import *

def ariste1():
    float80 = LatticeNode(Ariste_LatticeItem(Ariste_NodeType.FLOAT, bits=80))
    uint16 = LatticeNode(Ariste_LatticeItem(Ariste_NodeType.UINT, bits=16))

    print(float80.common_ancestor_paths(uint16))

def ariste2():
    dtype_uint4 = DataTypeInt(size=4, signed=False)
    
    node = LatticeNode.from_datatype(Ariste_LatticeItem, dtype_uint4)
    print(node)

if __name__ == "__main__":
    ariste2()