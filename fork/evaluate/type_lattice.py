from enum import Enum, auto, unique
from typing import List, Union
# from util import *

# The interface to implement if you want to be the "item type" that is stored within a lattice
# Each item must know how to construct its parent and its children
class LatticeItemType(object):
    def parent(self) -> Union['LatticeItemType', None]:
        pass

    def children(self) -> List['LatticeItemType']:
        pass

    def __eq__(self) -> bool:
        pass

# Wraps the LatticeItemType object and exposes higher-level methods for traversal, etc.
class LatticeNode(object):
    def __init__(
        self,
        item: LatticeItemType
    ):
        self.item = item

    def get_item(self) -> LatticeItemType:
        return self.item

    def parent(self) -> Union['LatticeNode', None]:
        return LatticeNode(self.item.parent()) if not self.is_root() else None

    def children(self) -> List['LatticeNode']:
        return [ LatticeNode(item) for item in self.item.children() ]
    
    def is_root(self) -> bool:
        return self.item.parent() is None

    def is_leaf(self) -> bool:
        return not self.item.children()

    def is_inner(self) -> bool:
        return not self.is_root() and not self.is_inner()

    def height(self) -> int:
        return 0 if self.is_leaf() else 1 + max([ child.height() for child in self.children() ])

    def depth(self) -> int:
        return 0 if self.is_root() else 1 + self.parent().depth()

    def path_from_root(self) -> List['LatticeNode']:
        return [self] if self.is_root() else self.parent().path_from_root() + [self]

    def path_to_root(self) -> List['LatticeNode']:
        return reversed(self.path_from_root())

    def path_between(self, other: 'LatticeNode') -> List['LatticeNode']:
        # try traversing upwards toward root, then reverse the path
        # try iterating children
        pass

    def common_parent(self, other: 'LatticeNode') -> 'LatticeNode':
        for node in self.path_to_root():
            for othernode in other.path_to_root():
                if node == othernode:
                    return node
        return None

    def __eq__(self, other: 'LatticeNode') -> bool:
        return self.item == other.item

    def __str__(self) -> str:
        return "<LatticeNode {}>".format(self.item)

    def __repr__(self) -> str:
        return self.__str__()

# Implements the LatticeItemType interface
@unique
class TIE_NodeType(Enum):
    ROOT = auto()
    CODE = auto()
    DATA = auto()
    FLOAT = auto()
    NUM = auto()
    PTR = auto()
    INT = auto()
    UINT = auto()

    @staticmethod
    def _children_map() -> 'dict[TIE_NodeType, List[TIE_NodeType]]':
        _cls = TIE_NodeType
        return {
            _cls.ROOT: [_cls.CODE, _cls.DATA],
            _cls.DATA: [_cls.FLOAT, _cls.NUM],
            _cls.NUM: [_cls.PTR, _cls.INT, _cls.UINT]
        }

    @staticmethod
    def _parent_map() -> 'dict[TIE_NodeType, Union[TIE_NodeType, None]]':
        _map = {}
        for k, vs in TIE_NodeType._children_map().items():
            for v in vs:
                _map[v] = k
        return _map


    def parent(self) -> Union['TIE_NodeType', None]:
        return self._parent_map().get(self, None)

    def children(self) -> List['TIE_NodeType']:
        return self._children_map().get(self, [])


# Implements the LatticeItemType interface
class TIE_LatticeItem(object):

    VALID_BIT_SIZES = [1, 8, 16, 32, 64, 80]

    def __init__(self,
        nodetype: TIE_NodeType, # also implements the LatticeItemType interface
        bits: Union[int, None] = None # the number of bits this primitive type is
    ):
        self.nodetype = nodetype
        self.bits = bits # number of bits

    def parent(self) -> Union['TIE_LatticeItem', None]:
        # if we are "sized" data, our parent is unsized data
        if self.nodetype == TIE_NodeType.DATA and self.bits is not None:
            return __class__(TIE_NodeType.DATA, bits=None)

        # if we are "sized" code, our parent is unsized code
        elif self.nodetype == TIE_NodeType.CODE and self.bits is not None:
            return __class__(TIE_NodeType.CODE, bits=None)

        # otherwise, the structure follows the TIE_NodeType structure with the bits the same
        else:
            nodetype_parent = self.nodetype.parent()
            return __class__(nodetype_parent, bits=self.bits) if nodetype_parent is not None else None

    def children(self) -> List['TIE_LatticeItem']:
        if self.nodetype == TIE_NodeType.DATA:
            if self.bits is None:
                return [ __class__(TIE_NodeType.DATA, bits=bits) for bits in TIE_LatticeItem.VALID_BIT_SIZES ]
            elif self.bits == 1:
                return []
            elif self.bits == 80:
                return [ __class__(TIE_NodeType.FLOAT, bits=self.bits) ]
        
        return [ __class__(nodetype, size=self.bits) for nodetype in self.nodetype.children() ]

    def __eq__(self, other: 'TIE_LatticeItem') -> bool:
        return self.nodetype == other.nodetype and self.bits == other.bits

    def __str__(self) -> str:
        return "<TIE_LatticeItem nodetype={} bits={}>".format(self.nodetype, self.bits)

    def __repr__(self) -> str:
        return self.__str__()


if __name__ == "__main__":
    float80 = LatticeNode(TIE_LatticeItem(TIE_NodeType.FLOAT, bits=80))
    uint16 = LatticeNode(TIE_LatticeItem(TIE_NodeType.UINT, bits=16))

    print(float80.common_parent(uint16))

