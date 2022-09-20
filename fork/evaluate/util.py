from collections import OrderedDict
from typing import Any, Iterator, List, Union

# _map: the original unordered dict
# transform: the transformation to apply to the key before ordering
def ordered_dict_by_key(_map: dict, transform=lambda x: x) -> OrderedDict:
    return OrderedDict(sorted(_map.items(), key=lambda pair: transform(pair[0])))

def indent_str(s: str, indent: int) -> str:
    if indent <= 0:
        return s
    
    lines = s.splitlines()
    return "".join(["{}{}\n".format("\t" * indent, _s) for _s in lines])

def count(_iter, start=0, step=1):
    __iter = iter(_iter)
    cnt = start
    while try_next(__iter) is not None:
        cnt += step
    return cnt

# intercept StopIteration from the vanilla next() method and return None instead
def try_next(_iter):
    try:
        return next(_iter)
    except StopIteration:
        return None

# An Iterator class that "zips" 2 ordered iterators together
# Produces and ordered iterator of 'Left', 'Right', and 'Conflict' objects
class OrderedZipper(object):

    class ZipItem(object):
        def __init__(self):
            pass

        # get the value(s)
        # () -> A | (A, A), where A the type of the obj being stored
        def get_value(self):
            raise NotImplementedError()

        # get the index(es) of this item from the original input iterator(s)
        # () -> int | (int, int)
        def get_idx(self):
            raise NotImplementedError()
        
        def is_left(self):
            return False
        
        def is_right(self):
            return False

        def is_conflict(self):
            return False

    class Left(ZipItem):
        def __init__(self, obj, idx):
            super(__class__, self).__init__()
            self.obj = obj
            self.idx = idx

        def get_value(self):
            return self.obj

        def get_idx(self):
            return self.idx

        def is_left(self):
            return True

        def __str__(self):
            return "<Left({})>".format(self.obj)

        def __repr__(self):
            return self.__str__()

    class Right(ZipItem):
        def __init__(self, obj, idx):
            super(__class__, self).__init__()
            self.obj = obj
            self.idx = idx

        def get_value(self):
            return self.obj

        def get_idx(self):
            return self.idx

        def is_right(self):
            return True

        def __str__(self):
            return "<Right({})>".format(self.obj)

        def __repr__(self):
            return self.__str__()

    class Conflict(ZipItem):
        def __init__(self, objl, idxl, objr, idxr):
            super(__class__, self).__init__()
            self.objl = objl
            self.idxl = idxl
            self.objr = objr
            self.idxr = idxr

        def get_value(self):
            return (self.objl, self.objr)

        def get_idx(self):
            return (self.idxl, self.idxr)

        def is_conflict(self):
            return True

        def __str__(self):
            return "<Conflict({},{})>".format(self.objl, self.objr)

        def __repr__(self):
            return self.__str__()

    # left: Iterator<A>
    # right: Iterator<A>
    # key: (Ord B) => A -> B
    def __init__(self, left, right, key=None):
        self.key = key if key is not None else (lambda v: v)
        self.left = iter(sorted(left, key=self.key))
        self.right = iter(sorted(right, key=self.key))

        # get the first elements of each iterator
        self.curleft = try_next(self.left)
        self.curright = try_next(self.right)

        # keep track of the current index of each of the iterators
        self.left_idx = 0
        self.right_idx = 0

    def _exhausted_left(self):
        return self.curleft == None

    def _exhausted_right(self):
        return self.curright == None

    def __next__(self):
        if self._exhausted_left():
            self.curright = next(self.right)
            self.right_idx += 1
            return OrderedZipper.Right(self.curright, self.right_idx)

        elif self._exhausted_right():
            self.curleft = next(self.left)
            self.left_idx += 1
            return OrderedZipper.Left(self.curleft, self.left_idx)

        elif self.key(self.curleft) == self.key(self.curright):
            ret = OrderedZipper.Conflict(self.curleft, self.left_idx, self.curright, self.right_idx)
            self.curleft = try_next(self.left)
            self.left_idx += 1
            self.curright = try_next(self.right)
            self.right_idx += 1
            return ret

        elif self.key(self.curleft) < self.key(self.curright):
            ret = OrderedZipper.Left(self.curleft, self.left_idx)
            self.curleft = try_next(self.left)
            self.left_idx += 1
            return ret

        elif self.key(self.curleft) > self.key(self.curright):
            ret = OrderedZipper.Right(self.curright, self.right_idx)
            self.curright = try_next(self.right)
            self.right_idx += 1
            return ret

        else:
            raise StopIteration

    def __iter__(self):
        return self

class Tree(object):

    class Node(object):
        def __init__(self,
            item: Any,
            parent: 'Union[Tree.Node, None]' = None,
            children: 'List[Tree.Node]' = []
        ):
            self.item = item
            self.parent = parent
            self.children = children

            for child in self.children:
                child.set_parent(self)

        def get_item(self) -> Any:
            return self.item

        def get_parent(self) -> 'Union[Tree.Node, None]':
            return self.parent

        def get_children(self) -> 'List[Tree.Node]':
            return self.children

        def set_parent(self, parent: 'Tree.Node') -> 'Tree.Node':
            self.parent = parent
            return self

        def add_child(self, child: 'Tree.Node') -> 'Tree.Node':
            self.children.append(child)
            child.set_parent(self)
            return self

        def is_root(self) -> bool:
            return self.parent is None

        def is_leaf(self) -> bool:
            return not self.children

        def is_inner(self) -> bool:
            return not self.is_root() and not self.is_leaf()

        def height(self, min_height: bool = False) -> int:
            return 0 if self.is_leaf() else 1 + (max if not min_height else min)([child.height(min_height=min_height) for child in self.children])

        def depth(self) -> int:
            return 0 if self.is_root() else 1 + self.parent.depth()

        def path_from_root(self) -> List['Tree.Node']:
            path = [] if self.is_root() else self.parent.path_from_root()
            path.append(self)
            return path

        # finds the most immediate common root of this node and another
        # if not in same tree, return None
        def common_root(self, other: 'Tree.Node') -> Union['Tree.Node', None]:
            for l in reversed(self.path_from_root()):
                for r in reversed(other.path_from_root()):
                    if l is r:
                        return l
            return None

        # recursively search for the first node containing the given item which matches a condition
        # self.item: A
        # condition: A -> bool
        def find_first(self, condition) -> Union['Tree.Node', None]:
            for node in iter(self):
                if condition(node.item):
                    return node

        # preorder traversal
        def __iter__(self) -> Iterator['Tree.Node']:
            traverse = [self]
            for child in self.children:
                traverse += list(iter(child))
            return iter(traverse)

        def __str__(self) -> str:
            def _status_str() -> str:
                if self.is_leaf():
                    return "LEAF"
                elif self.is_root():
                    return "ROOT"
                else:
                    return "INNER"
            return "<Tree.Node {} item={} id={} parent_id={} children={}>".format(
                _status_str(),
                self.item,
                id(self),
                None if self.is_root() else id(self.parent),
                len(self.children)
            )

        def __repr__(self):
            return self.__str__()


    def __init__(self, root: 'Union[Tree.Node, None]'):
        self.root = root

    def is_empty(self) -> bool:
        return self.root is None

    def get_root(self) -> 'Union[Tree.Node, None]':
        return None

    def set_root(self, root: 'Tree.Node'):
        self.root = root

    def height(self, min_height: bool = False) -> int:
        return -1 if self.is_empty() else self.root.height(min_height=min_height)

    def __iter__(self) -> Iterator['Tree.Node']:
        return iter([]) if self.is_empty() else iter(self.root)

    def __str__(self) -> str:
        return "<Tree root_id={}>".format(
            None if self.is_empty() else id(self.root)
        )

    def __repr__(self) -> str:
        return self.__str__()