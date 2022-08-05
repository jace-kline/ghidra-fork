
# An Iterator class that "zips" 2 ordered iterators together
# Produces and ordered iterator of 'Left', 'Right', and 'Conflict' objects
class OrderedZipper(object):

    class ZipItem(object):
        def __init__(self):
            pass

        def get_value(self):
            raise NotImplementedError()
        
        def is_left(self):
            return False
        
        def is_right(self):
            return False

        def is_conflict(self):
            return False

    class Left(ZipItem):
        def __init__(self, obj):
            super(__class__, self).__init__()
            self.obj = obj

        def get_value(self):
            return self.obj

        def is_left(self):
            return True

        def __str__(self):
            return "<Left({})>".format(self.obj)

        def __repr__(self):
            return self.__str__()

    class Right(ZipItem):
        def __init__(self, obj):
            super(__class__, self).__init__()
            self.obj = obj

        def get_value(self):
            return self.obj

        def is_right(self):
            return True

        def __str__(self):
            return "<Right({})>".format(self.obj)

        def __repr__(self):
            return self.__str__()

    class Conflict(object):
        def __init__(self, objl, objr):
            super(__class__, self).__init__()
            self.objl = objl
            self.objr = objr

        def get_value(self):
            return (self.objl, self.objr)

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
        self.left = iter(left)
        self.right = iter(right)
        self.key = key if key is not None else (lambda v: v)

        # get the first elements of each iterator
        self.curleft = self._next(self.left)
        self.curright = self._next(self.right)

    # intercept StopIteration from the vanilla next() method and return None instead
    def _next(self, _iter):
        try:
            return next(_iter)
        except StopIteration:
            return None

    def _exhausted_left(self):
        return self.curleft == None

    def _exhausted_right(self):
        return self.curright == None

    def __next__(self):
        if self._exhausted_left():
            self.curright = next(self.right)
            return OrderedZipper.Right(self.curright)

        elif self._exhausted_right():
            self.curleft = next(self.left)
            return OrderedZipper.Left(self.curleft)

        elif self.key(self.curleft) == self.key(self.curright):
            ret = OrderedZipper.Conflict(self.curleft, self.curright)
            self.curleft = self._next(self.left)
            self.curright = self._next(self.right)
            return ret

        elif self.key(self.curleft) < self.key(self.curright):
            ret = OrderedZipper.Left(self.curleft)
            self.curleft = self._next(self.left)
            return ret

        elif self.key(self.curleft) > self.key(self.curright):
            ret = OrderedZipper.Right(self.curright)
            self.curright = self._next(self.right)
            return ret

        else:
            raise StopIteration

    def __iter__(self):
        return self