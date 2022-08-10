
class AddressType:
    ABSOLUTE = 0
    REGISTER = 1
    REGISTER_OFFSET = 2
    STACK = 3
    EXTERNAL = 4
    UNKNOWN = 5

    @staticmethod
    def to_string(addrtype):
        if addrtype == AddressType.ABSOLUTE:
            return "ABSOLUTE"
        elif addrtype == AddressType.REGISTER:
            return "REGISTER"
        elif addrtype == AddressType.REGISTER_OFFSET:
            return "REGISTER_OFFSET"
        elif addrtype == AddressType.STACK:
            return "STACK"
        elif addrtype == AddressType.UNKNOWN:
            return "UNKNOWN"
        elif addrtype == AddressType.EXTERNAL:
            return "EXTERNAL"
        else:
            raise Exception("Invalid AddressType specifier {}".format(addrtype))

    # Can an address range be constructed from this address type?
    # returns bool
    @staticmethod
    def rangeable(addrtype):
        return addrtype in [ AddressType.ABSOLUTE, AddressType.REGISTER_OFFSET, AddressType.STACK ]

    @staticmethod
    def single_location(addrtype):
        return addrtype in [ AddressType.REGISTER ]

    @staticmethod
    def unknown_location(addrtype):
        return addrtype in [ AddressType.UNKNOWN, AddressType.EXTERNAL ]

class Address(object):
    def __init__(self, addrtype):
        self.addrtype = addrtype

    # a method that returns this Address's offset from
    # the base pointer of its "address space"
    def space_offset(self):
        return 0

    def rangeable(self):
        return AddressType.rangeable(self.addrtype)

    def add_const(self, n):
        raise Exception("Cannot add const to Address type '{}'".format(AddressType.to_string(self.addrtype)))

    def add_addr(self, addr):
        raise Exception("Cannot add Addresses of type '{}'".format(AddressType.to_string(self.addrtype)))

    # Computes the distance from self to addr in a given address space.
    # Negative result if addr comes before self.
    def distance(self, addr):
        raise Exception("Cannot compute distance between addresses of types '{}' and '{}'.".format(AddressType.to_string(self.addrtype), AddressType.to_string(addr.addrtype)))

    def __lt__(self, addr):
        raise Exception("Cannot use comparison operation between addresses of types '{}' and '{}'.".format(AddressType.to_string(self.addrtype), AddressType.to_string(addr.addrtype)))

    def __le__(self, addr):
        raise Exception("Cannot use comparison operation between addresses of types '{}' and '{}'.".format(AddressType.to_string(self.addrtype), AddressType.to_string(addr.addrtype)))

    def __gt__(self, addr):
        raise Exception("Cannot use comparison operation between addresses of types '{}' and '{}'.".format(AddressType.to_string(self.addrtype), AddressType.to_string(addr.addrtype)))

    def __ge__(self, addr):
        raise Exception("Cannot use comparison operation between addresses of types '{}' and '{}'.".format(AddressType.to_string(self.addrtype), AddressType.to_string(addr.addrtype)))

    # by default, use object comparison equality
    def __eq__(self, addr):
        return super(__class__, self).__eq__(addr)

    def __str__(self):
        return "<{}>".format(AddressType.to_string(self.addrtype))

class AbsoluteAddress(Address):
    def __init__(self, addr):
        super(AbsoluteAddress, self).__init__(addrtype=AddressType.ABSOLUTE)
        self.addr = addr

    def space_offset(self):
        return self.addr

    def add_const(self, n):
        return AbsoluteAddress(self.addr + n)

    def add_addr(self, other):
        return AbsoluteAddress(self.addr + other.addr)

    def distance(self, addr):
        return addr.addr - self.addr

    def __lt__(self, addr):
        return self.addr < addr.addr

    def __le__(self, addr):
        return self.addr <= addr.addr

    def __gt__(self, addr):
        return self.addr > addr.addr

    def __ge__(self, addr):
        return self.addr >= addr.addr

    def __eq__(self, addr):
        return self.addr == addr.addr

    def __str__(self):
        return "<{}:{:#x}>".format(AddressType.to_string(self.addrtype), self.addr)

class RegisterAddress(Address):
    def __init__(self, register):
        super(RegisterAddress, self).__init__(addrtype=AddressType.REGISTER)
        self.register = register

    def __eq__(self, addr):
        return self.register == addr.register

    def __str__(self):
        return "<{}:{}>".format(AddressType.to_string(self.addrtype), self.register)

class RegisterOffsetAddress(Address):
    def __init__(self, register, offset):
        super(RegisterOffsetAddress, self).__init__(addrtype=AddressType.REGISTER_OFFSET)
        self.register = register
        self.offset = offset

    def space_offset(self):
        return self.offset

    def add_const(self, n):
        return RegisterOffsetAddress(self.register, self.offset + n)

    def distance(self, addr):
        return addr.offset - self.offset

    def __lt__(self, addr):
        return self.offset < addr.offset

    def __le__(self, addr):
        return self.offset <= addr.offset

    def __gt__(self, addr):
        return self.offset > addr.offset

    def __ge__(self, addr):
        return self.offset >= addr.offset

    def __eq__(self, addr):
        return self.register == addr.register and self.offset == addr.offset

    def __str__(self):
        negative = self.offset < 0
        opstr = "-" if negative else "+"
        offsetstr = -1 * self.offset if negative else self.offset
        return "<{}:reg({}){}{:#x}>".format(AddressType.to_string(self.addrtype), self.register, opstr, offsetstr)

# offset from a stack frame's base pointer
class StackAddress(Address):
    def __init__(self, offset):
        super(StackAddress, self).__init__(addrtype=AddressType.STACK)
        self.offset = offset

    def space_offset(self):
        return self.offset

    def add_const(self, n):
        return StackAddress(self.offset + n)

    def distance(self, addr):
        return addr.offset - self.offset

    def __lt__(self, addr):
        return self.offset < addr.offset

    def __le__(self, addr):
        return self.offset <= addr.offset

    def __gt__(self, addr):
        return self.offset > addr.offset

    def __ge__(self, addr):
        return self.offset >= addr.offset

    def __eq__(self, addr):
        return self.offset == addr.offset

    def __str__(self):
        return "<{}:{:#x}>".format(AddressType.to_string(self.addrtype), self.offset)

class ExternalAddress(Address):
    def __init__(self):
        super(ExternalAddress, self).__init__(addrtype=AddressType.EXTERNAL)

class UnknownAddress(Address):
    def __init__(self):
        super(UnknownAddress, self).__init__(addrtype=AddressType.UNKNOWN)


# Range includes start, excludes end.
# start < end
# start and end addresses must be of the same AddressType.
class AddressRange(object):
    # start: Address
    # end: Address | None
    # size: int | None
    # provide either end or size
    def __init__(self, start, end=None, size=None):
        self.start = start
        self.addrtype = self.start.addrtype
        assert(AddressType.rangeable(self.addrtype))
        if end:
            assert(end.addrtype == self.start.addrtype)
            assert(start < end)
            self.end = end
            self.size = self.start.distance(self.end)
        elif size:
            assert(size >= 0)
            self.size = size
            self.end = start.add_const(size)
        else:
            raise Exception("Must provide 'end' or 'size' attribute to construct AddressRange.")

    def does_overlap(self, other):
        overlap = self.get_overlap(other)
        return overlap.overlap is not None

    def get_size(self):
        return self.size

    # other: AddressRange
    # (AddressRange, AddressRange) -> AddressRangeOverlap
    def get_overlap(self, other):
        return AddressRangeOverlap(self, other)

    # does the given Address object fall within this AddressRange?
    def contains(self, addr):
        return addr.addrtype == self.addrtype and self.start <= addr < self.end

    # comparison operators based on where the start of the range lines up
    def __lt__(self, rng):
        return self.start < rng.start

    def __le__(self, rng):
        return self.start <= rng.start

    def __gt__(self, rng):
        return self.start > rng.start

    def __ge__(self, rng):
        return self.start >= rng.start

    def __eq__(self, other):
        return self.start == other.start and self.end == other.end and self.size == other.size

    def __str__(self):
        return "<AddressRange ({},{})>".format(self.start, self.end)

    def __repr__(self):
        return self.__str__()

class AddressLiveRange(object):
    """
    This class represents the association between an Address (stack location, register, etc.)
    and the PC range that it is considered "alive" for a particular variable.
    In unoptimized code, the live range of a local variable should span the entire function
    since it will be placed on the stack.

    addr: Address
        The address where the variable is stored.
    startpc: Address
        The start PC address of the live range.
    endpc: Address
        The address of the PC of the last instruction in the live range.

    """
    def __init__(self, addr=None, startpc=None, endpc=None):
        self.addr = addr
        self.startpc = startpc
        self.endpc = endpc
        self.pc_range = None

    # if startpc & endpc are both None, this range is considered global
    def is_global(self):
        return self.startpc.offset is None and self.endpc.offset is None

    def get_pc_range(self):
        if not self.pc_range:
            self.pc_range = AddressRange(self.startpc, self.endpc)
        return self.pc_range

    # comparison operators based on where the PC AddressRange starts line up
    def __lt__(self, other):
        self.get_pc_range() < other.get_pc_range()

    def __le__(self, other):
        self.get_pc_range() <= other.get_pc_range()

    def __gt__(self, other):
        self.get_pc_range() > other.get_pc_range()

    def __ge__(self, other):
        self.get_pc_range() >= other.get_pc_range()

    def __eq__(self, other):
        self.addr == other.addr and self.get_pc_range() == other.get_pc_range()

    def __str__(self):
        return "<AddressLiveRange addr={} startpc={} endpc={}>".format(self.addr, self.startpc, self.endpc)

    def __repr__(self):
        return self.__str__()

# Ordered set of AddressLiveRange objects.
# Ordering based on PC range
class AddressLiveRangeSet(object):
    # liveranges: Iter<AddressLiveRange>
    def __init__(self, liveranges):
        self.liveranges = sorted(liveranges)
        self._verify_no_pc_overlaps()

    # No overlaps in PC ranges should be permitted
    def _verify_no_pc_overlaps(self):
        for i in range(0, len(self.liveranges) - 1):
            assert(self.liveranges[i].endpc <= self.liveranges[i + 1].startpc)

    # Given a PC Address, find the Address of the AddressLiveRange associated with the containing PC range (or None).
    def get_address_at_pc(self, pc):
        for liverng in self.liveranges:
            if liverng.get_pc_range().contains(pc):
                return liverng.addr
        return None

    # support iteration
    def __iter__(self):
        return iter(self.liveranges)

    # support bracket indexing
    def __getitem__(self, i):
        return self.liveranges[i]

    def __str__(self):
        return "<AddressLiveRangeSet {}>".format(self.liveranges)

    def __repr__(self):
        return self.__str__()
            

class AddressRangeOverlap(object):

    class SubRange(object):
        # range types
        LEFT_ONLY = 0
        RIGHT_ONLY = 1
        OVERLAP = 2

        @staticmethod
        def rangetype_to_str(rangetype):
            if rangetype == AddressRangeOverlap.SubRange.LEFT_ONLY:
                return "LEFT_ONLY"
            elif rangetype == AddressRangeOverlap.SubRange.RIGHT_ONLY:
                return "RIGHT_ONLY"
            elif rangetype == AddressRangeOverlap.SubRange.OVERLAP:
                return "OVERLAP"
            else:
                raise Exception("Invalid range type")

        def __init__(self, rangetype, range):
            self.rangetype = rangetype
            self.range = range

        def is_left_only(self):
            return self.rangetype == AddressRangeOverlap.SubRange.LEFT_ONLY

        def is_right_only(self):
            return self.rangetype == AddressRangeOverlap.SubRange.RIGHT_ONLY

        def is_overlap(self):
            return self.rangetype == AddressRangeOverlap.SubRange.OVERLAP

        def get_range(self):
            return self.range

        def get_rangetype(self):
            return self.rangetype

        def __str__(self):
            return "<SubRange {} {}>".format(
                AddressRangeOverlap.SubRange.rangetype_to_str(self.rangetype),
                self.range
            )

        def __repr__(self):
            return self.__str__()

    def __init__(self, left_range, right_range):
        self.left_range = left_range
        self.right_range = right_range
        self.subranges = AddressRangeOverlap.compute_subranges(self.left_range, self.right_range)

    @staticmethod
    def compute_subranges(left_range, right_range):

        def left_subrange(range):
            return AddressRangeOverlap.SubRange(AddressRangeOverlap.SubRange.LEFT_ONLY, range)

        def right_subrange(range):
            return AddressRangeOverlap.SubRange(AddressRangeOverlap.SubRange.RIGHT_ONLY, range)

        def overlap_subrange(range):
            return AddressRangeOverlap.SubRange(AddressRangeOverlap.SubRange.OVERLAP, range)

        # first, check that the ranges are of the same address type
        if left_range.addrtype != right_range.addrtype:
            return [
                left_subrange(left_range),
                right_subrange(right_range)
            ]

        # start and end both align
        elif left_range == right_range:
            return [
                overlap_subrange(left_range)
            ]

        elif left_range.start == right_range.start:
            if left_range.end < right_range.end:
                return [
                    overlap_subrange(left_range),
                    right_subrange(AddressRange(left_range.end, end=right_range.end))
                ]

            else: # right_range.end < left_range.end
                return [
                    overlap_subrange(right_range),
                    right_subrange(AddressRange(right_range.end, end=left_range.end))
                ]

        elif left_range.end == right_range.end:
            if left_range.start < right_range.start:
                return [
                    left_subrange(AddressRange(left_range.start, end=right_range.start)),
                    overlap_subrange(right_range)
                ]

            else: # right_range.start < left_range.start
                return [
                    right_subrange(AddressRange(right_range.start, end=left_range.start)),
                    overlap_subrange(left_range)
                ]

        elif left_range.start < left_range.end <= right_range.start < right_range.end:
            return [
                left_subrange(left_range),
                right_subrange(right_range)
            ]

        elif right_range.start < right_range.end <= left_range.start < left_range.end:
            return [
                right_subrange(right_range),
                left_subrange(left_range)
            ]
        
        elif left_range.start < right_range.start < right_range.end < left_range.end:
            return [
                left_subrange(AddressRange(left_range.start, end=right_range.start)),
                overlap_subrange(right_range),
                left_subrange(AddressRange(right_range.end, end=left_range.end))
            ]

        elif right_range.start < left_range.start < left_range.end < right_range.end:
            return [
                right_subrange(AddressRange(right_range.start, end=left_range.start)),
                overlap_subrange(left_range),
                right_subrange(AddressRange(left_range.end, end=right_range.end))
            ]

        elif left_range.start < right_range.start < left_range.end < right_range.end:
            return [
                left_subrange(AddressRange(left_range.start, end=right_range.start)),
                overlap_subrange(AddressRange(right_range.start, end=left_range.end)),
                right_subrange(AddressRange(left_range.end, end=right_range.end))
            ]

        elif right_range.start < left_range.start < right_range.end < left_range.end:
            return [
                right_subrange(AddressRange(right_range.start, end=left_range.start)),
                overlap_subrange(AddressRange(left_range.start, end=right_range.end)),
                left_subrange(AddressRange(right_range.end, end=left_range.end))
            ]

    def get_left_range(self):
        return self.left_range
    
    def get_right_range(self):
        return self.right_range

    def get_subranges(self):
        return self.subranges

    def get_overlap_range(self):
        rngs = [ subrng.get_range() for subrng in self.subranges if subrng.is_overlap() ]
        return rngs[0] if len(rngs) > 0 else None

    def get_left_ranges(self):
        return [ subrng.get_range() for subrng in self.subranges if subrng.is_left() ]

    def get_right_ranges(self):
        return [ subrng.get_range() for subrng in self.subranges if subrng.is_right() ]

    def does_overlap(self):
        return self.get_overlap_range() is not None

    def start_aligned(self):
        return self.subranges[0].is_overlap()

    def end_aligned(self):
        return self.subranges[-1].is_overlap()

    def left_first(self):
        return self.subranges[0].is_left()

    def right_first(self):
        return self.subranges[0].is_right()

    def left_last(self):
        return self.subranges[-1].is_left()

    def right_last(self):
        return self.subranges[-1].is_right()

    def disjoint(self):
        return not self.does_overlap()

    def misaligned(self):
        return self.overlap is not None and not self.left_contains_right() and not self.right_contains_left()

    # all of the right address range is contained within left
    def left_contains_right(self):
        return self.does_overlap() \
            and (self.left_first() or self.start_aligned()) \
            and (self.left_last() or self.end_aligned())

    # all of the left address range is contained within right
    def right_contains_left(self):
        return self.does_overlap() \
            and (self.right_first() or self.start_aligned()) \
            and (self.right_last() or self.end_aligned())

    def ranges_equal(self):
        return self.left_range == self.right_range

    # left.start - right.start
    def start_distance(self):
        return self.left_range.start.distance(self.right_range.start)

    # left.end - right.end
    def end_distance(self):
        return self.left_range.start.distance(self.right_range.start)

    def bytes_overlapped(self):
        return self.get_overlap_range().get_size() if self.does_overlap() else 0

    def __str__(self):
        return "<AddressRangeOverlap(subranges={})>".format(self.subranges)

    def __repr__(self):
        return self.__str__

# defines the mapping from x86-64 register names
# to their associated register numbers
# ref: https://docs.rs/gimli/0.13.0/gimli/struct.UnwindTableRow.html#method.register
class RegsX86_64(object):
    RAX = 0
    RDX = 1
    RCX = 2
    RBX = 3
    RSI = 4
    RDI = 5
    RBP = 6
    RSP = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15
    RA = 16

