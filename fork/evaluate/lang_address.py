
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

    # other: AddressRange
    # (AddressRange, AddressRange) -> AddressRangeOverlap
    def get_overlap(self, other):
        # first, check that the ranges are of the same address type
        if self.addrtype != other.addrtype:
            return AddressRangeOverlap([self], None, [other])

        swap = self.start > other.start
        fst = other if swap else self
        snd = self if swap else other

        fstonly = []
        sndonly = []
        overlap = None
        # we know fst.start <= all other addresses
        if fst.end <= snd.start:
            fstonly, overlap, sndonly = ([fst], None, [snd])

        else: # fst.end > snd.start
            if fst.start != snd.start:
                fstonly.append(AddressRange(fst.start, snd.start))
            
            if fst.end <= snd.end:
                overlap = AddressRange(snd.start, snd.end)
                if fst.end != snd.end:
                    sndonly.append(AddressRange(fst.end, end=snd.end))
            
            else: # fst.end > snd.end
                overlap = snd
                fstonly.append(AddressRange(snd.end, end=fst.end))
        
        leftonly = sndonly if swap else fstonly
        rightonly = fstonly if swap else sndonly
        return AddressRangeOverlap(leftonly, overlap, rightonly)

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
    # leftonly: [AddressRange] (either 0, 1, or 2 ranges)
    # overlap: AddressRange | None
    # rightonly: [AddressRange] (either 0, 1, or 2 ranges)
    def __init__(self, leftonly, overlap, rightonly):
        self.leftonly = leftonly
        self.overlap = overlap
        self.rightonly = rightonly

    @staticmethod
    def does_overlap(addrl, addrr):
        return addrl.does_overlap(addrr)

    @staticmethod
    def get_overlap(addrl, addrr):
        return addrl.get_overlap(addrr)

    def __repr__(self):
        return "<AddressRangeOverlap(leftonly={}, overlap={}, rightonly={})>".format(self.leftonly, self.overlap, self.rightonly)

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

