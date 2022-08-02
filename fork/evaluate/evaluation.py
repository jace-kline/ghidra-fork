from collections import namedtuple
from translation import *

# leftonly: [AddressRange]
# overlap: AddressRange | None
# rightonly: [AddressRange]
AddressRangeOverlap = namedtuple("AddressRangeOverlap", "leftonly overlap rightonly")

# Range includes start, excludes end.
# The start and end addresses must be of the same AddressType.
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
            self.end = end
            # if end < start, swap the order
            if self.end < self.start:
                self.start = end
                self.end = start
            self.size = self.start.distance(self.end)
        elif size:
            assert(size >= 0)
            self.size = size
            self.end = start.add_const(size)
        else:
            raise Exception("Must provide 'end' or 'size' attribute to construct AddressRange.")

    # other: AddressRange
    # (AddressRange, AddressRange) -> AddressRangeOverlap
    def overlap(self, other):
        # first, check that the ranges are of the same address type
        if self.addrtype != other.addrtype:
            return AddressRangeOverlap([self], None, [other])

        swap = self.start > other.start
        fst = other if swap else fst
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

