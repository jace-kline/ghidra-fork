from lang import *

def test_AddressRangeOverlap():
    a00 = AbsoluteAddress(0x1000)
    a01 = AbsoluteAddress(0x1100)
    r0 = AddressRange(a00, end=a01)
    assert(r0.end == r0.start.add_const(r0.size))

    a10 = AbsoluteAddress(0x1010)
    a11 = AbsoluteAddress(0x1110)
    r1 = AddressRange(a10, end=a11)
    res = r0.get_overlap(r1)
    print(res)

    a10 = AbsoluteAddress(0x0100)
    a11 = AbsoluteAddress(0x1110)
    r1 = AddressRange(a10, end=a11)
    res = r0.get_overlap(r1)
    print(res)

def test_ordering():
    a00 = AbsoluteAddress(0x1000)
    a01 = AbsoluteAddress(0x1100)
    r0 = AddressRange(a00, end=a01)

    a10 = AbsoluteAddress(0x1010)
    a11 = AbsoluteAddress(0x1110)
    r1 = AddressRange(a10, end=a11)

    a20 = AbsoluteAddress(0x0100)
    a21 = AbsoluteAddress(0x1110)
    r2 = AddressRange(a20, end=a21)

    rngs = [ r0, r1, r2 ]
    rngs_sorted = sorted(rngs)
    print(rngs_sorted)
    assert(rngs_sorted == [ r2, r0, r1 ])


if __name__ == "__main__":
    test_ordering()
    