import re

def parse_line(l): # return (class, grouplist)
    pat = "^\s*(\S+)\s*\(\"(.*)\"\).*$"
    p = re.compile(pat)
    m = p.match(l)
    return m.groups() if m is not None else None

def main():
    f = open("action-sequence-decompiler.txt")
    # read each line
    ls = f.readlines()
    cls_grps = [ parse_line(l) for l in ls ]
    cls_grps = [ l for l in cls_grps if l is not None ]

    m = {}
    for c, grp in cls_grps:
        try:
            m[grp].append(c)
        except KeyError:
            m[grp] = [c]
    
    for grp, cs in m.items():
        print(grp)
        for c in cs:
            print(f"\t{c}")


def test():
    m = {"hello": 1, "goodbye": 2, "sup": 3}
    print(m["test"])

if __name__ == "__main__":
    main()