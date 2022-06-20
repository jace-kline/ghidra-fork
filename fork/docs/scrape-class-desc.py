import pandas as pd
import re

def remove_first_char(s):
    return s[1:]

def mk_lookup_fn():
    res = pd.read_html("./classes.html")
    df = res[0]
    df['class'] = df['class'].apply(remove_first_char)
    df.set_index('class', inplace=True, drop=True)

    def lookup(_class):
        try:
            res = df.at[_class, 'description']
        except KeyError:
            res = None
        return res
    
    return lookup

def test_lookup():
    lookup = mk_lookup_fn()
    print(lookup('Action'))

def parse_line(l): # return (spaces, class name)
    pat = "^([ ]*)(\S+).*$"
    p = re.compile(pat)
    m = p.match(l)
    return m.groups() if m is not None else None

def trim_newline(l):
    return l[:-1]

def main():
    desc_of = mk_lookup_fn()
    f = open("action-sequence-decompiler.txt")
    # read each line
    ls = f.readlines()
    ls = [ trim_newline(l) for l in ls ]

    # for each line, capture the leading spaces + the class name
    _ls = [ (l, parse_line(l)) for l in ls ]

    for l, parse in _ls:
        print(l)
        if parse is not None:
            spaces, _class = parse
            desc = desc_of(_class)
            if desc is not None:
                print(f"  {spaces}- {desc}")

def test():
    f = open("action-sequence-decompiler.txt")
    ls = f.readlines()
    ls = [ trim_newline(l) for l in ls ]
    print(ls)

if __name__ == "__main__":
    main()