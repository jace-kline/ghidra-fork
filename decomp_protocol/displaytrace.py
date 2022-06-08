import re

# returns (syscall, content string)
def parse_line(line):
    fmt = '^\d+\s(read|write)[(]\d+,\s["](.+)["],\s\d+[)]\s+=\s+\d+$'
    p = re.compile(fmt)
    m = p.match(line)
    if m is not None:
        return m.groups()
    else:
        return None

def main():
    strace_file = "decomp-protocol.strace"
    ls = open(strace_file).readlines()
    parsed_lines = [ l for l in [ parse_line(l) for l in ls ] if l is not None ]
    for (call, content) in parsed_lines:
        print(f"{call}:\n\t{content}")

if __name__ == "__main__":
    main()
    