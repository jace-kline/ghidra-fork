from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile

def mk_ELFFile(fname):
    try:
        f = open(fname, 'rb')
        elffile = ELFFile(f)
        return elffile
    except:
        return None

# get all DIE entries across all CUs
# ignore null DIEs
def get_all_DIEs(dwarfinfo):
    dies = []
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            if not die.is_null():
                dies.append(die)
    return dies

def get_function_DIEs(dwarfinfo):
    dies = get_all_DIEs(dwarfinfo)
    return [ die for die in dies if die.tag == "DW_TAG_subprogram" ]

def main():
    objfilepath = "./progs/p0"
    elffile = mk_ELFFile(objfilepath)
    if elffile is None:
        print("Error: Could not parse ELF info")
        return

    if not elffile.has_dwarf_info():
        print("Error: File has no DWARF info")
        return

    dwarfinfo = elffile.get_dwarf_info()

    if not dwarfinfo.has_debug_info:
        print("Error: DWARF info has no debug info")
        return

    # get all DIE objects across all CUs
    fn_dies = get_function_DIEs(dwarfinfo)
    for die in fn_dies:
        print(die)

    
    elffile.stream.close()

if __name__ == "__main__":
    main()
    
