from parse_dwarf_util import *
from parse_dwarf import *

def setup():
    objfilepath = "../progs/typecases_debug_O3.bin"
    return get_elf_dwarf_info(objfilepath)

def test():
    elffile, dwarfinfo = setup()

    structs = dwarfinfo.structs
    # print(structs)
    # print(dir(structs))
    
    dies = get_all_DIEs(dwarfinfo)
    # print(dir(dwarfinfo))
    loclists = dwarfinfo.location_lists() # LocationLists
    # print(dir(loclists))

    # loclist = loclists.get_location_list_at_offset(0x8) # [LocationEntry]
    # locentry = loclist[0] # LocationEntry
    # print(locentry)
    # print(dir(locentry))

    vardies = [ die for die in dies if die.tag in ["DW_TAG_variable", "DW_TAG_formal_parameter"] ]
    # print(vardies)
    # locs = [ get_DIE_locs(die) for die in vardies ]
    # print(locs)
    # varloc_attrs = [ attr for attr in [ get_DIE_attr(die, "DW_AT_location") for die in vardies ] if attr is not None ]
    # varloc_attr_forms = [ attr.form for attr in varloc_attrs ]
    # print(varloc_attr_forms)

    gblvardie = get_var_DIE_by_name(dwarfinfo, "globalvar_uninit")
    localvardie0 = get_var_DIE_by_name(dwarfinfo, "s", fname="main")
    localvardie1 = get_var_DIE_by_name(dwarfinfo, "stackvar", fname="main")
    
    for vardie in [gblvardie, localvardie0, localvardie1]:
        print("{}".format(get_DIE_name(vardie)))
        locs = get_DIE_locs(vardie)
        # print(locs)
        if type(locs) == list:
            addrs = []
            for loc in locs:
                try:
                    # type(loc) == LocationEntry
                    addr = parse_dwarf_locexpr_addr(dwarfinfo, loc.loc_expr)
                    if addr is not None:
                        addrs.append(addr)
                except AttributeError:
                    # type(loc) == BaseAddressEntry | LocationViewPair
                    pass
            for addr in addrs:
                print(addr)
        else:
            addr = parse_dwarf_locexpr_addr(dwarfinfo, locs.loc_expr)
            print(addr)
        print(""),

    # for die in dies:
    #     print(die)

def test_high_pc_attr():
    _, dwarfinfo = setup()

    fndies = get_function_DIEs(dwarfinfo)
    for fndie in fndies:
        print(get_DIE_name(fndie))
        lowpc_attr = get_DIE_attr(fndie, "DW_AT_low_pc")
        if lowpc_attr is not None:
            print(lowpc_attr.form)
        highpc_attr = get_DIE_attr(fndie, "DW_AT_high_pc")
        if highpc_attr is not None:
            print(highpc_attr.form)
        print(""),

def test_low_high_pc_attr():
    _, dwarfinfo = setup()
    fndies = get_function_DIEs(dwarfinfo)
    for fndie in fndies:
        print(get_DIE_name(fndie))
        res = get_DIE_low_high_pc(fndie)
        if res is not None:
            lowpc, highpc = res
            print("{:#x}\n{:#x}\n".format(lowpc, highpc)),

def test_parse_dwarf():
    proginfo = parse_from_objfile("../progs/typecases_debug_O0.bin")
    proginfo.print_summary()

def test_addr_parse():
    _, dwarfinfo = get_elf_dwarf_info("../progs/typecases_debug_O0.bin")
    fndies = get_function_DIEs(dwarfinfo)
    for fndie in fndies:
        pass

if __name__ == "__main__":
    test_parse_dwarf()