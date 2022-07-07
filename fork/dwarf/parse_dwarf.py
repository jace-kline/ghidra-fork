from resolve import *
from resolve_stubs import *
from parse_dwarf_util import *

class ParseDWARF:
    def __init__(self, dwarfinfo):
        self.dwarfinfo = dwarfinfo
        # holds {ref: DIE} mappings
        self.diemap = {}
        # holds {ref: stub} mappings
        self.db = ResolverDatabase()

    def generate_unique_key(self):
        MAXREF = 999999
        for k in range(0, MAXREF):
            if not self.db.exists(k):
                return k

    def parse(self):
        # map each DIE to its (ref, DIE)
        self.diemap = dict([ (die.offset, die) for die in get_all_DIEs(self.dwarfinfo) ])

        # create a "root" ProgramInfoStub object
        globalrefs = [ die.offset for die in get_global_var_DIEs(self.dwarfinfo) ]
        functionrefs = [ die.offset for die in get_function_DIEs(self.dwarfinfo) ]
        rootkey = self.generate_unique_key()
        self.db.make_record(
            rootkey,
            ProgramInfoStub(globalrefs=globalrefs, functionrefs=functionrefs)
        )
        self.db.set_root_key(rootkey)

        # TODO implement rest of this method



def parse_from_dwarfinfo(dwarfinfo):
    parser = ParseDWARF(dwarfinfo)
    return parser.parse()

# produce a Translation object from the DWARF info
def parse_from_objfile(objfilepath):
    elffile, dwarfinfo = get_elf_dwarf_info(objfilepath)
    return parse_from_dwarfinfo(dwarfinfo)
    