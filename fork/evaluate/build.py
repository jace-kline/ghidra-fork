# This module facilitates build process for generating the ProgramInfo pickle files for a given C program.

import os
import shutil
import subprocess
import pickle
import sys

MODULE = os.path.dirname(os.path.abspath(__file__))
CWD = os.path.abspath(os.getcwd())
MAKEFILE_PATH = os.path.join(MODULE, "../progs/Makefile")

# if path is resolvable, leave alone.
# otherwise, make it relative to the CWD.
# str -> str | None
def resolve_path_cwd(path):
    if os.path.exists(path):
        return os.path.abspath(path)

    path = os.path.join(CWD, path)
    return os.path.abspath(path) if os.path.exists(path) else None

class PickleTarget(object):
    def __init__(self, progname, opt_lvl=0, decompiler="ghidra", strip=False, debug=False):
        self.progname = progname
        self.opt_lvl = opt_lvl
        self.decompiler = decompiler
        self.strip = strip
        self.debug = debug

        self.build_result = None

    def set_build_result(self, build_result):
        self.build_result = build_result

    def get_build_result(self):
        return self.build_result

    def __str__(self):
        target = "{}_O{}".format(self.progname, self.opt_lvl)
        if self.debug:
            target += "_debug"
        elif self.strip:
            target += "_strip"
        target += ".{}.pickle".format(self.decompiler)
        return target

class DWARFPickleTarget(PickleTarget):
    def __init__(self, progname, opt_lvl):
        super(__class__, self).__init__(
            progname,
            opt_lvl=opt_lvl,
            decompiler="dwarf",
            strip=False,
            debug=True
        )

class GhidraPickleTarget(PickleTarget):
    def __init__(self, progname, opt_lvl, strip=False, debug=False):
        super(__class__, self).__init__(
            progname,
            opt_lvl=opt_lvl,
            decompiler="ghidra",
            strip=strip,
            debug=debug
        )

class PickleBuilder(object):
    def __init__(self, 
        dir, # the program directory containing the .c files
        makefile=MAKEFILE_PATH, # the path where the generic makefile lives (to build the target program)
        optimization_levels=[0], # list of levels, subset of [0..3]
        debug=False, # should the binary's debug info be used by the decompiler?
        strip=False, # should the binary be stripped for the decompiler?
        override_makefile=True, # if there exists a Makefile in the program directory, do we have permission to override it?
        decompilers=["ghidra"] # the decompilers to use -> shouldn't override this
    ):
        self.dir = resolve_path_cwd(dir)
        if self.dir is None:
            raise FileNotFoundError("Error: Program directory '{}' is not valid.".format(dir))

        # name of the program = the basename of the program directory path
        self.progname = os.path.basename(self.dir)

        self.makefile = resolve_path_cwd(makefile)
        if self.makefile is None:
            raise FileNotFoundError("Error: Makefile path '{}' is not valid.".format(makefile))

        self.optimization_levels = optimization_levels
        assert(all(( 0 <= x <= 3 for x in self.optimization_levels )))

        self.debug = debug
        self.strip = strip
        self.override_makefile = override_makefile
        self.decompilers = decompilers
        self.targets = self._generate_targets()
        self.success = True
        self.built = False

    # generate the string names of the target pickle files
    def _generate_targets(self):
        targets = []
        for opt_lvl in self.optimization_levels:
            targets.append(DWARFPickleTarget(self.progname, opt_lvl=opt_lvl))
            for decompiler in self.decompilers:
                _make_target = lambda debug, strip: PickleTarget(self.progname, opt_lvl=opt_lvl, decompiler=decompiler, debug=debug, strip=strip)
                if self.strip:
                    targets.append(_make_target(False, True))
                elif self.debug:
                    targets.append(_make_target(True, False))
                else:
                    targets.append(_make_target(False, False))
        return targets

    def _copy_makefile(self):
        # attempt to get the old Makefile from the program dir
        # if generic Makefile is newer by modification time, then copy the generic into the program dir
        makefile_loc = os.path.join(self.dir, "Makefile")
        if self.override_makefile:
            copy = True
            if os.path.exists(makefile_loc):
                orig_mtime = os.path.getmtime(makefile_loc)
                mtime = os.path.getmtime(self.makefile)
                if orig_mtime >= mtime:
                    copy = False

            if copy:
                shutil.copy2(self.makefile, makefile_loc)
        
        assert(os.path.exists(makefile_loc))

    def clean(self):
        self.success = subprocess.call(["make", "-C", self.dir, "clean"])
        return self.success

    # This function runs the `make` build for the target source directory with the desired targets.
    # .c files -> .o files -> .bin (executable) -> [decompile/parse DWARF] -> [translate] -> .pickle files
    def build(self, rebuild=False):
        # copy the generic makefile to the build directory
        self._copy_makefile()

        # if rebuild flag set, clean old artifacts & rebuild
        if rebuild:
            self.clean()
            
        print("Building Makefile targets in directory '{}':".format(self.dir))
        for target in self.targets:
            print("\t{}".format(target))
        
        status = subprocess.call(["make", "-C", self.dir] + [ str(target) for target in self.targets] )
        self.success = self.success and status == 0
        if status == 0:
            print("Verifying targets...")
            self.success = all(( os.path.exists(os.path.join(self.dir, str(target))) for target in self.targets ))
            if self.success:
                print("Success!")
            else:
                print("Error: Could not verify all targets.")
        else:
            print("Error: Make process executed with return code {}.".format(status))
        
        self.built = self.success

        # if build failed, clean up
        if not self.built:
            self.clean()

        return self.success

    def is_built(self):
        return self.built

    def get_targets(self):
        return self.targets

    # For the given PickleTarget, load the pickle file from the filesystem
    def get_built_pickle(self, target):
        if not self.is_built():
            raise Exception("Error: build() has not been performed.")
        picklepath = os.path.join(self.dir, str(target))
        return load_pickle(picklepath)

    # For each PickleTarget, load the associated Pickle file from the filesystem
    # and inject into the target
    def set_target_build_results(self):
        if not self.is_built():
            raise Exception("Error: build() has not been performed.")
        for target in self.get_targets():
            picklepath = os.path.join(self.dir, str(target))
            target.set_build_result(load_pickle(picklepath))

# str -> ProgramInfo
def load_pickle(picklepath):
    infile = open(picklepath, 'rb')
    obj = pickle.load(infile)
    infile.close()
    return obj

def build(progdir, optimization_levels=[0], debug=False, strip=False, decompilers=["ghidra"], rebuild=False):
    builder = PickleBuilder(progdir, optimization_levels=optimization_levels, debug=debug, strip=strip, decompilers=decompilers)
    if(builder.build(rebuild=rebuild)):
        builder.set_target_build_results()
        return builder.get_targets()

def build2(progdir, opt_lvl, debug=False, strip=False, decompiler="ghidra", rebuild=False):
    targets = build(progdir, optimization_levels=[opt_lvl], debug=debug, strip=strip, decompilers=[decompiler], rebuild=rebuild)
    dwarf_proginfo = targets[0].get_build_result()
    decomp_proginfo = targets[1].get_build_result()
    return (dwarf_proginfo, decomp_proginfo)

def build_dwarf(progdir, rebuild=False):
    targets = build(progdir, decompilers=[], rebuild=rebuild)
    return targets[0].get_build_result()

def test():
    picklepath_dwarf = "../progs/typecases_splitobjs/typecases_splitobjs_O0_debug.dwarf.pickle"
    picklepath_ghidra = "../progs/typecases_splitobjs/typecases_splitobjs_O0.ghidra.pickle"
    proginfo = load_pickle(picklepath_ghidra)
    proginfo.print_summary()

def test_build(dir):
    builder = PickleBuilder(dir=dir, optimization_levels=[0,3])
    success = builder.build(rebuild=True)
    return success

if __name__ == "__main__":
    dir = sys.argv[1]
    test_build(dir)
