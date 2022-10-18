import pandas as pd
from build_parse import *
from metrics import *

# def compute_program_comparison_metrics(
#     prog: Program,
#     metrics_group: MetricsGroup,
#     build_opts: BuildOptions = BuildOptions(debug=False, strip=False, optimization=0),
#     decompiler: str = "ghidra"
# ) -> List[MetricResult]:
#     # parse the program with DWARF & decompiler
#     # then construct an UnoptimizedProgramInfoCompare2 object
#     cmp = parse_compare_unoptimized(prog, build_opts, decompiler=decompiler)

COREUTILS_EXCLUDED = [ "arch", "coreutils", "hostname", "install", "chcon", "chgrp", "chmod", "chown", "cp", "du", "fmt", "mv", "rm", "nl", "sort", "tail", "chroot", "csplit", "date", "dd", "df", "dir", "env", "expr", "factor", "id", "kill", "ls", "mkdir", "od", "pr", "printf", "ptx", "split", "stat", "stty", "tac", "timeout", "touch", "tr", "uptime", "vdir", "[", "pinky", "shred", "test" ]

# COREUTILS_PROG_NAMES = """
# [ arch b2sum base32 base64 basename basenc cat chcon chgrp chmod chown
# chroot cksum comm coreutils cp csplit cut date dd df dir dircolors dirname
# du echo env expand expr factor false fmt fold groups head hostid hostname
# id install join kill link ln logname ls md5sum mkdir mkfifo mknod mktemp
# mv nice nl nohup nproc numfmt od paste pathchk pinky pr printenv printf ptx
# pwd readlink realpath rm rmdir runcon seq sha1sum sha224sum sha256sum
# sha384sum sha512sum shred shuf sleep sort split stat stdbuf stty sum sync
# tac tail tee test timeout touch tr true truncate tsort tty uname unexpand
# uniq unlink uptime users vdir wc who whoami yes
# """.split()

COREUTILS_PROG_NAMES = [
    '[', 'b2sum', 'base32', 'base64', 'basename', 'basenc', 'cat', 'chcon',
    'chgrp', 'chmod', 'chown', 'chroot', 'cksum', 'comm', 'cp', 'csplit',
    'cut', 'date', 'dd', 'df', 'dir', 'dircolors', 'dirname', 'du', 'echo', 'env',
    'expand', 'expr', 'factor', 'false', 'fmt', 'fold', 'groups', 'head', 'hostid',
    'id', 'join', 'kill', 'link', 'ln', 'logname', 'ls',
    'md5sum', 'mkdir', 'mkfifo', 'mknod', 'mktemp', 'mv', 'nice', 'nl', 'nohup',
    'nproc', 'numfmt', 'od', 'paste', 'pathchk', 'pinky', 'pr', 'printenv', 'printf',
    'ptx', 'pwd', 'readlink', 'realpath', 'rm', 'rmdir', 'runcon', 'seq', 'sha1sum',
    'sha224sum', 'sha256sum', 'sha384sum', 'sha512sum', 'shred', 'shuf', 'sleep', 'sort',
    'split', 'stat', 'stdbuf', 'stty', 'sum', 'sync', 'tac', 'tail', 'tee', 'test', 'timeout',
    'touch', 'tr', 'true', 'truncate', 'tsort', 'tty', 'uname', 'unexpand', 'uniq', 'unlink',
    'uptime', 'users', 'vdir', 'wc', 'who', 'whoami', 'yes'
]

COREUTILS_PROGS = [ CoreutilsProgram(progname) for progname in COREUTILS_PROG_NAMES if progname not in COREUTILS_EXCLUDED ]

def compute_program_metrics(
    prog: Program,
    opts: BuildOptions,
    metrics: List[Metric],
    decompiler: str = "ghidra"
) -> List[Union[int, float]]:

    # get the comparison object
    cmp = build_parse_compare_program(prog, opts, decompiler=decompiler)

    # use the comparison to generate the desired metrics
    return [ metric(cmp) for metric in metrics ]

def compute_program_metrics_dataframe_cached(
    progs: List[Program],
    opts: BuildOptions,
    metrics: List[Metric],
    decompiler: str = "ghidra",
    recache: bool = False
):
    cache_hash = hash((tuple(progs), opts, tuple(metrics), decompiler))
    csv_name = "{}.csv".format(cache_hash)
    csv_path = PICKLE_CACHE_DIR.joinpath(csv_name)
    
    progdeps = [ prog.get_binary_path(opts) for prog in progs ]
    srcdeps = [ CODEDIR.joinpath("metrics.py") ]
    deps = progdeps + srcdeps

    if up_to_date(csv_path, deps) and not recache:
        return pd.read_csv(csv_path, index_col=0)
    
    metrics_lists = [ compute_program_metrics(prog, opts, metrics, decompiler=decompiler) for prog in progs ]
    row_names = [ prog.get_name() for prog in progs ]
    col_names = [ metric.get_display_name() for metric in metrics ]
    df = pd.DataFrame(
        metrics_lists,
        index=row_names,
        columns=col_names
    )
    df.to_csv(csv_path)
    return df
    


