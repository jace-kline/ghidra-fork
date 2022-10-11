import os
from typing import Any, List, Union
from pathlib import Path, PosixPath

class FilesystemDependencyRuleDatabase(object):
    def __init__(
        self,
        rules: List['FilesystemDependencyRule'] = []
    ):
        self.db: dict[Path, FilesystemDependencyRule] = \
            dict([ (rule.get_target_path(), rule) for rule in rules ])

        for rule in rules:
            rule.set_rule_db(self)

    def add_rule(self, rule: 'FilesystemDependencyRule'):
        self.db[rule.get_target_path()] = rule
        rule.set_rule_db(self)

    def get_rule(self, target: Path) -> Union['FilesystemDependencyRule', None]:
        return self.db.get(target, None)

    def make_target(self, target: Path, rebuild: bool = False) -> bool:
        rule = self.get_rule(target)
        return target.exists() if rule is None \
            else all([ self.make_target(dep, rebuild=rebuild) for dep in rule.get_deps() ]) and rule.do_rule(rebuild=rebuild)

# singleton rule database -> injected into each rule object
RULE_DB = FilesystemDependencyRuleDatabase()

# This is a rudimentary implementation of a Makefile "target".
# A target "out path" that depends on a set of "dependency paths".
class FilesystemDependencyRule(object):
    def __init__(
        self,
        target: Path,
        deps: List[Path],
        build, # () -> bool ... function to build the target. Returns True on success, False on failure
        rule_db: 'FilesystemDependencyRuleDatabase' = RULE_DB
    ):
        self.target = target
        self.deps = tuple(deps)
        self.build = build

        self.rule_db = rule_db
        self.rule_db.add_rule(self)

    def set_rule_db(self, db: 'FilesystemDependencyRuleDatabase'):
        self.rule_db = db

    def get_target_path(self) -> Path:
        return self.target

    def get_target_hash(self) -> int:
        return hash(self.target)

    def get_deps(self) -> List[Path]:
        return self.deps

    # Is the target date newer than the dates of all deps?
    def target_up_to_date(self) -> bool:
        def last_modification_ns(p: Path) -> int:
            res = p.stat().st_mtime_ns
            return res if res else -1

        target_mtime_ns = last_modification_ns(self.target)
        return target_mtime_ns > 0 and all([ target_mtime_ns > last_modification_ns(dep) for dep in self.deps ])

    def target_exists(self) -> bool:
        return self.target.exists()

    # Tries to load the cached target.
    # If not up to date, rebuilds it.
    # Returns the target path on success, None on failure.
    def do_rule(self, rebuild: bool = False) -> bool:
        return self.target if not rebuild and self.target_exists() and self.target_up_to_date() \
            else self.build()

    # invokes the parent DB to resolve and make this target
    def make(self, rebuild: bool = False) -> bool:
        return self.rule_db.make_target(self.get_target_path(), rebuild=rebuild)

    def clean(self):
        if self.target_exists():
            os.remove(str(self.target))

    def __hash__(self) -> int:
        return hash((self.target, self.deps))