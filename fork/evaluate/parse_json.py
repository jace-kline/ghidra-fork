import json
from resolve import *
from resolve_stubs import *
# The purpose of this module is to parse a dictionary (from JSON/YAML)
# into our common language.

# start with JSON/YAML
# -> (( json / yaml module: parse into Python dict ))
# -> Python dict {ref: obj} 
# -> (( parse objs to stubs ))
# -> Python dict {ref: stub} 
# -> (( convert each stub to a record & add to ResolverDatabase ))
# -> ResolverDatabase
# -> (( call db.resolve_root() to resolve from the ProgramInfoStub's record ))
# -> ProgramInfo

class ParseException(Exception):
    pass

def dict_from_json_file(fpath):
    f = open(fpath)
    d = json.load(f)
    f.close()
    return d

def dict_to_stub(d):
    # dynamically retrieve the target stub class type
    stubclass = globals()[d['objtype'] + "Stub"]
    # remove the 'objtype' field
    del d['objtype']
    # the rest of the kwargs can be directly mapped to instantiate stub
    return stubclass(**d)

def make_resolver_database(d):
    db = ResolverDatabase()
    for k, v in d.items():
        if v['objtype'] == "ProgramInfo":
            db.set_root_key(k)
        try:
            stub = dict_to_stub(v)
        except:
            raise ParseException("Could not parse object with key {}".format(k))
        db.make_record(k, stub)
    return db

def parse_from_dict(d):
    return make_resolver_database(d).resolve_root()

def parse_from_json_file(fpath):
    return parse_from_dict(dict_from_json_file(fpath))

def parse_from_json_string(s):
    return parse_from_dict(json.loads(s))

def test():
    d = dict_from_json_file("./api_json_example.json")
    db = make_resolver_database(d)
    proginfo = db.resolve_root()
    print(proginfo)
    print(proginfo.get_functions())
    print(proginfo.get_globals())

if __name__ == "__main__":
    test()
