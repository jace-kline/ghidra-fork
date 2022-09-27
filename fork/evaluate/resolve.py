class ResolverException(Exception):
    pass

def none_attr_exception(obj, attr):
    raise AttributeError(
        "In class {}: required '{}' attribute is None"
        .format(type(obj).__name__, attr)
    )

def assert_not_none(obj, attr):
    if vars(obj).get(attr, None) is None:
        none_attr_exception(obj, attr)


# Holds ResolverRecord objects in a map.
# Used to create nested/recursive structures from an initial
# flattened table.
# The key type can be any type suitable for the domain, but generally
# it is an int.
class ResolverDatabase(object):

    # An abstract class representing a flattened "stub" object stored in
    # a ResolverRecord. Each child class must implement the "resolve()" method.
    class ResolverStub(object):
        def resolve(self, record):
            raise NotImplementedError("Must implement resolve() method in subclass")

    class ResolverTag(object):
        STUB = 0
        RESOLVED = 1

    # holds a stub and/or resolved object, depending on the tag
    class ResolverRecord(object):
        def __init__(self, db, key, stub):
            # the parent database
            self.db = db
            # this record's key in the ResolverDatabase
            self.key = key
            # indicates whether this record is resolved
            self.tag = ResolverDatabase.ResolverTag.STUB
            # the "flattened" object information
            self.stub = stub
            # the "resolved"/nested object, initially unset
            self.obj = None

            # Mark whether recursive resolution is currently occuring
            # to sub-types of this object.
            # In this state, the 'obj' field is a DataType, but the
            # fields are in an unstable/unresolved form.
            # Used to prevent cycles.
            self.resolving = False

        def is_resolving(self):
            return self.resolving

        def set_resolving(self):
            if not self.resolving:
                self.resolving = True
            else:
                raise ResolverException("Tried to set an already 'resolving' record")

        def unset_resolving(self):
            if self.resolving:
                self.resolving = False
            else:
                raise ResolverException("Tried to unset a non-'resolving' record")

        def resolve(self, db):
            # If this record is resolved, just return the self.obj.
            # If this record is already resolving, we are in a recursive cycle.
            # Otherwise, we are calling for first time.
            if (not self.is_resolving()) and self.tag == ResolverDatabase.ResolverTag.STUB:
                
            # if this record is still a stub, we must resolve the stub
                if self.tag == ResolverDatabase.ResolverTag.STUB:
                    self.set_resolving()
                    self.obj = self.stub.resolve(self)


                # not recursive
                if self.is_resolving():
                    self.unset_resolving()
                    self.tag = ResolverDatabase.ResolverTag.RESOLVED
            
            return self.obj

        def __str__(self):
            return "<ResolverRecord key={} tag={} stub={}>".format(self.key, self.tag, self.stub)

        def __repr__(self):
            return str(self)

    def __init__(self, db={}, rootkey=None):
        self.db = db
        # the key that marks the "root" node of the flattened structure
        self.rootkey = rootkey

    def exists(self, key):
        return key in self.db

    def lookup(self, key):
        return self.db.get(key, None)

    def has_root_key(self):
        return self.rootkey is not None

    def set_root_key(self, key):
        self.rootkey = key

    def make_record(self, key, stub, overwrite=False):
        # if not overwrite and self.exists(key):
        #     raise KeyError("Key already exists in ResolverDatabase: key={}, record={}, provided={}".format(
        #         key,
        #         self.lookup(key),
        #         stub
        #     ))

        return self.add(
            key,
            ResolverDatabase.ResolverRecord(self, key, stub)
        )

    def add(self, key, record):
        self.db[key] = record
        return record

    # only add if existing key doesn't exist
    def try_add(self, key, record):
        return self.db.setdefault(key, record)

    # if the key already exists, remove it. Otherwise, do nothing.
    def remove(self, key):
        if self.exists(key):
            del self.db[key]

    def set_resolving(self, key):
        record = self.lookup(key)
        if record is not None:
            record.set_resolving()
        else:
            raise KeyError(
                "Attempted to 'set_resolving' on non-existent key {}"
                .format(key)
            )

    def unset_resolving(self, key):
        record = self.lookup(key)
        if record is not None:
            record.unset_resolving()
        else:
            raise KeyError(
                "Attempted to 'unset_resolving' on non-existent key {}"
                .format(key)
            )

    def resolve(self, key):
        record = self.lookup(key)
        if record is not None:
            return record.resolve(self)
        else:
            raise KeyError(
                "Attempted to resolve non-existent key within 'resolve': key={}".format(key)
            )

    def resolve_many(self, keys):
        try:
            return [ self.resolve(key) for key in keys ]
        except KeyError as e:
            raise ResolverException(
                str(e) + ". Attempted to resolve non-existent key within 'resolve_many'\n" + str(self.db)
            )

    def resolve_root(self):
        if not self.has_root_key():
            raise ResolverException("Attempted to resolve from root with no root key set")
        
        return self.resolve(self.rootkey)