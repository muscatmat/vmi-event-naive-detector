#!/usr/bin/python

print "--- Starting Malware Detection! ---"

# Import System Required Paths
import sys
sys.path.append('/usr/local/src/volatility-master')

# Import Volalatility
import volatility.conf as conf
import volatility.registry as registry
registry.PluginImporter()
config = conf.ConfObject()
import volatility.commands as commands
import volatility.addrspace as addrspace
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.PROFILE="LinuxDebian31604x64"
config.LOCATION = "vmi://debian-hvm"

def dt(objct, address = None, space = None, recursive = False, depth = 0):
            if address is not None:
                objct = obj.Object(objct, address, space or self._proc.get_process_address_space())

            try:
                if isinstance(objct, str):
                        size = profile.get_obj_size(objct)
                        membs = [ (profile.get_obj_offset(objct, m), m, profile.vtypes[objct][1][m][1]) for m in profile.vtypes[objct][1] ]
                        print "{0}".format("..." * depth), repr(objct), "({0} bytes)".format(size)
                        for o, m, t in sorted(membs):
                            print "{0}{1:6}: {2:30} {3}".format("..." * depth, hex(o), m, t)
                            if recursive: 
                                if t[0] in profile.vtypes:
                                    dt(t[0], recursive = recursive, depth = depth + 1)
                elif isinstance(objct, obj.BaseObject):
                    membs = [ (o, m) for m, (o, _c) in objct.members.items() ]
                    if not recursive:
                        print repr(objct)
                    offsets = []
                    for o, m in sorted(membs):
                        val = getattr(objct, m)
                        if isinstance(val, list):
                            val = [ str(v) for v in val ]

                        # Handle a potentially callable offset
			if callable(o):
                            o = o(objct) - objct.obj_offset

                        offsets.append((o, m, val))

                    # Deal with potentially out of order offsets
                    offsets.sort(key = lambda x: x[0])

                    for o, m, val in offsets:
                        try:
                            print "{0}{1:6}: {2:30} {3}".format("..." * depth, hex(o), m, val)
                            print "{0}{1:6}: {2:30} {3}".format("..." * depth, hex(o), m, val)
                            print "{0}{1:6}: {2:30} {3}".format("..." * depth, hex(o), m, val)
                            print "{0}{1:6}: {2:30} {3}".format("..." * depth, hex(o), m, val)
                        except UnicodeDecodeError:
                            print "{0}{1:6}: {2:30} -".format("..." * depth, hex(o), m)
                        if recursive:
                            if val.obj_type in profile.vtypes:
                                dt(val, recursive = recursive, depth = depth + 1)
                elif isinstance(objct, obj.NoneObject):
                    print "ERROR: could not instantiate object"
                    print
                    print "Reason: ", objct.reason
                else:
                    print "ERROR: first argument not an object or known type"
                    print
                    print "Usage:"
                    print
                    hh(dt)
            except TypeError:
                print "Error: could not instantiate object"
                print
                print "Reason: ", "displaying types with dynamic attributes is currently not supported"

dt("task_struct");

print "--- Malware Detection Exited! ---"
