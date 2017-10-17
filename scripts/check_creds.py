#!/usr/bin/python

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

# Other imports
import time

# Retrieve check creds plugin
import volatility.plugins.linux.check_creds as fopPlugin
fopData = fopPlugin.linux_check_creds(config)

invalid_fop_start_time = time.time()
for msg in fopData.calculate():
	print "***Processes are sharing credential structures***"  
	print msg
	dir(msg)
print("--- Check creds Time Taken: %s seconds ---" % (time.time() - invalid_fop_start_time))
