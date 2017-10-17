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

# Retrieve hidden modules
import volatility.plugins.linux.hidden_modules as hiddenModulesPlugin
hiddenModulesData = hiddenModulesPlugin.linux_hidden_modules(config)

hidden_modules_start_time = time.time()
for msg in hiddenModulesData.calculate():
	print "***Possible malware detected by checking for hidden modules***"  
	print msg
	dir(msg)
print("--- Hidden Modules Time Taken: %s seconds ---" % (time.time() - hidden_modules_start_time))
