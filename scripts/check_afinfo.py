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

# Retrieve hidden af info
import volatility.plugins.linux.check_afinfo as afInfoPlugin
afInfoData = afInfoPlugin.linux_check_afinfo(config)

hidden_af_info_start_time = time.time()
for msg in afInfoData.calculate():
	print "***Possible malware detected by checking for network connection tampering***"  
	print msg
	dir(msg)
print("--- Hidden Af Info Time Taken: %s seconds ---" % (time.time() - hidden_af_info_start_time))
