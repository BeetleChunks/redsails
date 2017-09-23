from pydivert.windivert import *

from rsHelper.rsUtils import *

class TCPListener:
	# Determine if listener is still running
	isListening = False

	# Not filtering on address for flexability
	def __init__(self, listenPort):
		# Create debug logging object
		#self.loggingTCPListener = loggingUtils("tcpListener-debug.log")

		self.listenPort = listenPort
		self.filter = "tcp.DstPort == %s" % (self.listenPort)
		self.listener = WinDivert(self.filter)

	def startListener(self):
		try:
			self.listener.open()
			self.isListening = True

		except Exception as e:
			#print "[!] Error starting listener...\n%s" % (e)
			pass

	def stopListener(self):
		try:
			self.listener.close()
			self.isListening = False

		except Exception as e:
			#print "[!] Error stopping listener...\n%s" % (e)
			pass

	def recvPacket(self):
		try:
			self.packet = self.listener.recv()

		except Exception as e:
			#print "[!] Error receiving packet...\n%s" % (e)
			# DEBUG - Log packet to debug log
			#self.loggingTCPListener.logPacket(self.packet, "rsRemote->rsNetworking.py->recvPacket - ERROR")
			pass

	def sendPacket(self):
		try:
			self.listener.send(self.packet, recalculate_checksum=True)

		except Exception as e:
			#print "[!] Error sending packet...\n%s" % (e)
			# DEBUG - Log packet to debug log
			#self.loggingTCPListener.logPacket(self.packet, "rsRemote->rsNetworking.py->sendPacket - ERROR")
			pass

class TCPHelper:
	def isInitConnection(self, packet):
		self.packet = packet
		only_SYN = False
		null_payload = False
		ack_zero = False

		self.getFlags()

		if (self.flags[0] == 1) and ((self.flags[1]+self.flags[2]+self.flags[3]+self.flags[4]) == 0):
			only_SYN = True

		if (len(self.packet.tcp.payload) == 0):
			null_payload = True

		if (self.packet.tcp.ack_num == 0):
			ack_zero = True

		if (only_SYN and null_payload and ack_zero):
			return True

		else:
			return False

	def getFlags(self):
		self.flags = [0, 0, 0, 0, 0]

		if self.packet.tcp.syn == True:
			self.flags[0] = 1

		if self.packet.tcp.ack == True:
			self.flags[1] = 1

		if self.packet.tcp.psh == True:
			self.flags[2] = 1

		if self.packet.tcp.fin == True:
			self.flags[3] = 1

		if self.packet.tcp.rst == True:
			self.flags[4] = 1

class ProxyListener:
	# Determine if listener is still running
	isListening = False

	# Not filtering on address for flexability
	def __init__(self, filterConfig):
		# Create debug logging object
		#self.loggingProxyListener = loggingUtils("proxyListener-debug.log")

		self.filter = filterConfig
		self.listener = WinDivert(self.filter)

	def startListener(self):
		try:
			self.listener.open()
			self.isListening = True

		except Exception as e:
			#print "[!] Error starting listener...\n%s" % (e)
			pass

	def stopListener(self):
		try:
			self.listener.close()
			self.isListening = False

		except Exception as e:
			#print "[!] Error stopping listener...\n%s" % (e)
			pass

	def recvPacket(self):
		try:
			self.packet = self.listener.recv()

		except Exception as e:
			#print "[!] Error receiving packet...\n%s" % (e)
			# DEBUG - Log packet to debug log
			#self.loggingProxyListener.logPacket(self.packet, "rsRemote->rsNetworking.py->recvPacket - ERROR")
			pass

	def sendPacket(self):
		try:
			self.listener.send(self.packet, recalculate_checksum=True)

		except Exception as e:
			#print "[!] Error sending packet...\n%s" % (e)
			# DEBUG - Log packet to debug log
			#self.loggingProxyListener.logPacket(self.packet, "rsRemote->rsNetworking.py->sendPacket - ERROR")
			pass

class ProxyHelper:
	def isInitConnection(self, packet):
		self.packet = packet
		only_SYN = False
		null_payload = False
		ack_zero = False

		self.getFlags()

		if (self.flags[0] == 1) and ((self.flags[1]+self.flags[2]+self.flags[3]+self.flags[4]) == 0):
			only_SYN = True

		if (len(self.packet.tcp.payload) == 0):
			null_payload = True

		if (self.packet.tcp.ack_num == 0):
			ack_zero = True

		if (only_SYN and null_payload and ack_zero):
			return True

		else:
			return False

	def getFlags(self):
		self.flags = [0, 0, 0, 0, 0]

		if self.packet.tcp.syn == True:
			self.flags[0] = 1

		if self.packet.tcp.ack == True:
			self.flags[1] = 1

		if self.packet.tcp.psh == True:
			self.flags[2] = 1

		if self.packet.tcp.fin == True:
			self.flags[3] = 1

		if self.packet.tcp.rst == True:
			self.flags[4] = 1
