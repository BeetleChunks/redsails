# Custom modules
from rsHelper.rsUtils import *
from rsNetworking import ProxyListener, ProxyHelper
import sys
class ProxyHandler:
	def __init__(self, proxyDict, connectionDict):
		# Define constants
		self.OUTBOUND = 0
		self.INBOUND = 1
		self.LOOPBACK_IPV4 = "127.0.0.1"
		self.LOOPBACK_INTERFACE = (1L, 0L)

		# After implementing TCP Validation checking, we need
		# to move these stateful configs to the connection records
		# to allow multiple connections per running instance - later :)
		self.STATEFUL_INTERNAL_IP = "0.0.0.0"
		self.STATEFUL_INTERFACE = (11L, 0L)

		self.port = proxyDict["PORT"]
		self.service = proxyDict["SERVICE"]

		self.attackerIPv4 = connectionDict["attackerIPv4"]

		# Create debug logging object
		#self.loggingPRXY = loggingUtils(self.service+"-proxy-debug.log")

		# Build WinDivert packet filter
		self.buildFilter()

		# Start proxy handler
		self.handleProxy()

	def handleProxy(self):
		if self.service == "rdp":
			self.rdpProxy()

		elif self.service == "smb":
			self.smbProxy()

		else:
			print "\n[!] Invalid proxy configuration defined...terminating!"
			print "\tService:", self.service
			print "\tPort:   ", self.port
			return 1

	def rdpProxy(self):
		# Start listener on given port
		self.listenerPRXY = ProxyListener(self.filter)
		self.listenerPRXY.startListener()

		# Enable for debugging from the command line
		#print "[+] RDP Proxy handler started..."

		while self.listenerPRXY.isListening == True:
			# Get diverted packet
			self.listenerPRXY.recvPacket()

			# Create a local instance of the packet
			self.packet = self.listenerPRXY.packet

			# Check if packet valid for proxying
			#	1) Is it from our attacker defind IPv4
			#	2) Is it loopback thats part of our spoofed connection
			#
			#	NOTE: We are not check if the source port because the
			#		  filter mitigates us getting packets from Loopback
			#		  that arent src port == service port
			if self.packet.src_addr == self.attackerIPv4:
				# Update internal target IP and Interface used (could have multiple)
				self.STATEFUL_INTERNAL_IP = self.packet.dst_addr
				self.STATEFUL_INTERFACE = self.packet.interface

				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "INBOUND from Attacker")

				# Modify packet with spoofed data
				self.inboundToLoopbackMod()

				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "MODIFIED - INBOUND from Attacker")

				# Forward packet
				self.listenerPRXY.sendPacket()

			elif self.packet.src_addr == self.LOOPBACK_IPV4:
				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "LOOPBACK from Target")

				# Need to implement SEQ/ACK validation for stability
				#self.validateTcpSeqAck()

				# Modify packet with attacker/target addressing and interface
				self.loopbackToOutboundMod()

				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "MODIFIED - LOOPBACK from Target")

				# Forward packet
				self.listenerPRXY.sendPacket()

	def smbProxy(self):
		# Start listener on given port
		self.listenerPRXY = ProxyListener(self.filter)
		self.listenerPRXY.startListener()

		# Enable for debugging from the command line
		#print "[+] SMB Proxy handler started..."

		while self.listenerPRXY.isListening == True:
			# Get diverted packet
			self.listenerPRXY.recvPacket()

			# Create a local instance of the packet
			self.packet = self.listenerPRXY.packet

			# Check if packet valid for proxying
			#	1) Is it from our attacker defind IPv4
			#	2) Is it loopback thats part of our spoofed connection
			#
			#	NOTE: We are not check if the source port because the
			#		  filter mitigates us getting packets from Loopback
			#		  that arent src port == service port
			if self.packet.src_addr == self.attackerIPv4:
				# Update internal target IP and Interface used (could have multiple)
				self.STATEFUL_INTERNAL_IP = self.packet.dst_addr
				self.STATEFUL_INTERFACE = self.packet.interface

				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "INBOUND from Attacker")

				# Modify packet with spoofed data
				self.inboundToLoopbackMod()

				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "MODIFIED - INBOUND from Attacker")

				# Forward packet
				self.listenerPRXY.sendPacket()

			elif self.packet.src_addr == self.LOOPBACK_IPV4:
				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "LOOPBACK from Target")

				# Need to implement SEQ/ACK validation for stability
				#self.validateTcpSeqAck()

				# Modify packet with attacker/target addressing and interface
				self.loopbackToOutboundMod()

				# DEBUG - Log packet to debug log
				#self.loggingPRXY.logPacket(self.packet, "MODIFIED - LOOPBACK from Target")

				# Forward packet
				self.listenerPRXY.sendPacket()

	def buildFilter(self):
		self.filter = ( "("
							"ip.SrcAddr == "+self.attackerIPv4+" "
								"and "
							"tcp.DstPort == "+str(self.port)+
						") "
							"or "
						"("
							"ip.DstAddr == "+self.LOOPBACK_IPV4+" "
								"and "
							"tcp.SrcPort == "+str(self.port)+
						")" )

	def inboundToLoopbackMod(self):
		# Modify packet src and dst IPs to Loopback IP
		self.packet.dst_addr = self.LOOPBACK_IPV4
		self.packet.src_addr = self.LOOPBACK_IPV4

		# Change packet to the loopback interface
		self.packet.interface = self.LOOPBACK_INTERFACE

		# Change packet direction to OUTBOUND
		self.packet.direction = self.OUTBOUND

	def loopbackToOutboundMod(self):
		# Modify packet src and dst IPs from Loopback IP
		self.packet.dst_addr = self.attackerIPv4
		self.packet.src_addr = self.STATEFUL_INTERNAL_IP

		# Change packet from the Loopback interface to original
		self.packet.interface = self.STATEFUL_INTERFACE

		# Change packet direction to OUTBOUND (Just to be sure)
		self.packet.direction = self.OUTBOUND

