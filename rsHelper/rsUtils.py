import unicodedata
import re

class packetUtils:
	def pktPrintFlow(self, packet):
		try:
			proto = self.getProtocol(packet.protocol)

		except:
			proto = "N/A"

		return "\r\n\t[SRC] %s:%s --> [DST] %s:%s (%s, %s)" % \
			(packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port, proto, packet.interface)

	def getProtocol(self, pktTuple):
		self.protocols = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 
					 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP", 
					 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS ", 
					 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP"}
		return self.protocols[pktTuple[0]]

class loggingUtils:
	def __init__(self, logName):
		self.logName = logName
		with open(self.logName, "w") as debugFileOut:
			debugFileOut.write("Fresh log file...\r\n")

	def logPacket(self, packet, state):
		self.packet = packet
		self.state = state

		self.getFlags()

		with open(self.logName, "a") as self.dblfd:
			try:
				self.proto = self.getProtocol()

			except:
				self.proto = "N/A"

			try:
				self.dblfd.write("\r\n{PACKET STATE: " + self.state + "}")

				self.dblfd.write("\r\n[SRC] " + self.packet.src_addr + " --> [DST] " \
					+ self.packet.dst_addr + " (" + self.proto + ")")

				self.dblfd.write("\n\tPort-Flow: " + str(self.packet.src_port) + " --> " \
					+ str(self.packet.dst_port))

				if (self.proto == "TCP"):
					self.dblfd.write("\n\tSEQ       : " + str(self.packet.tcp.seq_num))
					self.dblfd.write("\n\tACK       : " + str(self.packet.tcp.ack_num))
					self.dblfd.write("\n\tWindow SZ : " + str(self.packet.tcp.window_size))
					self.dblfd.write("\n\tFlags     : " + self.flags)
					self.dblfd.write("\n\tDirection : " + self.getDirection())
					self.dblfd.write("\n\tPayload SZ: " + str(len(self.packet.tcp.payload)))
					self.dblfd.write("\n\n\tPayload   : " + str(self.cleanPayload()))
					self.dblfd.write("\n\n\tHexString : " + self.getHexString())

				elif self.proto == "UDP":
					self.dblfd.write("\n\tPayload   : " + str(len(self.packet.udp.payload)))
					self.dblfd.write("\n\n\tPayload SZ: " + str(self.cleanPayload()))
					self.dblfd.write("\n\n\tHexString : " + self.getHexString())

			except Exception as e:
				self.dblfd.write("\r\n[! Exception Writing Packet to Log !]: \n%s" % e)

	def getDirection(self):
		if self.packet.direction == 0:
			return "Outbound"

		elif self.packet.direction == 1:
			return "Inbound"

		else:
			return "Unknown ID -", self.packet.direction

	def cleanPayload(self):
		all_chars = (unichr(i) for i in xrange(0x110000))
		control_chars = ''.join(map(unichr, range(0,32) + range(127,160)))
		control_char_re = re.compile('[%s]' % re.escape(control_chars))

		if self.proto == "TCP":
			return control_char_re.sub('', self.packet.tcp.payload)

		elif self.proto == "UDP":
			return control_char_re.sub('', self.packet.udp.payload)

		else:
			return "[?] Payload is not UDP or TCP"

	def getHexString(self):
		return (" ".join(hex(ord(n)) for n in self.packet.tcp.payload)).replace(" ", "\\")

	def getFlags(self):
		self.flags = ""

		if self.packet.tcp.syn == True:
			self.flags += "SYN"

		if self.packet.tcp.ack == True:
			self.flags += "|ACK"

		if self.packet.tcp.psh == True:
			self.flags += "|PSH"

		if self.packet.tcp.fin == True:
			self.flags += "|FIN"

		if self.packet.tcp.rst == True:
			self.flags += "|RST"

		if self.packet.tcp.cwr == True:
			self.flags += "|CWR"

		if self.packet.tcp.ece == True:
			self.flags += "|ECE"

		if self.packet.tcp.ns == True:
			self.flags += "|NS"

		if self.packet.tcp.urg == True:
			self.flags += "|URG"

	def getProtocol(self):
		self.protocols = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP",
					 7: "CBT", 8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP",
					 13: "ARGUS ", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP"}

		return self.protocols[self.packet.protocol[0]]
