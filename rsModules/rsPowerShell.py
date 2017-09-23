import subprocess
import os

from base64 import b64encode

class rsPowerShell():
	def __init__(self, payload):
		self.payload = payload
		self.execute()

	def execute(self, input=None):
		try:
			os.environ["PROGRAMFILES(X86)"]
			psCmdList = ["%SystemRoot%\\SysNative\\WindowsPowerShell\\v1.0\\PowerShell.exe", "-EncodedCommand"]

		except:
			psCmdList = ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "-EncodedCommand"]
		
		psCmdList.append(b64encode((self.payload.strip()).encode('UTF-16LE')))
		
		try:
			proc = subprocess.Popen(psCmdList,\
									stdout=subprocess.PIPE,\
									stderr=subprocess.PIPE,\
									shell=True,\
									universal_newlines=True)

			self.response = proc.stdout.read()

		except Exception as e:
			self.response = "%s" % (e)
