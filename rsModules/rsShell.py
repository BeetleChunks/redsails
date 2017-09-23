import subprocess

class rsShell():
	def __init__(self, payload):
		self.payload = payload
		self.execute()

	def execute(self):
		shCmdList = [i for i in (self.payload.strip()).split(" ")]
		
		try:
			proc = subprocess.Popen(shCmdList,\
									stdout=subprocess.PIPE,\
									universal_newlines=True)

			self.response = proc.stdout.read()
		except Exception as e:
			self.response = "%s" % (e)
