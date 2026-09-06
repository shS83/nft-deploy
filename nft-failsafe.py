import time
import sys
import psutil
import subprocess
import shutil

class Failsafe(object):
	def __init__(self, failsafe_timer: int, command: str="echo 'Win'", backup_file: str="/tmp/nftables.conf.backup") -> None:
		self.backup_file = backup_file
		self.timer = failsafe_timer
		self.command = command
		self.config_file = "/etc/nftables.conf"
		self.errors: object | None = None
		print("Aces.")
		print("Initialized failsafe...")
		program = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
		stdout, stderr = program.communicate(timeout=1)

	def activate_failsafe(self) -> bool:
		print(f"Activating failsafe in {self.timer} seconds...")
		time.sleep(int(self.timer))
		print("Failsafe activated. Checking process status...")
		status, error = self.check_main_status()
		if not status:
			print(f"Failed with: \033[1;34m{error}\033[0m")
			return False
		return True

	def check_main_status(self) -> tuple[bool, str]:
		rerun = 0
		if rerun != 0:
			print("The process is still running. Trying to kill it again.")
		if rerun > 1:
			print("Too many retries. Aborting...")
			return False, "too many retries"
		for process in psutil.process_iter(["pid", "name", "cmdline"]):
			if (process.info["name"] == "nft-deploy.py" or process.info["name"] == "python3"):
				print(f"Process {process.pid} is running with status {process.status()}")
				# print("This is highly unexpected.")
				#print("Killing the process: ", end="")
				# program = subprocess.Popen(["kill", "-9", process.pid])
				# returncode = program.wait()
				# if process.pid in psutil.process_iter(["pid"]):
				#	rerun += 1
				#	print("Alive?!")
				#	self.check_main_status()
				# print("Dead.")
				# return False, "Process hung"
		program = subprocess.Popen(["systemctl", "status", "nftables"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
		stdout, stderr = program.communicate(timeout=5)
		if not "enabled" in stdout:
			print("The process is not running. Trying to restart it.")
			program = subprocess.Popen(["systemctl", "restart", "nftables.service"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
			program = subprocess.Popen(["systemctl", "status", "nftables"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
			stdout, stderr = program.communicate(timeout=1)

			if "failed" in stdout:
				print("Something is deeply wrong. Copying old backup back to revitalize nftables.")
				status = self.reroll_backup(self.backup_file)
				status = 0
				if status == 1:
					return False, "Could not copy backup back to place. Please attend to your system yourself."
				elif status == 0:
					return False, "Mythical \033[1;36mepic\033[0m error with configuration. Please use proper syntax."
			if "enabled" in stdout:
				print("The process is running. That's a relief")
		return True, "Everything went smoothly as a penguin's fur on a hot day."

	def reroll_backup(self, backupfile) -> int:
		print(f"Rerolling {backupfile} (therefore needing sudo password):")
		program = subprocess.Popen(["sudo", "cp", "-v", backupfile, "/etc/nftables.conf"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = program.communicate()
		print(f"STDOUT: {stdout}")
		return 0


	def poll(self, codeword=""):
		if codeword == "foo":
			return "bar"
		return True if self.errors is None else False


if __name__ == "__main__":
	print("\033[0;32mPING\033[0m")
	if len(sys.argv) > 0:
		if (timer := sys.argv[1]).isdigit():
			backup_file = sys.argv[2]
		else:
			backup_file = "/tmp/nftables.conf.backup"
		failsafe = Failsafe(failsafe_timer=int(timer), command="echo [failsafe] DONG!", backup_file=backup_file)
		failsafe.activate_failsafe()

	sys.exit(0)