import time
import sys
import psutil
import subprocess
import shutil
import math
from colors import Color as c

class Failsafe(object):
	def __init__(self, failsafe_timer: int, command: str="touch /tmp/ken_sent_me", backupfile: str ="/tmp/nftables.conf.backup") -> None:
		self.backup_file = backupfile
		self.timer = failsafe_timer
		self.command = command
		self.config_file = "/etc/nftables.conf"
		self.errors: object | None = None
		self.nft = shutil.which("nft")
		if self.nft is None:
			raise SystemExit(
				f"{c.crimson}Error: nft executable not found.{c.reset}"
			)
		print("Aces.")
		print("Initialized failsafe...")
		program = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
		stdout, stderr = program.communicate(timeout=1)

	def print_above_prompt(self, text: str) -> None:
		self.errors = False
		print(
			"\033[s"  # Save current cursor position
			# "\033[1A"  # Move one line up
			"\r"  # Move to beginning of line
			"\033[2K"  # Clear entire line
			f"{text}"
			"\033[u",  # Restore cursor position
			end="",
			flush=True,
		)

	def countdown(self, override_timer: int | None = None) -> None:
		duration = (
			override_timer
			if override_timer is not None
			else self.timer
		)

		if duration < 0:
			raise ValueError(
				"Countdown duration cannot be negative"
			)

		symbols = ("♹", "♸", "♷", "♶", "♵", "♴", "♳")
		deadline = time.monotonic() + duration
		previous_second = None

		while True:
			remaining = deadline - time.monotonic()

			if remaining <= 0:
				break

			seconds = math.ceil(remaining)

			# Päivitetään terminaali vain sekunnin vaihtuessa.
			if seconds != previous_second:
				previous_second = seconds

				symbol = (
					symbols[7 - seconds]
					if 1 <= seconds <= 7
					else ""
				)

				self.print_above_prompt(
					f"{c.gold}Failsafe in {seconds:>3} seconds "
					f"{c.peach}{symbol}{c.reset}"
				)

			time.sleep(min(0.1, remaining))

		self.print_above_prompt(
			f"{c.deep_purple}Failsafe activated! ⚛{c.reset}"
		)

	def activate_failsafe(self) -> bool:
		print(f"Activating failsafe in {self.timer} seconds... ", end="")
		time.sleep(2)
		print(self.timer)
		self.countdown(int(self.timer))
		print()
		print("Failsafe activated. Checking process status...")
		status, error = self.check_main_status()
		if not status:
			print(f"{c.white}Failed with: {c.crimson}{error}{c.reset}")
			return False
		return True

	def check_main_status(self) -> tuple[bool, str]:
		rerun = 0
		if rerun != 0:
			print(f"{c.yellow}The process is still running. Trying to kill it again.{c.reset}")
		if rerun > 1:
			print(f"{c.crimson}Too many retries. Aborting...{c.reset}")
			return False, "Too many retries"
		for process in psutil.process_iter(["pid", "name", "cmdline"]):
			if (process.info["name"] == "nft-deploy.py" or process.info["name"] == "python3"):
				print(f"Process {c.bright_pink}{process.pid}{c.reset} is running with status {c.caramel}{process.status()}")

		enabled = subprocess.run(
			[
				"systemctl",
				"is-enabled",
				"--quiet",
				"nftables.service",
			],
		).returncode == 0

		service_active = subprocess.run(
			[
				"systemctl",
				"is-active",
				"--quiet",
				"nftables.service",
			],
		).returncode == 0

		ruleset_result = subprocess.run(["sudo", self.nft, "list", "ruleset"], capture_output=True, text=True)

		ruleset_active = (
				ruleset_result.returncode == 0
				and "table inet filter" in ruleset_result.stdout
		)
		print(f"Ruleset: {ruleset_result.stdout}")
		print(f"Ruleset active: {ruleset_result.returncode}")

		print(f"{c.white}Systemd service enabled: {c.lime_green if enabled else c.crimson}{enabled}")
		print(f"{c.white}Systemd service active: {c.lime_green if service_active else c.crimson}{service_active}")
		print(f"{c.white}Nftables ruleset loaded: {c.lime_green if ruleset_active else c.crimson}{ruleset_active}")
		print(f"{c.white}Comprehensive system status: {c.bright_green}{service_active and ruleset_active and enabled}{c.reset}")

		if not enabled:
			print("The process is not running. Trying to restart it.")
			program = subprocess.Popen(["systemctl", "restart", "nftables.service"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
			program = subprocess.Popen(["systemctl", "status", "nftables.service"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
			stdout, stderr = program.communicate(timeout=1)

			if "failed" in stdout:
				print("Something is deeply wrong. Copying old backup back to revitalize nftables.")
				status = self.reroll_backup(self.backup_file)
				if status == 1:
					return False, "Could not copy backup back to place. Please attend to your system yourself."
				elif status == 0:
					return False, f"Mythical {c.indigo}epic{c.reset} error with configuration. Please use proper syntax."
			if "enabled" in stdout:
				print("The process is running. That's a relief")
		return True, "Everything went smoothly as a penguin's fur on a hot day."

	def reroll_backup(self, backupfile) -> int:
		print(f"Rerolling {backupfile} (therefore needing sudo password):")
		program = subprocess.Popen(["sudo", "cp", "-vb", self.backup_file, "/etc/nftables.conf"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		stdout, stderr = program.communicate()
		print(f"STDOUT: {stdout}")
		return 0


	def poll(self, codeword=""):
		if codeword.casefold() == "foo":
			return "bar"
		elif codeword.casefold() == "ken sent me":
			print(f"{c.red_orange}remember protection{c.reset}")
			return True

		return True if self.errors is None else False


if __name__ == "__main__":
	print(f"{c.light_salmon}PING{c.reset}")
	if len(sys.argv) > 0:
		if (timer := sys.argv[1]).isdigit():
			backup_file = sys.argv[2]
		else:
			backup_file = "/tmp/nftables.conf.backup"
		failsafe = Failsafe(failsafe_timer=int(timer), command="echo [failsafe] DONG!", backupfile=backup_file)
		failsafe.activate_failsafe()

	sys.exit(0)