import argparse
import math
import os
import re
import shutil
import shlex
from pathlib import Path
import subprocess
import sys
import time
from colors import Color as c
from nft_highlight import highlight_ruleset

class Failsafe:
    def __init__(self, failsafe_timer, backupfile, config_file="/etc/nftables.conf", simulate_failure=False):
        self.simulate_failure = simulate_failure
        self.timer = failsafe_timer
        self.backup_file = backupfile
        self.config_file = config_file
        self.nft = shutil.which("nft")
        if not self.nft and not simulate_failure:
            raise RuntimeError("nft executable not found")

    def run(self, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode and result.stderr:
            print(result.stderr.strip(), flush=True)
        return result

    def print_above_prompt(self, text: str) -> None:
        # A single write keeps cursor movement and drawing together. DEC save /
        # restore also preserves the user's current terminal text attributes.
        if not sys.stdout.isatty() or os.environ.get("TERM") == "dumb":
            if text:
                print(text, flush=True)
            return
        try:
            fd = sys.stdout.fileno()
            columns, rows = os.get_terminal_size(fd)
            plain = re.sub(r"\x1b\[[0-9;]*m", "", text)
            width = 30
            # Leave the last column unused to avoid wrapping / scrolling.
            if columns <= width or rows < 2 or len(plain) > width:
                return
            column = columns - width
            padding = " " * (width - len(plain))
            frame = f"\0337\033[{rows};{column}H{text}{padding}\0338"
            os.write(fd, frame.encode("utf-8"))
        except OSError:
            # A closed terminal must not prevent the firewall check.
            return

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

        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                seconds = math.ceil(remaining)
                if seconds < 10 and seconds != previous_second:
                    previous_second = seconds
                    symbol = symbols[7 - seconds] if 1 <= seconds <= 7 else ""
                    symbol_color = c.bright_red if seconds <= 2 else c.yellow if seconds <= 4 else c.lime_green
                    self.print_above_prompt(
                        f"{c.gold}Failsafe in {seconds:>3} seconds "
                        f"{symbol_color}{symbol}{c.reset}"
                    )
                time.sleep(min(0.1, remaining))
        finally:
            if previous_second is not None:
                self.print_above_prompt("")

    def check_main_status(self):
        enabled = self.run(["systemctl", "is-enabled", "nftables.service"])
        active = self.run(["systemctl", "is-active", "nftables.service"])
        rules = self.run([self.nft, "list", "ruleset"])
        loaded = rules.returncode == 0 and bool(rules.stdout.strip())
        print(f"Ruleset: {highlight_ruleset(rules.stdout)}")
        print(f"Ruleset active: {rules.returncode}")

        print(f"{c.white}Systemd service enabled: {c.lime_green if enabled.returncode == 0 else c.crimson}{enabled.stdout.strip().capitalize()}")
        print(f"{c.white}Systemd service active: {c.lime_green if active.returncode == 0 else c.crimson}{active.stdout.strip().capitalize()}")
        print(f"{c.white}Nftables ruleset loaded: {c.lime_green if loaded != 0 else c.crimson}{loaded}")
        print(
            f"{c.white}Comprehensive system status: {c.bright_green}{"Complete" if active.returncode == 0 and loaded else "INCOMPLETE"}{c.reset}")

        # Boot enablement is reported separately from the live firewall state.
        return active.returncode == 0 and loaded

    def activate_failsafe(self):
        self.countdown()
        print("Checking nftables status...", flush=True)
        try:
            if self.simulate_failure:
                print("SIMULATION: forcing a failed check; firewall state is unchanged.", flush=True)
            elif self.check_main_status():
                return True
        except (OSError, subprocess.SubprocessError) as error:
            print(f"Firewall check failed: {error}", flush=True)
        command = shlex.join([
            "sudo", str(Path(__file__).resolve().with_name("nft-failsafe")),
            "--rollback", "--backup", str(Path(self.backup_file).resolve()),
            "--config", str(Path(self.config_file).resolve()),
        ])
        print(
            "nftables is not active or rules could not be verified.\n"
            "You can restore the backup by running the following command:\n"
            f"{command}", flush=True,
        )
        return False

    def confirm_rollback(self):
        # Only the foreground command may read input; the background guard
        # must never consume commands meant for the user's shell.
        if not sys.stdin.isatty() or os.tcgetpgrp(sys.stdin.fileno()) != os.getpgrp():
            print("Run the rollback command in the foreground.", flush=True)
            return False
        print(f"Backup: {self.backup_file}\nRestore point: {self.config_file}", flush=True)
        try:
            answer = input(
                "Do you want to restore the backup and restart nftables? [y/N] "
            ).strip().casefold()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            print("Rollback canceled. No changes were made.", flush=True)
            return False
        # Validate the backup before replacing the current configuration.
        if self.run([self.nft, "-c", "-f", self.backup_file]).returncode != 0:
            print("Backup verification failed. No rollback was done.", flush=True)
            return False
        print(f"Restoring backup: {self.backup_file}", flush=True)
        shutil.copyfile(self.backup_file, self.config_file)
        restored = self.run([self.nft, "-f", self.config_file])
        restart = self.run(["systemctl", "restart", "nftables.service"])
        healthy = self.check_main_status()
        if restored.returncode == 0 and restart.returncode == 0 and healthy:
            print("Backup restored and firewall verified.", flush=True)
            return True
        print("ERROR: Firewall recovery failed. Manual intervention required.", flush=True)
        return False

    def poll(self, codeword=""):
        if codeword.casefold() == "foo":
            return "bar"
        elif codeword.casefold() == "ken sent me":
            print(f"{c.red_orange}remember protection{c.reset}")
            return True
        return True if self.errors is None else False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("timer", type=int, nargs="?", default=0)
    parser.add_argument("backup_file", nargs="?")
    parser.add_argument("--backup", help="Backup file to restore")
    parser.add_argument("--config", default="/etc/nftables.conf")
    parser.add_argument("--wait-for-parent", action="store_true")
    parser.add_argument("--rollback", action="store_true", help="Confirm backup restoration in the foreground")
    parser.add_argument("--simulate-failure", action="store_true", help="Simulate a failed check without changing the firewall")
    args = parser.parse_args()
    if args.rollback and args.simulate_failure:
        parser.error("--rollback cannot be combined with --simulate-failure")
    if args.rollback and args.wait_for_parent:
        parser.error("--rollback cannot be combined with --wait-for-parent")
    backup_file = args.backup or args.backup_file
    if not backup_file:
        parser.error("Specify the backup file with --backup FILE")
    if args.timer < 0:
        parser.error("Failsafe timer cannot be negative")
    if os.geteuid() != 0 and not args.simulate_failure:
        parser.error("Failsafe requires root privileges; run the deployer with sudo")
    try:
        failsafe = Failsafe(args.timer, backup_file, args.config, simulate_failure=args.simulate_failure)
        if args.rollback:
            return 0 if failsafe.confirm_rollback() else 1
        if args.wait_for_parent:
            sys.stdin.buffer.read()
        return 0 if failsafe.activate_failsafe() else 1
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Failsafe failed: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
