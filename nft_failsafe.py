import argparse
import math
import os
import re
import shutil
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
        self.errors = None
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
                    color = c.bright_red if seconds <= 2 else c.yellow if seconds <= 4 else c.lime_green
                    self.print_above_prompt(
                        f"{c.gold}Failsafe in {color}{seconds:>3} seconds{c.reset}"
                    )
                time.sleep(min(0.1, remaining))
        finally:
            if previous_second is not None:
                self.print_above_prompt("")

    def check_main_status(self):
        enabled = self.run(["systemctl", "is-enabled", "nftables.service"])
        active = self.run(["systemctl", "is-active", "nftables.service"])
        rules = self.run([self.nft, "list", "ruleset"])
        configured = self.run([self.nft, "-c", "-f", self.config_file])
        loaded = rules.returncode == 0 and bool(rules.stdout.strip())
        configuration_valid = configured.returncode == 0
        try:
            configured_ruleset = Path(self.config_file).read_text()
        except (OSError, UnicodeError) as error:
            configured_ruleset = rules.stdout
            print(
                f"{c.crimson}Could not read configured ruleset "
                f"{self.config_file}: {error}{c.reset}"
            )

        print("Ruleset:")
        print(
            highlight_ruleset(configured_ruleset),
            end="" if configured_ruleset.endswith("\n") else "\n",
        )
        print(f"Ruleset active: {rules.returncode}")

        print(f"{c.white}Systemd service enabled: {c.lime_green if enabled.returncode == 0 else c.crimson}{enabled.stdout.strip().capitalize()}")
        print(f"{c.white}Systemd service active: {c.lime_green if active.returncode == 0 else c.peach}{active.stdout.strip().capitalize()}")
        print(f"{c.white}Nftables ruleset loaded: {c.lime_green if loaded != 0 else c.crimson}{loaded}")
        print(f"{c.white}Configuration valid: {c.lime_green if configuration_valid else c.crimson}{configuration_valid}")
        system_status = (
            enabled.returncode == 0
            and active.returncode == 0
            and loaded
            and configuration_valid
        )

        print(
            f"{c.white}Comprehensive system status: {c.bright_green if system_status else c.crimson}{"Complete" if system_status else "Incomplete"}{c.reset}")
        print()
        # Boot enablement is reported separately from the live firewall state.
        return system_status

    def activate_failsafe(self):
        try:
            self.countdown()
            print("Checking nftables status...", flush=True)
            try:
                if self.simulate_failure:
                    print("SIMULATION: forcing a failed check; firewall state is unchanged.", flush=True)
                    return False
                elif self.check_main_status():
                    return True
            except (OSError, subprocess.SubprocessError) as error:
                print(f"Firewall check failed: {error}", flush=True)
            print(
                f"{c.crimson}nftables is not healthy. Starting automatic rollback.{c.reset}",
                flush=True,
            )
            return self.rollback()
        finally:
            print(
                f"\n{c.white}Press any key to continue...{c.reset}",
                flush=True,
            )

    def rollback(self) -> bool:
        print(f"{c.white}Validating rollback configuration: {c.amethyst}{self.backup_file}{c.reset}", flush=True)
        if self.run([self.nft, "-c", "-f", self.backup_file]).returncode != 0:
            print(f"{c.crimson}Backup verification failed. Automatic rollback was aborted.{c.reset}", flush=True)
            return False

        time.sleep(1)
        print(f"{c.white}Restoring rollback configuration to: {c.coral}{self.config_file}{c.reset}", flush=True)
        try:
            shutil.copyfile(self.backup_file, self.config_file)
        except OSError as error:
            print(f"{c.crimson}Could not restore rollback configuration: {error}{c.reset}", flush=True)
            return False

        time.sleep(1)
        print(f"{c.white}Restarting {c.bright_green}nftables.service{c.reset}...", flush=True)
        restart = self.run(["systemctl", "restart", "nftables.service"])
        if restart.returncode != 0:
            print(f"{c.crimson}nftables restart failed after rollback.{c.reset}", flush=True)
            return False

        time.sleep(1)
        healthy = self.check_main_status()
        if healthy:
            print(f"{c.green}Rollback restored and verified the pre-deployment configuration.{c.reset}", flush=True)
            return True

        print(f"{c.crimson}ERROR:{c.reset} Firewall recovery failed. Manual intervention required.", flush=True)
        return False

    def confirm_rollback(self):
        # Only the foreground command may read input; the background guard
        # must never consume commands meant for the user's shell.
        if not sys.stdin.isatty() or os.tcgetpgrp(sys.stdin.fileno()) != os.getpgrp():
            print("Run the rollback command in the foreground.", flush=True)
            return False
        print(f"{c.white}Backup: {c.amethyst}{self.backup_file}\n{c.white}Restore point: {c.coral}{self.config_file}", flush=True)
        try:
            answer = input(
                f"Do you want to restore the backup and restart {c.bright_green}nftables{c.reset}? [{c.green}y{c.reset}/{c.bright_red}N{c.reset}] "
            ).strip().casefold()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            print("Rollback canceled. No changes were made.", flush=True)
            return False
        return self.rollback()

    def poll(self, codeword=""):
        if codeword.casefold() == "status":
            self.check_main_status()
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
