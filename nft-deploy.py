import os
import subprocess
import sys
import zlib
from ipaddress import IPv4Interface
from pyroute2 import IPRoute
import shutil
import time
from pathlib import Path
import re
from colors import Color as c
from datetime import datetime

def get_default_network():
    with IPRoute() as ipr:
        routes = ipr.get_default_routes(family=2)  # AF_INET / IPv4

        if not routes:
            raise RuntimeError("IPv4-default route not found.")

        route = routes[0]
        attributes = dict(route["attrs"])

        interface_index = attributes.get("RTA_OIF")
        gateway = attributes.get("RTA_GATEWAY")

        if interface_index is None:
            raise RuntimeError(
                f"{c.crimson}Default route has no exit node: {c.bright_red}{route}{c.reset}"
            )

        link = ipr.get_links(interface_index)[0]
        interface_name = dict(link["attrs"])["IFLA_IFNAME"]

        addresses = ipr.get_addr(
            index=interface_index,
            family=2,
        )

        for address in addresses:
            addr_attributes = dict(address["attrs"])
            local_address = addr_attributes.get("IFA_LOCAL")

            if local_address:
                prefix_length = address["prefixlen"]
                interface = IPv4Interface(
                    f"{local_address}/{prefix_length}"
                )

                return {
                    "interface": interface_name,
                    "address": str(interface.ip),
                    "network": str(interface.network),
                    "bits": int(255-int(str(interface.netmask).split(".")[3])),
                    "netmask": str(interface.netmask),
                    "gateway": gateway,
                }

        raise RuntimeError(
            f"{c.crimson}Your {c.light_lime}{interface_name}{c.crimson} does not have a local address.{c.reset}"
        )

class Deployer:
    def __init__(self, args: list):
        self.pwd: str = str(Path(__file__).resolve().parent)
        self.args: list = args
        self.kwargs: list = []
        self.is_dry_run: bool = False
        self.failsafe: str | None = None
        self.config_path: str = "/etc/nftables.conf"
        self.ports: list = []
        self.default_ruleset: str = ""
        self.custom_file: str = ""
        self.dry_run_config: str | Path = "/tmp/nft-deploy/nft-dry-run-rules.conf"
        self.custom_ruleset: str = ""
        self.ruleset: str = ""
        self.comment: str | None = None
        self.compressed_config: bytes = b""
        self.failsafe_timer: float = 60.0
        self.user_home: str | None = os.getenv("HOME")
        self.backup_file: str = "/tmp/nft-deploy/nftables.conf.backup"
        self.ports: list = []
        network = get_default_network()
        self.network: str | int | None | any = network.get("network", "127.0.0.1")
        self.bits: str | int | None | any = network.get("bits", "32")
        self.optimized: str | None = None
        self.tmp_path: str = "/tmp/nft-deploy"
        self.nft = shutil.which("nft")
        if self.nft is None:
            raise FileNotFoundError(f"{c.crimson}nft is not installed.{c.reset}")

        print(f"DEBUG: {self.backup_file}")

    @staticmethod
    def clean_old_backups(
            backup_directory: Path,
            keep: int = 3,
    ) -> None:
        backups = sorted(
            (
                path
                for path in backup_directory.glob(
                "nftables.conf.backup-*"
            )
                if path.is_file() and not path.is_symlink()
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        for old_backup in backups[keep:]:
            try:
                old_backup.unlink()
                print(
                    f"{c.dark_gray}"
                    f"Removed old backup: {old_backup}"
                    f"{c.reset}"
                )
            except OSError as error:
                print(
                    f"{c.crimson}"
                    f"Could not remove old backup "
                    f"{old_backup}: "
                    f"{c.wine_red}{error}"
                    f"{c.reset}"
                )

    def backup_first(self) -> bool:
        backup_directory = Path(self.tmp_path)

        try:
            backup_directory.mkdir(
                mode=0o700,
                parents=True,
                exist_ok=True,
            )

            timestamp = datetime.now().strftime(
                "%d%m%Y-%H%M%S-%f"
            )

            backup_file = (
                    backup_directory
                    / f"nftables.conf.backup-{timestamp}"
            )

            shutil.copy2(
                self.config_path,
                backup_file,
            )

            # Failsafe tarvitsee uusimman backupin polun.
            self.backup_file = str(backup_file)

            self.clean_old_backups(
                backup_directory,
                keep=3,
            )

        except OSError as error:
            print(
                f"{c.crimson}"
                f"Could not create nftables backup: "
                f"{c.wine_red}{error}"
                f"{c.reset}"
            )
            return False

        print(
            f"{c.peach}Peaches{c.reset}. "
            f"Backup created: {backup_file}"
        )

        return True


    def get_default_rules(self):
        ruleset = b'x\xda\x85Q\xcdj\x1c1\x0c\xbe\xfb)\xd4\r\xe4\xd4d\xa04=\x04r\xc81\x87B!O\xe0\xb55\x8c\xba\x1e\xcb\xc8\xda\x9d,a\xdf\xbd\xb2\xa7\x9b\xb4lJ/\xc6\xd6\xf7\'\xc9W\x9f\x86}\x95aKy\xc8\xa3\xc2\xcd\xe8\xae\xe0@\xf3}E\x05\xad\x0f_\xa0.v\xa0\xde;\x03\x9e~\x1c\xbe\x0ev|\x83g\x9aKB\xb8\x86g?"\x8c$\xb8\xf8\x94@\xf6\tMyk\xdc\xef,\x08\xf8\xe2\x1b\xaf\x02e\xe89u\xf2\x82-\xc9o\xad<\x80\xcf\xf1O rx\x07\xcf\xe2\xe1\xd6\xb9\x88U\x85\x8f\xd0!s\xb3\xeeFJ\x8a\xe2.*\xf0\xea\x00\xc2\xe4-\x92r\xd9k\x7f\x03\xe8\xb1\xe0\x9911\xef~\x83E\x88\x85\xf4x\xb6k\xd4\xc2\x89\xc2\x11\xa2pq\xbd\x10\x14\xaazm1\x07\x9f(v\x08\x02\xcf3f\x85\rzI+\x1dx|\xe3\x04\xce\x19\x83\x12\xe7\xba\xf9\xdb\xe5\xd5\x86\xb1\xae\xa9N\x18?\x83`\xb2b<\x81\x0f\x01\x8b\xbe\xdb\xdaBy\x01\x15\x1fv\xf8\x81\x1d\xd1\x98\xfd\x8c\xb0I\xbc\xb9\xd0>\xae\xef\xc4\xc1\xa7\x89\xab~ /6;+\x07N@a.\x97\x16=\xbeA\xab\xa0\xec\xb4\xef\xb0\xdb%\x9aIA\xda4wCEso\x1d\xees\xdb\xae\xe0OK\x82\x85t\xea\xf2\x97u\xf7>\xce\x94o,s\xa2-\xd9\xc0\xebNV\x8d\xddOo\xbf6\xb2,^\xe2\xbf\xfe\xed\x0c\xff\xef\xe7\x9a\xe5\xc9\xb9_\x9bb\xfb\xf8'

        if self.custom_file != "":
            try:
                with open(self.custom_file, "r") as file:
                    custom_ruleset = file.read()
            except Exception as e:
                raise SystemExit(f"Error: {e}")

        self.compressed_config = ruleset
        decompressed = zlib.decompress(self.compressed_config).decode("utf-8")
        return str(decompressed)

    @staticmethod
    def get_promethean_rules():
        basic_ruleset = b'x\xda\xbd\x8e\xddj\xc3 \x1cG\xef\xf7\x14?\xf2\x00m>\x0c\x89\x97i\xbaAG;\xba\x04\xbak\xa7\xae\x0b5\x1a\xd4\x92=\xfe2z\xb1\x91\x12\xe86\x88z#\x9e\xf3?\x02@\xd3\xc11!,\xa2p1\x1c\x12/\xc2e\x9c\xc1\xf3\x0e\xa23\xd6#J2p\x0f\xe7\x99\x97\xd0\xb2\x07\xe3\\v\x1e\xdc\xb4\xad\xd4\x1eAq\xb9\xd7\xbb\xd5\xb2\xdc<\xd4x\xb3\xa6\x852\x9c\xa9\x01\xf7\xbd\xb1\xa7\xe0\x0e\xb7\x95\xf2\xd9Jt\xa6\x12!\xe9L\xa5<\xcc\xe3\x9bR\xc5\xf6P\xfd=C)\x99)\x93\xcc\x93!\xff\xcf|\xcfs\xee\xfdz\x82R\xa6\xffz\x11c:\xa54\x9c\xc0\x1f\xa5\x7f\xb5\xac\xd1\x0e\x9b\xf5=\xaa}y\xe5\x86\xc3\x9a\x90K#\xe4\xc7X\xa0Y\x9aM\xf0/\xcd\xa1z\xba\xf0g\xf1;\xfe\xc7\x87H\x12O\xf0{\xe3\xfc\xd1\xca\xfay;\x96\xa2t\xd8\x13V\xb1\xc2\xda\xf4Z\x19&\xb0c\x9a\x1d\xa5\x85j\xf4\t\x9cu\xfele\x80O_F~\xdd'
        return zlib.decompress(basic_ruleset).decode("utf-8")

    def merge_ruleset(self, ruleset: str, custom_ruleset: str = "", ports: list = []) -> str:
        if custom_ruleset == "":
            custom_ruleset = self.get_promethean_rules()
        new_ruleset = []
        new_lines = []
        user_ports = []
        ruleset = ruleset.split("\n")
        first_line = 0

        print(f"Adding custom ruleset:\n{c.silver}")
        checked = 0
        for i, line in enumerate(ruleset):
            if "pkttype" in line and custom_ruleset != "":
                first_line = int(i) if isinstance(i, int) else 0
                print(f"{c.lime_green}", end="")
                if checked == 0:
                    print("\n    # Begin of custom ruleset")
                    new_ruleset.append("\n    # Begin of custom ruleset")
                    checked = 1
                new_ruleset.append(custom_ruleset)
                print(custom_ruleset)
                if len(self.ports) > 0:
                    # print(f"DEBUG (ports): {self.ports}")
                    print("    # End of custom ruleset\n")
                    new_ruleset.append("    # End of custom ruleset\n")
                    for port in self.ports:
                        if checked == 1:
                            print(f"{c.bright_aqua}", end="")
                            print ("    # Begin of user configured ports")
                            new_ruleset.append("    # Begin of user configured ports")
                            checked = 2
                        user_line = f"    ip saddr {self.network} tcp dport {port} ct state new accept comment \"{self.comment or "User configured new open port"}\""
                        user_ports.append(user_line)
                        new_ruleset.append(user_line)
                        print(user_line)
                    print("    # End of user configured ports\n")
                    new_ruleset.append("    # End of user configured ports\n")

            print(f"{c.silver}", end="")
            print(line)
            new_ruleset.append(line)

        custom_line_count = len(custom_ruleset.splitlines())
        first_line += 1

        new_lines.extend(
            range(first_line, first_line + custom_line_count)
        )

        print(f"{c.reset}", end="")

        print(f"{c.white}Added no. of custom rule lines: {c.bright_aqua}{len(new_lines)}{c.white}, lines: {c.golden_orange}{", ".join(str(x) for x in new_lines)}{c.reset}")
        print(f"{c.deep_purple}Aces!{c.reset}")
        return "\n".join(new_ruleset)

    def check_args(self):
        action = None

        for i, arg in enumerate(self.args[1:], start=1):
            if not arg.startswith("--"):
                continue

            match arg:
                case "--port":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--port needs a value{c.reset}")

                    try:
                        port = int(self.args[i + 1])
                    except ValueError:
                        raise SystemExit(f"{c.crimson}--port needs a numerical value{c.reset}")

                    if not 1 <= port <= 65535:
                        raise SystemExit(f"{c.crimson}--port must be between 1 and 65535{c.reset}")

                    self.ports.append(port)

                case "--comment":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--comment needs a value{c.reset}")

                    self.comment = self.args[i + 1]

                case "--config":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--config needs a filename{c.reset}")

                    self.config_path = self.args[i + 1]

                case "--file":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--file needs a filename{c.reset}")

                    self.custom_file = self.args[i + 1]

                case "--timer":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--timer needs a value{c.reset}")

                    try:
                        self.failsafe_timer = int(self.args[i + 1])
                    except ValueError:
                        raise SystemExit(f"{c.crimson}--timer needs a numerical value{c.reset}")

                case "--deploy":
                    action = "deploy"

                case "--dry-run":
                    action = "dry-run"

                case "--optimize":
                    action = "optimize"

                case "--help":
                    action = "help"

                case _:
                    raise SystemExit(f"Invalid argument: {c.crimson}{arg}")

        match action:
            case "deploy":
                return self.deploy()
            case "dry-run":
                return self.dry_run()
            case "optimize":
                return self.optimize()
            case "help" | None:
                return self.help()
            case _:
                print(f"{c.crimson}This should have never been reached.{c.reset}")
                return 1
        return 0

    def optimize(self):
        if not self.backup_first():
            print(
                f"{c.bright_red}"
                f"Optimizing aborted because backup failed."
                f"{c.reset}"
            )
            return 1

        print(f"{c.white}Optimizing {c.indigo}stuff:{c.reset}")

        program = subprocess.run(
            [
                "sudo",
                self.nft,
                "-c",
                "-o",
                "-f",
                self.config_path,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if program.stdout:
            print(f"{c.golden_orange}Optimized rules:{c.reset}")
            print(program.stdout, end="")
            self.optimized = program.stdout

        if program.stderr:
            print(f"{c.light_gold}Optimization report:{c.reset}")
            print(program.stderr, end="")

        if program.returncode != 0:
            print(
                f"{c.crimson}Optimization failed with return code "
                f"{c.bright_red}{program.returncode}{c.reset}"
            )
            return 1

        return 0

    def test_rules(self, conf_filename: str = "") -> int:
        result = subprocess.run(
            ([] if os.geteuid() == 0 else ["sudo"])
            + [self.nft, "-c", "-f", conf_filename or self.config_path],
            capture_output=True, text=True,
        )
        if result.returncode:
            print(result.stderr or result.stdout or "Ruleset validation failed.")
        else:
            print("Excellent! Clean config file.")
        return result.returncode

    def deploy(self):
        if os.geteuid() != 0:
            print("Deployment requires root. Run this script with sudo.")
            return 1
        if self.failsafe_timer < 0:
            print("Failsafe timer cannot be negative.")
            return 1
        if self.check_env() != 0 or not self.backup_first():
            return 1
        if not self.ruleset:
            self.ruleset = self.merge_ruleset(self.get_default_rules(), self.get_promethean_rules())
        candidate = Path(self.backup_file + ".candidate")
        candidate.write_text(self.ruleset)
        try:
            if self.test_rules(str(candidate)) != 0:
                return 1
            print("Deploying...", flush=True)
            # Start the independent guard before changing the firewall. It waits
            # for EOF so the countdown also starts if the parent exits early.
            guard = self.start_failsafe()
            deployment_ok = False
            try:
                shutil.copyfile(candidate, self.config_path)
                result = subprocess.run(
                    [self.nft, "-f", self.config_path],
                    capture_output=True, text=True, timeout=30,
                )
                deployment_ok = result.returncode == 0
                if not deployment_ok:
                    print(result.stderr or result.stdout or "Deployment failed.")
                    shutil.copyfile(self.backup_file, self.config_path)
            except (OSError, subprocess.SubprocessError) as error:
                print(f"Deployment failed: {error}")
                shutil.copyfile(self.backup_file, self.config_path)
            finally:
                guard.stdin.close()
            if deployment_ok:
                print(f"Configuration saved in {self.config_path}. Failsafe verification continues in the background.", flush=True)
                return 0
            return 1
        finally:
            candidate.unlink(missing_ok=True)

    def dry_run(self) -> int:
        if not self.backup_first():
            print(
                f"{c.bright_red}"
                f"Dry-run detected an error with the backup, but continues still."
                f"{c.reset}"
            )

        if os.path.exists(self.backup_file):
            print(f"Backed up existing config file to: {c.dark_purple}{self.backup_file}{c.reset}")
        else:
            print(f"{c.crimson}Backup failed{c.reset}. Please check your permissions.")
            return 1
        self.ruleset = self.get_default_rules()
        self.custom_ruleset = self.get_promethean_rules()
        self.ruleset = self.merge_ruleset(self.ruleset, self.custom_ruleset)
        print(f"\nWould save it in: {c.amethyst}{self.config_path}{c.reset}\n")
        with open(self.dry_run_config, "w") as f:
            f.write(self.ruleset)
        print(f"Wrote config file to: {c.bright_pink}{self.dry_run_config}{c.reset}")
        passable = self.test_rules(self.dry_run_config)
        if passable != 0:
            print(f"{c.crimson}This was tested and something is really broken, sorry mate.")
            return 1
        return 2

    @staticmethod
    def help():
        print(f"{c.dark_purple}NFT Deployer {c.white}-- {c.deep_purple}failsafe guard for updating nftables configs {c.reset}")
        print()
        print(f"Usage: {c.light_gold}nft-deploy.py {c.bright_green}[options]{c.reset}")
        print("Options:")
        print()
        print(f"  {c.golden_orange}--dry-run: {c.light_gold}Do not actually deploy anything{c.reset}")
        print(f"  {c.golden_orange}--help: {c.light_gold}Show this help message{c.reset}")
        print(f"  {c.golden_orange}--deploy: {c.light_gold}Deploy the default ruleset{c.reset}")
        print(f"  {c.golden_orange}--config: {c.light_gold}Specify your nftables.conf location (default: /etc/nftables.conf){c.reset}")
        print(f"  {c.golden_orange}--file: {c.light_gold}Specify a custom ruleset file{c.reset}")
        print(f"  {c.golden_orange}--port: {c.light_gold}Allow a specific port in the config from your personal local subnet{c.reset}")
        print(f"  {c.golden_orange}--comment: {c.light_gold}Comment to be added into the config file for your ports{c.reset}")
        print(f"  {c.golden_orange}--timer: {c.light_gold}failsafe timer in seconds (default: 60.0 seconds){c.reset}")
        print()
        quit()

    def check_env(self):
        if not os.path.exists(f"{self.pwd}/nft-failsafe.py"):
            return 1
        return 0

    def start_failsafe(self):
        program = subprocess.Popen(
            [sys.executable, "-u", str(Path(self.pwd) / "nft-failsafe.py"),
             str(int(self.failsafe_timer)), self.backup_file,
             "--config", self.config_path, "--wait-for-parent"],
            stdin=subprocess.PIPE,
            start_new_session=True,
        )
        print(f"Failsafe started with PID: {program.pid}", flush=True)
        return program


if __name__ == "__main__":
    process = Deployer(sys.argv)
    result = process.check_args()
    if result == 2:
        print("Dry run finished successfully. No changes were made to the config file.")
        result = 0
    sys.exit(result)
