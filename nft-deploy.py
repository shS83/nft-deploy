import os
import difflib
import fcntl
import subprocess
import sys
import zlib
from ipaddress import IPv4Interface
from pyroute2 import IPRoute
import shutil
import textwrap
import time
from pathlib import Path
import re
from colors import Color as c
from datetime import datetime
from nft_failsafe import Failsafe
from nft_highlight import highlight_ruleset
from enum import StrEnum

STATUS = ""

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
    class State(StrEnum):
        NONE = "No changes."
        INPUT = "Input chain modified."
        FORWARD = "Forward chain modified."
        OUTPUT = "Output chain modified."

    STATE = [State.NONE]
    global STATUS

    def __init__(self, args: list):
        self.pwd: str = str(Path(__file__).resolve().parent)
        self.args: list = args
        self.STATE = [self.State.NONE]
        self.is_dry_run: bool = False
        self.use_current_rules: bool = False
        self.failsafe: object = None
        self.config_path: str = "/etc/nftables.conf"
        self.ports: list = []
        self.default_ruleset: str = ""
        self.custom_input_files: list[str] = []
        self.custom_forward_files: list[str] = []
        self.custom_output_files: list[str] = []
        self.dry_run_config: str | Path = "/tmp/nft-deploy/nft-dry-run-rules.conf"
        self.custom_ruleset: str = ""
        self.ruleset: str = ""
        self.comment: str | None = None
        self.compressed_config: bytes = b""
        self.failsafe_timer: float = 15.0
        self.user_home: str | None = os.getenv("HOME")
        self.backup_file: str = "/tmp/nft-deploy/nftables.conf.backup"
        self.ports: list = []
        network = get_default_network()
        self.network: str | int | None | any = network.get("network", "127.0.0.1")
        self.bits: str | int | None | any = network.get("bits", "32")
        self.optimized: str | None = None
        self.tmp_path: str = "/tmp/nft-deploy"
        self.lock_fd: int | None = None
        self.lock_transferred: bool = False
        self.nft = shutil.which("nft")
        if self.nft is None:
            raise FileNotFoundError(f"{c.crimson}nft is not installed.{c.reset}")

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

        self.compressed_config = ruleset
        decompressed = zlib.decompress(self.compressed_config).decode("utf-8")
        return str(decompressed)

    def get_base_rules(self) -> str:
        if not self.use_current_rules:
            return self.get_default_rules()
        try:
            return Path(self.config_path).read_text()
        except (OSError, UnicodeError) as error:
            raise SystemExit(
                f"Cannot read current ruleset {self.config_path}: {error}"
            ) from error

    @staticmethod
    def get_promethean_rules():
        basic_ruleset = b'x\xda\xbd\x8e\xddj\xc3 \x1cG\xef\xf7\x14?\xf2\x00m>\x0c\x89\x97i\xbaAG;\xba\x04\xbak\xa7\xae\x0b5\x1a\xd4\x92=\xfe2z\xb1\x91\x12\xe86\x88z#\x9e\xf3?\x02@\xd3\xc11!,\xa2p1\x1c\x12/\xc2e\x9c\xc1\xf3\x0e\xa23\xd6#J2p\x0f\xe7\x99\x97\xd0\xb2\x07\xe3\\v\x1e\xdc\xb4\xad\xd4\x1eAq\xb9\xd7\xbb\xd5\xb2\xdc<\xd4x\xb3\xa6\x852\x9c\xa9\x01\xf7\xbd\xb1\xa7\xe0\x0e\xb7\x95\xf2\xd9Jt\xa6\x12!\xe9L\xa5<\xcc\xe3\x9bR\xc5\xf6P\xfd=C)\x99)\x93\xcc\x93!\xff\xcf|\xcfs\xee\xfdz\x82R\xa6\xffz\x11c:\xa54\x9c\xc0\x1f\xa5\x7f\xb5\xac\xd1\x0e\x9b\xf5=\xaa}y\xe5\x86\xc3\x9a\x90K#\xe4\xc7X\xa0Y\x9aM\xf0/\xcd\xa1z\xba\xf0g\xf1;\xfe\xc7\x87H\x12O\xf0{\xe3\xfc\xd1\xca\xfay;\x96\xa2t\xd8\x13V\xb1\xc2\xda\xf4Z\x19&\xb0c\x9a\x1d\xa5\x85j\xf4\t\x9cu\xfele\x80O_F~\xdd'
        return zlib.decompress(basic_ruleset).decode("utf-8")

    @staticmethod
    def _brace_count(line: str) -> int:
        """Count nft block braces, ignoring comments and quoted strings."""
        count = 0
        quote = None
        escaped = False
        for character in line:
            if escaped:
                escaped = False
                continue
            if quote and character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            elif quote:
                continue
            elif character in ('"', "'"):
                quote = character
            elif character == "#":
                break
            elif character == "{":
                count += 1
            elif character == "}":
                count -= 1
        return count

    @classmethod
    def _find_block(cls, lines: list[str], declaration: re.Pattern) -> tuple[int, int] | None:
        for start, line in enumerate(lines):
            if not declaration.match(line):
                continue
            depth = 0
            opened = False
            for end in range(start, len(lines)):
                change = cls._brace_count(lines[end])
                opened = opened or change > 0
                depth += change
                if opened and depth == 0:
                    return start, end
        return None

    @staticmethod
    def _indent_block(content: str, indent: str) -> list[str]:
        content = textwrap.dedent(content.expandtabs(4).strip("\n"))
        return [indent + line if line else "" for line in content.splitlines()]

    def _rule_files(self, chain: str) -> list[str]:
        files = getattr(self, f"custom_{chain}_files", None)
        if files is not None:
            return list(files)

        # Compatibility for callers that still set the old singular field.
        filename = getattr(self, f"custom_{chain}_file", "")
        return [filename] if filename else []

    def _has_custom_rule_files(self) -> bool:
        return any(self._rule_files(chain) for chain in ("input", "forward", "output"))

    def merge_ruleset(self, ruleset: str, custom_ruleset: str = "", ports: list | None = None) -> str:
        if custom_ruleset == "" and not self._has_custom_rule_files():
            custom_ruleset = self.get_promethean_rules()

        chain_content = {"input": [], "forward": [], "output": []}
        if custom_ruleset.strip() and self.State.INPUT in self.STATE:
            chain_content["input"].append(("custom ruleset", custom_ruleset))

        selected_ports = self.ports if ports is None else ports
        if selected_ports:
            if self.State.NONE in self.STATE:
                self.STATE.remove(self.State.NONE)
            self.STATE.append(self.State.INPUT)
            port_rules = "\n".join(
                f'ip saddr {self.network} tcp dport {port} ct state new accept '
                f'comment "{self.comment or "User configured new open port"}"'
                for port in selected_ports
            )
            chain_content["input"].append(("user configured ports", port_rules))

        for chain in ("input", "forward", "output"):
            for filename in self._rule_files(chain):
                try:
                    file_rules = Path(filename).read_text()
                except (OSError, UnicodeError) as error:
                    raise SystemExit(f"Cannot read custom rules {filename}: {error}") from error
                if file_rules.strip():
                    chain_content[chain].append((f"file {chain} rules", file_rules))

        original_lines = ruleset.splitlines()
        lines = original_lines.copy()
        for chain, blocks in chain_content.items():
            if not blocks:
                continue

            declaration = re.compile(rf"^\s*chain\s+(?:{chain}|[\"']{chain}[\"'])\s*\{{")
            span = self._find_block(lines, declaration)
            if span is None:
                table = self._find_block(
                    lines, re.compile(r"^\s*table\s+inet\s+filter\s*\{")
                )
                policy = "accept" if chain == "output" else "drop"
                new_chain = [
                    f"  chain {chain} {{",
                    f"    type filter hook {chain} priority filter",
                    f"    policy {policy}",
                    "  }",
                ]
                if table is None:
                    if lines and lines[-1].strip():
                        lines.append("")
                    lines.extend(["table inet filter {", *new_chain, "}"])
                else:
                    lines[table[1]:table[1]] = new_chain
                span = self._find_block(lines, declaration)

            opening_line, closing_line = span
            insertion_line = next(
                (
                    line_number
                    for line_number in range(opening_line + 1, closing_line)
                    if re.match(r"^\s*pkttype(?:\s|$)", lines[line_number])
                ),
                closing_line,
            )
            closing_indent = lines[closing_line][:-len(lines[closing_line].lstrip())]
            rule_indent = closing_indent + "  "
            additions = []
            if insertion_line and lines[insertion_line - 1].strip():
                additions.append("")
            for label, content in blocks:
                additions.append(f"{rule_indent}# Begin of {label}")
                additions.extend(self._indent_block(content, rule_indent))
                additions.append(f"{rule_indent}# End of {label}")
            lines[insertion_line:insertion_line] = additions

        result = "\n".join(lines) + ("\n" if ruleset.endswith("\n") else "")
        changed_lines = []
        matcher = difflib.SequenceMatcher(None, original_lines, lines, autojunk=False)
        for operation, _, _, final_start, final_end in matcher.get_opcodes():
            if operation in ("replace", "insert"):
                changed_lines.extend(range(final_start + 1, final_end + 1))

        changed_line_numbers = set(changed_lines)
        print(f"Adding custom ruleset:\n{c.silver}", end="")
        for line_number, line in enumerate(lines, start=1):
            line_color = c.green if line_number in changed_line_numbers else c.silver
            print(
                f"{c.cyan}{line_number:>4}: "
                f"{line_color}{line}{c.reset}"
            )
        print(
            f"{c.white}Number of changed lines: "
            f"{c.bright_green}{len(changed_lines)}{c.white}, lines: "
            f"{c.golden_orange}{', '.join(str(line) for line in changed_lines)}"
            f"{c.reset}"
        )
        print(f"{c.deep_purple}Aces!{c.reset}")
        return result

    def check_args(self):
        action = None
        options_with_values = {
            "--port", "-p", "--comment", "-m", "--config", "-C",
            "--timer", "-t",
            "--input-file", "-I", "--forward-file", "-F",
            "--output-file", "-O",
        }

        for i, arg in enumerate(self.args[1:], start=1):
            if i > 1 and self.args[i - 1] in options_with_values:
                continue
            if not arg.startswith("-"):
                continue

            match arg:
                case "--port" | "-p":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--port needs a value{c.reset}")

                    try:
                        port = int(self.args[i + 1])
                    except ValueError:
                        raise SystemExit(f"{c.crimson}--port needs a numerical value{c.reset}")

                    if not 1 <= port <= 65535:
                        raise SystemExit(f"{c.crimson}--port must be between 1 and 65535{c.reset}")

                    self.ports.append(port)

                case "--comment" | "-m":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--comment needs a value{c.reset}")

                    self.comment = self.args[i + 1]

                case "--config" | "-C":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--config needs a filename{c.reset}")

                    self.config_path = self.args[i + 1]

                case "--input-file" | "-I":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--input-file needs a filename{c.reset}")

                    if self.State.NONE in self.STATE:
                        self.STATE.remove(self.State.NONE)
                    self.STATE.append(self.State.INPUT)
                    self.custom_input_files.append(self.args[i + 1])

                case "--forward-file" | "-F":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--forward-file needs a filename{c.reset}")
                    if self.State.NONE in self.STATE:
                        self.STATE.remove(self.State.NONE)
                    self.STATE.append(self.State.FORWARD)
                    self.custom_forward_files.append(self.args[i + 1])

                case "--output-file" | "-O":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--output-file needs a filename{c.reset}")

                    if self.State.NONE in self.STATE:
                        self.STATE.remove(self.State.NONE)
                    self.STATE.append(self.State.OUTPUT)
                    self.custom_output_files.append(self.args[i + 1])

                case "--timer" | "-t":
                    if i + 1 >= len(self.args):
                        raise SystemExit(f"{c.crimson}--timer needs a value{c.reset}")

                    try:
                        self.failsafe_timer = int(self.args[i + 1])
                    except ValueError:
                        raise SystemExit(f"{c.crimson}--timer needs a numerical value{c.reset}")

                case "--use-current-rules" | "-U":
                    self.use_current_rules = True

                case "--deploy" | "-X":
                    action = "deploy"

                case "--dry-run" | "-D":
                    action = "dry-run"

                case "--optimize":
                    action = "optimize"

                case "--help" | "-h":
                    action = "help"

                case "--status" | "-s":
                    action = "status"

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
            case "status":
                self.failsafe = Failsafe(
                    self.failsafe_timer,
                    self.backup_file,
                    getattr(self, "config_path", "/etc/nftables.conf"),
                )
                self.failsafe.check_main_status()
                return 0
            case _:
                print(f"{c.crimson}This should have never been reached.{c.reset}")
                return 1
        return 0

    def optimize(self) -> int:
        if not self.acquire_deploy_lock():
            return 1
        try:
            return self._optimize_locked()
        finally:
            self.release_deploy_lock()

    def _optimize_locked(self) -> int:
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
            self.optimized = program.stdout
            print(highlight_ruleset(self.optimized), end="")
            if not self.optimized.endswith("\n"):
                print()

        if program.stderr:
            print(f"{c.light_gold}Optimization report:{c.reset}")
            print(program.stderr, end="")

        if program.returncode != 0:
            print(
                f"{c.crimson}Optimization failed with return code "
                f"{c.bright_red}{program.returncode}{c.reset}"
            )
            return 1

        if not self.optimized:
            print(f"{c.crimson}Optimization produced no ruleset.{c.reset}")
            return 1

        optimized_preview = self.optimized.replace("\n", "\n\t").rstrip()
        answer = input(
            f"{c.bright_blue}Optimized changes would be these:\n"
            f"\t{optimized_preview}\n"
            f"Do you want to continue Yes/No? {c.reset}"
        ).strip().lower()
        if answer not in ("yes", "y"):
            print(f"{c.white}Optimization canceled. No changes were made.{c.reset}")
            return 0

        try:
            Path(self.config_path).write_text(self.optimized)
        except (OSError, UnicodeError) as error:
            print(f"{c.crimson}Could not save optimized ruleset: {error}{c.reset}")
            return 1

        print(f"{c.bright_green}Optimized ruleset saved in {self.config_path}.{c.reset}")

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

    def print_change_summary(self, proposed: bool = False) -> None:
        changed_states = [state for state in self.STATE if state != self.State.NONE]
        if not changed_states:
            changed_states = [self.State.NONE]

        # Preserve command-line order but do not print a chain more than once.
        state_names = ", ".join(dict.fromkeys(state.name for state in changed_states))
        action = "proposed to" if proposed else "made to"
        print(
            f"{c.white}Changes were {action} "
            f"{c.bright_green}{state_names}{c.reset}."
        )

    def acquire_deploy_lock(self) -> bool:
        lock_directory = Path(getattr(self, "tmp_path", "/tmp/nft-deploy"))
        lock_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_file = lock_directory / "deploy.lock"
        lock_fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            print(f"{c.crimson}Another deployment or failsafe check is already running.{c.reset}")
            return False

        os.ftruncate(lock_fd, 0)
        os.write(lock_fd, f"{os.getpid()}\n".encode())
        self.lock_fd = lock_fd
        self.lock_transferred = False
        return True

    def release_deploy_lock(self) -> None:
        if getattr(self, "lock_fd", None) is None:
            return
        if not getattr(self, "lock_transferred", False):
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        os.close(self.lock_fd)
        self.lock_fd = None
        self.lock_transferred = False

    def deploy(self) -> int:
        if not self.acquire_deploy_lock():
            return 1
        try:
            return self._deploy_locked()
        finally:
            self.release_deploy_lock()

    def _deploy_locked(self) -> int:
        if os.geteuid() != 0:
            print("Deployment requires root. Run this script with sudo.")
            return 1
        if self.failsafe_timer < 0:
            print("Failsafe timer cannot be negative.")
            return 1
        if self.check_env() != 0:
            return 1
        print(f"{c.white}Validating current configuration before deployment...{c.reset}")
        if self.test_rules(self.config_path) != 0:
            print(
                f"{c.crimson}Deployment aborted: the current configuration "
                f"is not valid, so it cannot be used as a rollback point.{c.reset}"
            )
            return 1
        if not self.backup_first():
            return 1
        if not self.ruleset:
            self.ruleset = self.merge_ruleset(self.get_base_rules())
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
                self.print_change_summary()
                return 0
            return 1
        finally:
            candidate.unlink(missing_ok=True)

    def dry_run(self) -> int:
        if not self.acquire_deploy_lock():
            return 1
        try:
            return self._dry_run_locked()
        finally:
            self.release_deploy_lock()

    def _dry_run_locked(self) -> int:
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
        self.ruleset = self.get_base_rules()
        self.custom_ruleset = ""
        self.ruleset = self.merge_ruleset(self.ruleset, self.custom_ruleset)
        print(f"\nWould save it in: {c.amethyst}{self.config_path}{c.reset}\n")
        with open(self.dry_run_config, "w") as f:
            f.write(self.ruleset)
        print(f"Wrote config file to: {c.bright_pink}{self.dry_run_config}{c.reset}")
        passable = self.test_rules(self.dry_run_config)
        if passable != 0:
            print(f"{c.crimson}This was tested and something is really broken, sorry mate.{c.reset}")
            return 1
        print(f"{c.yellow}Dry run finished successfully.{c.reset}")
        self.print_change_summary(proposed=True)
        print(f"{c.peach_puff}No changes were made to the config file.{c.reset}")
        return 0

    @staticmethod
    def help():
        print(f"{c.dark_purple}NFT Deployer {c.white}-- {c.deep_purple}failsafe guard for updating nftables configs {c.reset}")
        print()
        print(f"Usage: {c.light_gold}nft-deploy.py {c.bright_green}[options]{c.reset}")
        print("Options:")
        print()
        print(f"  {c.golden_orange}--dry-run, -D: {c.light_gold}Do not actually deploy anything{c.reset}")
        print(f"  {c.golden_orange}--help, -h: {c.light_gold}Show this help message{c.reset}")
        print(f"  {c.golden_orange}--deploy, -X: {c.light_gold}Deploy the selected ruleset{c.reset}")
        print(f"  {c.golden_orange}--config, -C: {c.light_gold}Specify your nftables.conf location (default: /etc/nftables.conf){c.reset}")
        print(f"  {c.golden_orange}--use-current-rules, -U: {c.light_gold}Use the current config as the base ruleset{c.reset}")
        print(f"  {c.golden_orange}--input-file, -I: {c.light_gold}Append input-chain rules from a file; may be repeated{c.reset}")
        print(f"  {c.golden_orange}--forward-file, -F: {c.light_gold}Append forward-chain rules from a file; may be repeated{c.reset}")
        print(f"  {c.golden_orange}--output-file, -O: {c.light_gold}Append output-chain rules from a file; may be repeated{c.reset}")
        print(f"  {c.golden_orange}--port, -p: {c.light_gold}Allow a specific port in the config input chain from your personal local subnet{c.reset}")
        print(f"  {c.golden_orange}--comment, -m: {c.light_gold}Comment to be added into the config file for your ports{c.reset}")
        print(f"  {c.golden_orange}--timer, -t: {c.light_gold}failsafe timer in seconds (default: 15.0 seconds){c.reset}")
        print(f"  {c.golden_orange}--status, -s: {c.light_gold}Show system status{c.reset}")

        print()
        quit()

    def check_env(self):
        if not os.path.exists(f"{self.pwd}/nft_failsafe.py"):
            return 1
        return 0

    def start_failsafe(self):
        terminal_fd = None
        sudo_tty = os.environ.get("SUDO_TTY")
        try:
            if sudo_tty:
                # sudo's own PTY may disappear when the deployer exits.
                # Open the original terminal without acquiring it as a
                # controlling terminal or truncating a non-terminal path.
                try:
                    terminal_fd = os.open(
                        sudo_tty, os.O_WRONLY | os.O_NOCTTY | os.O_NOFOLLOW,
                    )
                    if not os.isatty(terminal_fd):
                        raise OSError("SUDO_TTY does not point to a terminal")
                except OSError as error:
                    raise SystemExit(
                        f"Cannot open failsafe terminal {sudo_tty}: {error}. "
                        "Deployment aborted before changing the firewall."
                    ) from error
            command = [
                sys.executable, "-u", str(Path(self.pwd) / "nft_failsafe.py"),
                str(int(self.failsafe_timer)), self.backup_file,
                "--config", self.config_path, "--wait-for-parent",
            ]
            lock_fd = getattr(self, "lock_fd", None)
            pass_fds = ()
            if lock_fd is not None:
                command.extend(["--lock-fd", str(lock_fd)])
                pass_fds = (lock_fd,)

            program = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=terminal_fd,
                stderr=terminal_fd,
                start_new_session=True,
                pass_fds=pass_fds,
            )
            if lock_fd is not None:
                self.lock_transferred = True
        finally:
            if terminal_fd is not None:
                os.close(terminal_fd)
        print(f"Failsafe started with PID: {program.pid}", flush=True)
        return program


if __name__ == "__main__":
    process = Deployer(sys.argv)
    result = process.check_args()
    sys.exit(result)
