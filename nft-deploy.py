import os
import subprocess
import sys
import zlib
import psutil
from ipaddress import IPv4Interface
from pyroute2 import IPRoute
import shutil

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
                f"Default route has no exit node: {route}"
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
            f"Your {interface_name} does not have a local address."
        )

class Deployer:
    def __init__(self, args: list):
        self.pwd: str = os.getcwd()
        self.args: list = args
        self.kwargs: list = []
        self.is_dry_run: bool = False
        self.failsafe: str | None = None
        self.config_path: str = "/etc/nftables.conf"
        self.ports: list = []
        self.default_ruleset: str = ""
        self.custom_file: str = ""
        self.custom_ruleset: str = ""
        self.ruleset: str = ""
        self.comment: str | None = None
        self.compressed_config: bytes = b""
        self.failsafe_timer: float = 6.0
        self.backup_file = ""
        self.user_home = os.getenv("HOME")
        self.backup_file = f"{self.user_home}/nftables.conf.backup"
        network = get_default_network()
        self.network = network.get("network", "127.0.0.1")
        self.bits = network.get("bits", "32")
        program = subprocess.Popen(["which", "nft"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = program.communicate()
        if program.returncode != 0:
            print(f"Errors: {stderr}')")

        self.nft = stdout.replace("\n", "")
        print(f"DEBUG: {self.backup_file}")

    def backup_first(self):
        try:
            shutil.copy("/etc/nftables.conf", self.backup_file)
        except (FileNotFoundError or psutil.AccessDenied or ValueError or EnvironmentError) as error:
            print(f"Error: {error}")
        print("\033[1;38mPeaches\033[0m.")

    def get_default_rules(self):
        ruleset = b'x\xda\x85Q\xcdj\x1c1\x0c\xbe\xfb)\xd4\r\xe4\xd4d\xa04=\x04r\xc81\x87B!O\xe0\xb55\x8c\xba\x1e\xcb\xc8\xda\x9d,a\xdf\xbd\xb2\xa7\x9b\xb4lJ/\xc6\xd6\xf7\'\xc9W\x9f\x86}\x95aKy\xc8\xa3\xc2\xcd\xe8\xae\xe0@\xf3}E\x05\xad\x0f_\xa0.v\xa0\xde;\x03\x9e~\x1c\xbe\x0ev|\x83g\x9aKB\xb8\x86g?"\x8c$\xb8\xf8\x94@\xf6\tMyk\xdc\xef,\x08\xf8\xe2\x1b\xaf\x02e\xe89u\xf2\x82-\xc9o\xad<\x80\xcf\xf1O rx\x07\xcf\xe2\xe1\xd6\xb9\x88U\x85\x8f\xd0!s\xb3\xeeFJ\x8a\xe2.*\xf0\xea\x00\xc2\xe4-\x92r\xd9k\x7f\x03\xe8\xb1\xe0\x9911\xef~\x83E\x88\x85\xf4x\xb6k\xd4\xc2\x89\xc2\x11\xa2pq\xbd\x10\x14\xaazm1\x07\x9f(v\x08\x02\xcf3f\x85\rzI+\x1dx|\xe3\x04\xce\x19\x83\x12\xe7\xba\xf9\xdb\xe5\xd5\x86\xb1\xae\xa9N\x18?\x83`\xb2b<\x81\x0f\x01\x8b\xbe\xdb\xdaBy\x01\x15\x1fv\xf8\x81\x1d\xd1\x98\xfd\x8c\xb0I\xbc\xb9\xd0>\xae\xef\xc4\xc1\xa7\x89\xab~ /6;+\x07N@a.\x97\x16=\xbeA\xab\xa0\xec\xb4\xef\xb0\xdb%\x9aIA\xda4wCEso\x1d\xees\xdb\xae\xe0OK\x82\x85t\xea\xf2\x97u\xf7>\xce\x94o,s\xa2-\xd9\xc0\xebNV\x8d\xddOo\xbf6\xb2,^\xe2\xbf\xfe\xed\x0c\xff\xef\xe7\x9a\xe5\xc9\xb9_\x9bb\xfb\xf8'
        custom_ruleset = self.get_promethean_rules()
        userconfig = []
        if custom_ruleset != "":
            # self.ruleset = self.merge_ruleset(str(zlib.decompress(ruleset).decode("utf-8")), custom_ruleset)
            if len(self.ports) > 0:
                userconfig = [f"ip saddr {self.network}/{self.bits} tcp dport {port} ct state new accept comment \"{"User configured new open port" or self.comment}\"" for port in self.ports]
                self.ruleset = self.merge_ruleset(self.ruleset, "\n".join(userconfig))

        self.compressed_config = ruleset
        decompressed = zlib.decompress(self.compressed_config).decode("utf-8")
        return str(decompressed)

    @staticmethod
    def get_promethean_rules():
        basic_ruleset = b'x\xda\xbd\x8e\xddj\xc3 \x1cG\xef\xf7\x14?\xf2\x00m>\x0c\x89\x97i\xbaAG;\xba\x04\xbak\xa7\xae\x0b5\x1a\xd4\x92=\xfe2z\xb1\x91\x12\xe86\x88z#\x9e\xf3?\x02@\xd3\xc11!,\xa2p1\x1c\x12/\xc2e\x9c\xc1\xf3\x0e\xa23\xd6#J2p\x0f\xe7\x99\x97\xd0\xb2\x07\xe3\\v\x1e\xdc\xb4\xad\xd4\x1eAq\xb9\xd7\xbb\xd5\xb2\xdc<\xd4x\xb3\xa6\x852\x9c\xa9\x01\xf7\xbd\xb1\xa7\xe0\x0e\xb7\x95\xf2\xd9Jt\xa6\x12!\xe9L\xa5<\xcc\xe3\x9bR\xc5\xf6P\xfd=C)\x99)\x93\xcc\x93!\xff\xcf|\xcfs\xee\xfdz\x82R\xa6\xffz\x11c:\xa54\x9c\xc0\x1f\xa5\x7f\xb5\xac\xd1\x0e\x9b\xf5=\xaa}y\xe5\x86\xc3\x9a\x90K#\xe4\xc7X\xa0Y\x9aM\xf0/\xcd\xa1z\xba\xf0g\xf1;\xfe\xc7\x87H\x12O\xf0{\xe3\xfc\xd1\xca\xfay;\x96\xa2t\xd8\x13V\xb1\xc2\xda\xf4Z\x19&\xb0c\x9a\x1d\xa5\x85j\xf4\t\x9cu\xfele\x80O_F~\xdd'
        return zlib.decompress(basic_ruleset).decode("utf-8")

    def merge_ruleset(self, ruleset: str, custom_ruleset: str="") -> str:
        if custom_ruleset == "":
            custom_ruleset = self.get_promethean_rules()
        new_ruleset = []
        ruleset = ruleset.split("\n")
        for i, line in enumerate(ruleset):
            if "pkttype" in line and custom_ruleset != "":

                new_ruleset.append(custom_ruleset)
                userconfig = "".join([f"    ip saddr {self.network} tcp dport {port} ct state new accept comment \"{"User configured new open port" or self.comment}\"\n" for port in self.ports])
                new_ruleset.append(userconfig.rstrip())
            new_ruleset.append(line)
        new_ruleset = str("\n".join(new_ruleset))
        print("\033[1;39mAces!\033[0m")
        print(f"Adding custom rules to line {i}:\n{"".join(new_ruleset)}\n")
        return "".join(new_ruleset)


    def check_args(self):

        for i, arg in enumerate(sys.argv[1:], start=1):
            if not arg.startswith("--"):
                continue
            match arg:
                case "--dry-run":
                    self.is_dry_run = True
                    return self.dry_run()
                case "--help":
                    return self.help()
                case "--deploy":
                    return self.deploy()
                case "--config":
                    self.config_path = self.args[i + 1]
                case "--file":
                    self.custom_file = self.args[i + 1]
                    try:
                        if os.path.exists(self.custom_file):
                            with open(self.custom_file, "r") as file:
                                self.custom_ruleset = file.read()
                    except Exception as e:
                        raise SystemExit(f"Error: {e}")
                case "--allowport":
                    if i + 1 < len(self.args) and self.args[i + 1].isdigit():
                        self.ports.append(str(self.args[i + 1]))
                case "--timer":
                    if i + 1 < len(self.args) and self.args[i + 1]:
                        try:
                            self.failsafe_timer = int(self.args[i + 1])
                        except ValueError:
                            raise SystemExit("--timer needs a numerical value")
                case "--comment":
                    if i + 1 < len(self.args):
                        self.comment = self.args[i + 1]
                case "--optimize":
                    print("Optimizing \033[1;31mstuff\033[0m")
                    program = subprocess.Popen(["sudo", self.nft, "-c", "-o", "-f", self.config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    print("self.config_path: ", self.config_path)
                    print("self.nft: ", self.nft)
                    stdout, stderr = program.communicate()
                    print(stdout)
                case _:
                    print("Invalid arguments")
                    self.help()

    def test_rules(self, conf_filename: str = "") -> int:
        errors = []
        if not conf_filename:
            conf_filename = self.config_path

        print(f"Executable {self.nft} will be ran as root.")
        try:
            program = subprocess.Popen(["sudo", self.nft, "-c -f", conf_filename or self.config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            program.wait(timeout=10)
            stdout, stderr = program.communicate()
            if stdout != "":
                errors = stderr or "Misconfigured config file"
                print(f"You have an error:\n{stdout}")
                print(f"DEBUG: {stderr}")
                raise RuntimeError(f"Your config file is misconfigured:\n{stdout}")
            else:
                print("Excellent! Clean config file.")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
            match error:
                case psutil.NoSuchProcess:
                    print(f"No such process has failed: {error.__str__}")
                case psutil.AccessDenied:
                    print(f"Permission problem {error.__str__}")
                case _:
                    print("This should never have been reached.")
            print(f"DEBUG: {"\n".join(errors)}")
            print(program.returncode)
        return 0

    def deploy(self):
        if self.ruleset == "":
            self.ruleset = self.get_default_rules()
            self.custom_ruleset = self.get_promethean_rules()
            self.ruleset = self.merge_ruleset(self.ruleset, self.custom_ruleset)
        print(f"Deploying with {self.config_path}...")
        print(f"Deploying following ruleset: \n{self.ruleset}")
        with open("/tmp/nftables.conf", "w") as f:
            f.write(self.ruleset)
        passable = self.test_rules("/tmp/nftables.conf")
        if passable != 0:
            print("This was tested and something is really broken, sorry mate.")
            return 1
        program = subprocess.Popen(["sudo", self.nft, "-f", "-c", "/tmp/nftables.conf"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("Deploying...")
        stdout, stderr = program.communicate(timeout=10)
        if len(stdout.strip()) > 0:
            print(stdout)
            print(stderr)
        if program.returncode != 0:
            print("Something went wrong, sorry mate.")
        program = subprocess.Popen(["sudo", "cp", "-v", "/tmp/nftables.conf", "/etc/nftables.conf"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = program.communicate(timeout=10)
        if len(stdout.strip()) > 0:
            print(stdout)
            print(stderr)
        if program.returncode != 0:
            print("Something went wrong, sorry mate.")
        print("Done. New configuration can be found in /etc/nftables.conf.")
        print("I've been \033[1;31mdeployed\033[0m.")
        return 0

    def dry_run(self) -> int:
        self.ruleset = self.get_default_rules()
        self.custom_ruleset = self.get_promethean_rules()
        self.ruleset = self.merge_ruleset(self.ruleset, self.custom_ruleset)
        print(f"\nWould save it in: \033[1;33m{self.config_path}\033[0m\nNow saving it in /tmp/nft-dry-run-rules.conf")
        with open("/tmp/nft-dry-run-rules.conf", "w") as f:
            f.write(self.ruleset)
        passable = self.test_rules("/tmp/nft-dry-run-rules.conf")
        if passable != 0:
            print("This was tested and something is really broken, sorry mate.")
            return 1
        return 0

    @staticmethod
    def help():
        print("Usage: nft-deploy.py [options]")
        print("Options:")
        print()
        print("  --dry-run: Do not actually deploy anything")
        print("  --help: Show this help message")
        print("  --deploy: Deploy the default ruleset")
        print("  --config: Specify your nftables.conf location (default: /etc/nftables.conf)")
        print("  --file: Specify a custom ruleset file")
        print("  --allowport: Allow a specific port in the config from your personal local subnet")
        print("  --comment: Comment to be added into the config file for your ports")
        print("  --timer: failsafe timer in seconds (default: 60.0 seconds)")
        print()
        quit()

    def check_env(self):
        if not os.path.exists(f"{self.pwd}/nft-failsafe.py"):
            return 1
        return 0

    def main(self):
        error: object
        result = self.check_env()
        matches = []

        if result != 0:
            return 1

        setsid = subprocess.Popen(["which", "setsid"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = setsid.communicate(timeout=1)
        setsid = stdout.strip()
        print(f"SETSID: {setsid}")
        python3 = subprocess.Popen(["which", "python3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = python3.communicate(timeout=1)
        python3 = stdout.strip()
        print(f"PYTHON3: {python3}")
        print(f"PWD: {self.pwd}")
        failsafe = [setsid, python3, os.path.join(self.pwd, 'nft-failsafe.py'), str(int(self.failsafe_timer)), self.backup_file]
        program = subprocess.Popen(failsafe, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = program.communicate()
        if "Aces." not in stdout:
            print(errors:="Failsafe didn't start")
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmdline = proc.info["cmdline"] or []

                if "nft-failsafe" in proc.info["name"] or any("nft-failsafe" in argument for argument in cmdline):
                    print(f"Failsafe successfully started as {proc.pid}")
                    matches.append({"pid": proc.pid, "name": proc.info["name"], "cmdline": proc.info["cmdline"]})

            except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                match error:
                    case psutil.NoSuchProcess:
                        print(f"Failsafe has failed: {error.__str__}")
                        return 1
                    case psutil.AccessDenied:
                        print(f"Permission problem {error.__str__}")
                        return 1
                    case _:
                        print("This should never have been reached.")
                        return 1
        return 0

if __name__ == "__main__":
    arguments = sys.argv
    process = Deployer(arguments)
    if len(arguments) > 1:
        print("Starting...")
        process.check_args()
        process.main()

    if str(process).isdigit():
        sys.exit(1)

    sys.exit(0)
