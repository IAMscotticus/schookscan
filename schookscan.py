#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import os

# === ANSI Colors ===
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"

TARGET_FILE = "ipaddr.txt"
LOG_DIR = "scan_logs"
os.makedirs(LOG_DIR, exist_ok=True)

# === NMAP COMMANDS ===
NMAP_COMMANDS = [
    ["nmap", "-Pn", "-vv", "-T2", "-p21,22,23,25,80,443,10443,8443",
     "-iL", TARGET_FILE, "-oX", "rnd1.xml", "--open"],

    ["nmap", "-Pn", "-vv", "-sU", "--top-ports", "30",
     "-iL", TARGET_FILE, "-oX", "udp-nmap.xml", "--open"],

    ["nmap", "-Pn", "-vv", "-T4", "--min-rate", "150", "-p0-65535",
     "-iL", TARGET_FILE, "-oX", "full-nmap.xml", "--open"]
]

# === Command Runner ===
def run_command(cmd, log_file=None):
    print(f"{BLUE}[+] Executing:{RESET} {' '.join(cmd)}")
    with open(log_file, "w") if log_file else subprocess.DEVNULL as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)

# === Tool Execution Helpers ===

def run_nikto(target, port):
    log_file = os.path.join(LOG_DIR, f"nikto_{target}_{port}.log")
    print(f"{GREEN}[+] Running Nikto on {target}:{port}{RESET} (log: {log_file})")
    run_command(["nikto", "-h", target, "-p", str(port)], log_file)

def run_feroxbuster(target, ssl=False):
    url = f"https://{target}" if ssl else f"http://{target}"
    log_file = os.path.join(LOG_DIR, f"feroxbuster_{target}.log")
    print(f"{GREEN}[+] Running Feroxbuster on {url}{RESET} (log: {log_file})")
    run_command([
        "/opt/feroxbuster",
        "-u", url,
        "-w", "/usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt",
        "-x", "php,html,txt",
        "-C", "400,403,404"
    ], log_file)

def run_snmp_tools(target):
    print(f"{YELLOW}[+] SNMP detected on {target}{RESET}")
