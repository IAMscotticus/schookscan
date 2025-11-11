#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import os

# ANSI color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"

TARGET_FILE = "ipaddr.txt"
LOG_DIR = "scan_logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Nmap commands
NMAP_COMMANDS = [
    ["nmap", "-Pn", "-vv", "-T2", "-p21,22,23,25,80,443,10443,8443", "-iL", TARGET_FILE, "-oX", "rnd1.xml", "--open"],
    ["nmap", "-Pn", "-vv", "-sU", "--top-ports", "30", "-iL", TARGET_FILE, "-oX", "udp-nmap.xml", "--open"],
    ["nmap", "-Pn", "-vv", "-T4", "--min-rate", "150", "-p0-65535", "-iL", TARGET_FILE, "-oX", "full-nmap.xml", "--open"]
]

def run_command(cmd, log_file=None):
    print(f"{BLUE}[+] Executing:{RESET} {' '.join(cmd)}")
    with open(log_file, "w") if log_file else subprocess.DEVNULL as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)

# Service-based actions
def run_nikto(target):
    log_file = os.path.join(LOG_DIR, f"nikto_{target}.log")
    print(f"{GREEN}[+] Running Nikto on {target}{RESET} (log: {log_file})")
    run_command(["nikto", "-h", target], log_file)

def run_feroxbuster(target, ssl=False):
    url = f"https://{target}" if ssl else f"http://{target}"
    log_file = os.path.join(LOG_DIR, f"feroxbuster_{target}.log")
    print(f"{GREEN}[+] Running Feroxbuster on {url}{RESET} (log: {log_file})")
    run_command([
        "/opt/feroxbuster", "-u", url,
        "-w", "/usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt",
        "-x", "php,html,txt",
        "-C", "400,403,404"
    ], log_file)

def run_snmp_tools(target):
    print(f"{YELLOW}[+] SNMP detected on {target}{RESET}")
    log_file1 = os.path.join(LOG_DIR, f"onesixtyone_{target}.log")
    log_file2 = os.path.join(LOG_DIR, f"snmpwalk_{target}.log")
    print(f"    {BLUE}-> Running onesixtyone{RESET} (log: {log_file1})")
    run_command(["onesixtyone", target], log_file1)
    print(f"    {BLUE}-> Running snmpwalk{RESET} (log: {log_file2})")
    run_command(["snmpwalk", "-v2c", "-c", "public", target], log_file2)

def run_smb_tools(target):
    log_file = os.path.join(LOG_DIR, f"netexec_{target}.log")
    print(f"{YELLOW}[+] SMB detected on {target}{RESET} -> {BLUE}Running NetExec{RESET} (log: {log_file})")
    run_command(["netexec", "smb", target, "-u", "", "-p", ""], log_file)

def run_ike_scan(target):
    log_file = os.path.join(LOG_DIR, f"ike-scan_{target}.log")
    print(f"{GREEN}[+] Running ike-scan on {target}{RESET} (log: {log_file})")
    run_command(["ike-scan", target], log_file)

# Parse XML and return ports and services per host
def parse_ports_and_services(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    host_data = {}
    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")
        if ip not in host_data:
            host_data[ip] = {"tcp": [], "udp": [], "services": set()}
        for port in host.findall(".//port"):
            state = port.find("state").get("state")
            proto = port.get("protocol")
            portid = port.get("portid")
            if state == "open" or (proto == "tcp" and state == "open"):
                service_elem = port.find("service")
                if service_elem is not None:
                    host_data[ip]["services"].add(service_elem.get("name"))
                if proto == "tcp":
                    host_data[ip]["tcp"].append(portid)
                elif proto == "udp" and state == "open":  # exclude open|filtered
                    host_data[ip]["udp"].append(portid)
    return host_data

def main():
    print(f"{GREEN}[*] Starting Nmap scans...{RESET}")
    for idx, cmd in enumerate(NMAP_COMMANDS, start=1):
        print(f"\n{BLUE}[+] Round {idx}:{RESET} Running Nmap scan...")
        run_command(cmd, os.path.join(LOG_DIR, f"nmap_round{idx}.log"))

    # Aggregate ports and services
    all_hosts = {}
    for xml_file in ["rnd1.xml", "udp-nmap.xml", "full-nmap.xml"]:
        if os.path.exists(xml_file):
            data = parse_ports_and_services(xml_file)
            for ip, info in data.items():
                if ip not in all_hosts:
                    all_hosts[ip] = {"tcp": set(), "udp": set(), "services": set()}
                all_hosts[ip]["tcp"].update(info["tcp"])
                all_hosts[ip]["udp"].update(info["udp"])
                all_hosts[ip]["services"].update(info["services"])

    # Print detected ports per host
    print(f"\n{GREEN}[*] Detected ports per host:{RESET}")
    for ip, info in all_hosts.items():
        tcp_ports = " ".join(f"{p}/tcp" for p in sorted(info["tcp"]))
        udp_ports = " ".join(f"{p}/udp" for p in sorted(info["udp"]))
        print(f"{YELLOW}{ip}{RESET}")
        if tcp_ports:
            print(f"    {tcp_ports}")
        if udp_ports:
            print(f"    {udp_ports}")

    # Trigger tools based on services and ports
    for ip, info in all_hosts.items():
        print(f"\n{BLUE}[+] Processing host {ip}...{RESET}")
        services = info["services"]
        if "http" in services or "https" in services:
            print(f"    {GREEN}-> Web ports detected, running Nikto and Feroxbuster{RESET}")
            run_nikto(ip)
            run_feroxbuster(ip, ssl="https" in services)
        if "snmp" in services:
            run_snmp_tools(ip)
        if "microsoft-ds" in services or "smb" in services:
            run_smb_tools(ip)
        if "500" in info["udp"]:  # IKE port
            print(f"    {GREEN}-> IKE port detected, running ike-scan{RESET}")
            run_ike_scan(ip)

    print(f"\n{GREEN}[*] All scans and actions completed.{RESET} Logs saved in: {LOG_DIR}")

if __name__ == "__main__":
    main()
