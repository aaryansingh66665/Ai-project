"""
Nmap Network Scanner & XML/Text Parser Tool for CyberAgent X.
Supports live execution via local nmap binary, structured XML parsing,
and offline ingestion of pre-existing scan files (.xml / .nmap).
"""

import os
import re
import sys
import shutil
import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional

# Force UTF-8 encoding on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


logger = logging.getLogger("CyberAgent.NmapScanner")

# Standard Windows and Unix Nmap paths
COMMON_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Tools\nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/homebrew/bin/nmap",
]


class NmapScanner:
    """Performs network reconnaissance and parses Nmap outputs."""

    def __init__(self):
        self.binary_path = self._detect_nmap_binary()

    def _detect_nmap_binary(self) -> Optional[str]:
        """Detects nmap executable on system PATH or default directories."""
        # 1. Check system PATH
        path_binary = shutil.which("nmap")
        if path_binary:
            return path_binary

        # 2. Check common installation directories
        for p in COMMON_NMAP_PATHS:
            if os.path.isfile(p):
                return p

        return None

    def is_available(self) -> bool:
        """Returns True if local Nmap binary is detected."""
        return self.binary_path is not None and os.path.exists(self.binary_path)

    def get_binary_info(self) -> Dict[str, Any]:
        """Returns installation status and version information."""
        if not self.is_available():
            return {
                "available": False,
                "path": None,
                "version": None,
                "message": "Nmap executable not found. Live scanning disabled. Offline XML/text log parsing is active.",
            }

        try:
            res = subprocess.run([self.binary_path, "-V"], capture_output=True, text=True, timeout=5)
            version_line = res.stdout.splitlines()[0] if res.stdout else "Nmap (version unknown)"
            return {
                "available": True,
                "path": self.binary_path,
                "version": version_line.strip(),
                "message": "Nmap is ready for live local and network scans.",
            }
        except Exception as e:
            return {
                "available": True,
                "path": self.binary_path,
                "version": "Error reading version",
                "error": str(e),
            }

    def scan(
        self,
        target: str,
        profile: str = "standard",
        custom_args: Optional[str] = None,
        timeout_seconds: int = 180,
    ) -> Dict[str, Any]:
        """
        Executes a live Nmap scan and returns structured JSON analysis.
        Profiles:
            - 'quick': -sV -T4 -F (Top 100 ports + service detection)
            - 'standard': -sV -sC -T4 (Default scripts + versioning)
            - 'vuln': -sV --script=vulners,vuln -T4 (Vulnerability and CVE scripts)
            - 'full': -sV -sC -p- -T4 (All 65535 ports)
            - 'custom': Uses `custom_args`
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "Nmap executable is not installed on this host. Use offline log upload or install Nmap (winget install Insecure.Nmap).",
                "target": target,
                "hosts": [],
            }

        # Determine arguments
        if profile == "quick":
            args = ["-sV", "-T4", "-F"]
        elif profile == "vuln":
            args = ["-sV", "--script=vulners,vuln", "-T4"]
        elif profile == "full":
            args = ["-sV", "-sC", "-p-", "-T4"]
        elif profile == "custom" and custom_args:
            args = [a.strip() for a in custom_args.split() if a.strip()]
        else:  # standard default
            args = ["-sV", "-sC", "-T4"]

        # Ensure XML output to stdout is requested
        full_command = [self.binary_path] + args + ["-oX", "-", target]

        logger.info(f"Executing Nmap scan: {' '.join(full_command)}")

        try:
            res = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            if res.returncode != 0 and not res.stdout:
                return {
                    "success": False,
                    "exit_code": res.returncode,
                    "error": res.stderr.strip() or f"Scan failed with exit code {res.returncode}",
                    "target": target,
                    "raw_stdout": res.stdout,
                }

            parsed = self.parse_nmap_xml(res.stdout)
            parsed["success"] = True
            parsed["target"] = target
            parsed["profile"] = profile
            parsed["command"] = " ".join(full_command)
            parsed["raw_stderr"] = res.stderr.strip()
            return parsed

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Nmap scan timed out after {timeout_seconds} seconds.",
                "target": target,
                "profile": profile,
            }
        except Exception as e:
            logger.error(f"Nmap scan execution error: {e}")
            return {
                "success": False,
                "error": str(e),
                "target": target,
            }

    def parse_nmap_xml(self, xml_content: str) -> Dict[str, Any]:
        """Parses Nmap XML output string into structured JSON."""
        if not xml_content or not xml_content.strip():
            return {"hosts": [], "total_hosts": 0, "up_hosts": 0, "open_ports_count": 0}

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as e:
            logger.warning(f"XML parse error, attempting fallback text parser: {e}")
            return self.parse_nmap_text(xml_content)

        hosts = []
        total_open_ports = 0

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            status = status_elem.get("state") if status_elem is not None else "unknown"
            if status != "up":
                continue

            # Addresses (IPv4, IPv6, MAC)
            ip_address = ""
            mac_address = ""
            vendor = ""
            for addr in host_elem.findall("address"):
                addr_type = addr.get("addrtype", "")
                if addr_type in ["ipv4", "ipv6"]:
                    ip_address = addr.get("addr", "")
                elif addr_type == "mac":
                    mac_address = addr.get("addr", "")
                    vendor = addr.get("vendor", "")

            # Hostnames
            hostnames = []
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                for hn in hostnames_elem.findall("hostname"):
                    name = hn.get("name")
                    if name:
                        hostnames.append(name)

            # OS Detection
            os_matches = []
            os_elem = host_elem.find("os")
            if os_elem is not None:
                for osm in os_elem.findall("osmatch"):
                    os_matches.append({
                        "name": osm.get("name", ""),
                        "accuracy": osm.get("accuracy", "0"),
                    })

            # Ports & Services
            ports = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "closed") if state_elem is not None else "closed"

                    if state != "open":
                        continue

                    total_open_ports += 1

                    # Service details
                    service_elem = port_elem.find("service")
                    service_info = {
                        "name": "unknown",
                        "product": "",
                        "version": "",
                        "extrainfo": "",
                        "cpe": [],
                    }
                    if service_elem is not None:
                        service_info["name"] = service_elem.get("name", "unknown")
                        service_info["product"] = service_elem.get("product", "")
                        service_info["version"] = service_elem.get("version", "")
                        service_info["extrainfo"] = service_elem.get("extrainfo", "")
                        for cpe in service_elem.findall("cpe"):
                            if cpe.text:
                                service_info["cpe"].append(cpe.text)

                    # NSE Scripts output
                    scripts = {}
                    for script in port_elem.findall("script"):
                        s_id = script.get("id", "")
                        s_out = script.get("output", "")
                        if s_id:
                            scripts[s_id] = s_out.strip()

                    ports.append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service_info["name"],
                        "product": service_info["product"],
                        "version": service_info["version"],
                        "extrainfo": service_info["extrainfo"],
                        "cpe": service_info["cpe"],
                        "scripts": scripts,
                    })

            hosts.append({
                "ip": ip_address,
                "hostnames": hostnames,
                "mac": mac_address,
                "vendor": vendor,
                "os_matches": os_matches,
                "ports": ports,
                "open_ports_count": len(ports),
            })

        return {
            "hosts": hosts,
            "total_hosts": len(hosts),
            "up_hosts": len(hosts),
            "open_ports_count": total_open_ports,
        }

    def parse_nmap_text(self, text_content: str) -> Dict[str, Any]:
        """Fallback regex parser for standard terminal Nmap output files (.nmap)."""
        hosts = []
        current_host = None
        port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([\w\-\?]+)(?:\s+(.*))?$")
        ip_pattern = re.compile(r"Nmap scan report for (?:([\w\.-]+) \()?([0-9a-fA-F\.:]+)\)?")

        for line in text_content.splitlines():
            line_str = line.strip()

            # Detect Host
            host_match = ip_pattern.search(line_str)
            if host_match:
                hostname = host_match.group(1) or ""
                ip = host_match.group(2) or ""
                current_host = {
                    "ip": ip,
                    "hostnames": [hostname] if hostname else [],
                    "mac": "",
                    "vendor": "",
                    "os_matches": [],
                    "ports": [],
                    "open_ports_count": 0,
                }
                hosts.append(current_host)
                continue

            # Detect Port Line
            if current_host:
                port_match = port_pattern.match(line_str)
                if port_match:
                    port_num = int(port_match.group(1))
                    proto = port_match.group(2)
                    state = port_match.group(3)
                    service = port_match.group(4)
                    version_info = port_match.group(5) or ""

                    if state == "open":
                        current_host["ports"].append({
                            "port": port_num,
                            "protocol": proto,
                            "state": state,
                            "service": service,
                            "product": version_info,
                            "version": "",
                            "extrainfo": "",
                            "cpe": [],
                            "scripts": {},
                        })
                        current_host["open_ports_count"] += 1

        total_open = sum(h["open_ports_count"] for h in hosts)
        return {
            "hosts": hosts,
            "total_hosts": len(hosts),
            "up_hosts": len(hosts),
            "open_ports_count": total_open,
        }

    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Reads and parses an Nmap scan file from disk (XML or standard text)."""
        path = Path(file_path)
        if not path.exists():
            return {"success": False, "error": f"File not found: {file_path}"}

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if path.suffix.lower() == ".xml" or "<nmaprun" in content:
                res = self.parse_nmap_xml(content)
            else:
                res = self.parse_nmap_text(content)

            res["success"] = True
            res["filename"] = path.name
            return res
        except Exception as e:
            return {"success": False, "error": f"Failed to parse {path.name}: {str(e)}"}


# Singleton instance
nmap_scanner = NmapScanner()


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="CyberAgent X - Nmap Scanner & Parser Tool")
    parser.add_argument("target", nargs="?", default=None, help="Target IP, domain or subnet to scan")
    parser.add_argument("--profile", default="standard", choices=["quick", "standard", "vuln", "full", "custom"], help="Scan profile")
    parser.add_argument("--args", dest="custom_args", default=None, help="Custom Nmap arguments")
    parser.add_argument("--file", help="Path to Nmap .xml or .nmap scan log to parse")

    parsed_args = parser.parse_args()

    print("=" * 70)
    print("⚡ CYBERAGENT X - NMAP RECONNAISSANCE SCANNER & PARSER TOOL")
    print("=" * 70)

    # 1. Check Binary Status
    info = nmap_scanner.get_binary_info()
    print(f"• Nmap Binary: {'[INSTALLED]' if info['available'] else '[NOT FOUND]'}")
    if info['available']:
        print(f"  Path: {info['path']}")
        print(f"  Version: {info['version']}")
    else:
        print(f"  Message: {info['message']}")
    print("-" * 70)

    # 2. Parse file if provided
    if parsed_args.file:
        print(f"Parsing scan file: {parsed_args.file}...")
        res = nmap_scanner.parse_file(parsed_args.file)
        print(json.dumps(res, indent=2))
        sys.exit(0)

    # 3. If target provided, attempt scan or simulation
    if parsed_args.target:
        print(f"Executing scan against target: {parsed_args.target} (Profile: {parsed_args.profile})...")
        res = nmap_scanner.scan(parsed_args.target, profile=parsed_args.profile, custom_args=parsed_args.custom_args)
        print(json.dumps(res, indent=2))
        sys.exit(0)

    # 4. Default Demo / Self-Test
    print("Running self-test demonstration with sample XML scan data...")
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" version="7.94">
      <host>
        <status state="up"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames><hostname name="localhost"/></hostnames>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4.49"/>
            <script id="http-title" output="CyberAgent Web Studio"/>
            <script id="vulners" output="CVE-2021-41773: Path Traversal and Remote Code Execution"/>
          </port>
          <port protocol="tcp" portid="11434">
            <state state="open"/>
            <service name="http" product="Ollama Local LLM Service" version="0.6.2"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    test_result = nmap_scanner.parse_nmap_xml(sample_xml)
    print(f"✔ Discovered {test_result['total_hosts']} host(s) and {test_result['open_ports_count']} open port(s):")
    for h in test_result["hosts"]:
        print(f"  • Host: {h['ip']} ({', '.join(h['hostnames'])})")
        for p in h["ports"]:
            print(f"    - Port {p['port']}/{p['protocol']}: {p['service']} | {p['product']} {p['version']}")
            if p.get("scripts"):
                for s_id, s_out in p["scripts"].items():
                    print(f"      [NSE {s_id}]: {s_out}")
    print("=" * 70)
    print("Ready for integration with CyberAgent X Multi-Agent Swarm!")

