"""
Vulnerability Correlation & 8-Step Risk Assessment Engine for CyberAgent X.

Implements the user-specified 8-stage vulnerability enrichment pipeline:

  [1] Nmap / Scan Ingestion
          ↓
  [2] Product + Version Normalization
          ↓
  [3] CPE (Common Platform Enumeration 2.3) Normalization
          ↓
  [4] Multi-Source CVE Matching (NVD, Vulners, GHSA, Rapid7, ExploitDB)
          ↓
  [5] CVSS v3.1 / v3.0 / v2.0 Scoring & Vector Extraction
          ↓
  [6] CISA KEV (Known Exploited Vulnerabilities) Verification
          ↓
  [7] Exploit Availability Assessment (ExploitDB, Metasploit, PoCs)
          ↓
  [8] Explainable Confidence Scoring (0-100% & Tier Rating)
"""

import re
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from tools.threat_intel_fetcher import threat_intel_fetcher, ThreatIntelResult
from core.mission_state import VulnerabilityRecord, ServiceRecord

logger = logging.getLogger("CyberAgent.VulnCorrelator")

# Common product to CPE vendor/product lookup dictionary
PRODUCT_CPE_MAP = {
    # Web & Reverse Proxies / Gateways / App Servers
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "apache tomcat": ("apache", "tomcat"),
    "traffic server": ("apache", "traffic_server"),
    "apache traffic server": ("apache", "traffic_server"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    "haproxy": ("haproxy", "haproxy"),
    "traefik": ("traefik", "traefik"),
    "envoy": ("envoyproxy", "envoy"),
    "squid": ("squid-cache", "squid"),
    "varnish": ("varnish_software", "varnish_cache"),
    "varnish cache": ("varnish_software", "varnish_cache"),
    "kong": ("konghq", "kong"),
    "kong gateway": ("konghq", "kong"),
    "jetty": ("eclipse", "jetty"),
    "eclipse jetty": ("eclipse", "jetty"),
    "glassfish": ("oracle", "glassfish_server"),
    "weblogic": ("oracle", "weblogic_server"),
    "oracle weblogic": ("oracle", "weblogic_server"),
    "websphere": ("ibm", "websphere_application_server"),
    "ibm websphere": ("ibm", "websphere_application_server"),
    "jboss": ("redhat", "wildfly"),
    "wildfly": ("redhat", "wildfly"),

    # Web Frameworks, Runtimes & Languages
    "node": ("nodejs", "node.js"),
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "express": ("expressjs", "express"),
    "express.js": ("expressjs", "express"),
    "flask": ("palletsprojects", "flask"),
    "werkzeug": ("palletsprojects", "werkzeug"),
    "gunicorn": ("gunicorn", "gunicorn"),
    "django": ("djangoproject", "django"),
    "fastapi": ("tiangolo", "fastapi"),
    "spring": ("vmware", "spring_framework"),
    "spring framework": ("vmware", "spring_framework"),
    "spring boot": ("pivotal", "spring_boot"),
    "springboot": ("pivotal", "spring_boot"),
    "rails": ("rubyonrails", "ruby_on_rails"),
    "ruby on rails": ("rubyonrails", "ruby_on_rails"),
    "laravel": ("laravel", "laravel"),
    "php": ("php", "php"),
    "asp.net": ("microsoft", "asp.net"),
    "aspnet": ("microsoft", "asp.net"),

    # Databases & Caching
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "mongo": ("mongodb", "mongodb"),
    "sqlite": ("sqlite", "sqlite"),
    "memcached": ("memcached", "memcached"),
    "cassandra": ("apache", "cassandra"),
    "apache cassandra": ("apache", "cassandra"),
    "couchdb": ("apache", "couchdb"),
    "apache couchdb": ("apache", "couchdb"),
    "neo4j": ("neo4j", "neo4j"),
    "influxdb": ("influxdata", "influxdb"),
    "clickhouse": ("clickhouse", "clickhouse"),
    "cockroachdb": ("cockroachlabs", "cockroachdb"),
    "oracle database": ("oracle", "database_server"),
    "oracle db": ("oracle", "database_server"),
    "mssql": ("microsoft", "sql_server"),
    "sql server": ("microsoft", "sql_server"),
    "microsoft sql server": ("microsoft", "sql_server"),
    "elastic": ("elastic", "elasticsearch"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "opensearch": ("amazon", "opensearch"),

    # Message Brokers & Event Streams
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "kafka": ("apache", "kafka"),
    "apache kafka": ("apache", "kafka"),
    "activemq": ("apache", "activemq"),
    "apache activemq": ("apache", "activemq"),
    "nats": ("nats", "nats-server"),
    "nats-server": ("nats", "nats-server"),
    "mosquitto": ("eclipse", "mosquitto"),
    "eclipse mosquitto": ("eclipse", "mosquitto"),

    # CMS & Enterprise Applications
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "magento": ("adobe", "magento"),
    "ghost": ("ghost", "ghost"),
    "moodle": ("moodle", "moodle"),
    "nextcloud": ("nextcloud", "nextcloud"),
    "owncloud": ("owncloud", "owncloud"),
    "confluence": ("atlassian", "confluence"),
    "atlassian confluence": ("atlassian", "confluence"),
    "jira": ("atlassian", "jira"),
    "atlassian jira": ("atlassian", "jira"),
    "gitlab": ("gitlab", "gitlab"),
    "grafana": ("grafana", "grafana"),
    "prometheus": ("prometheus", "prometheus"),
    "jenkins": ("jenkins", "jenkins"),
    "sonarqube": ("sonarsource", "sonarqube"),
    "vault": ("hashicorp", "vault"),
    "hashicorp vault": ("hashicorp", "vault"),
    "consul": ("hashicorp", "consul"),
    "hashicorp consul": ("hashicorp", "consul"),
    "keycloak": ("redhat", "keycloak"),
    "portainer": ("portainer", "portainer"),
    "minio": ("minio", "minio"),
    "log4j": ("apache", "log4j"),

    # Remote Access, Network Protocols & Devices
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "pureftpd": ("pureftpd", "pure-ftpd"),
    "filezilla": ("filezilla-project", "filezilla_server"),
    "filezilla server": ("filezilla-project", "filezilla_server"),
    "samba": ("samba", "samba"),
    "smb": ("samba", "samba"),
    "microsoft-ds": ("microsoft", "windows_server"),
    "bind": ("isc", "bind"),
    "dns": ("isc", "bind"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "openvpn": ("openvpn", "openvpn"),
    "wireguard": ("wireguard", "wireguard"),
    "strongswan": ("strongswan", "strongswan"),
    "cisco ios": ("cisco", "ios"),
    "cisco asa": ("cisco", "adaptive_security_appliance_software"),
    "fortinet": ("fortinet", "fortios"),
    "fortios": ("fortinet", "fortios"),
    "mikrotik": ("mikrotik", "routeros"),
    "routeros": ("mikrotik", "routeros"),
    "pfsense": ("netgate", "pfsense"),
    "opnsense": ("opnsense", "opnsense"),
    "docker": ("docker", "docker"),
    "kubernetes": ("kubernetes", "kubernetes"),

    # Operating Systems
    "linux": ("linux", "linux_kernel"),
    "linux kernel": ("linux", "linux_kernel"),
    "ubuntu": ("canonical", "ubuntu_linux"),
    "debian": ("debian", "debian_linux"),
    "centos": ("centos", "centos"),
    "rhel": ("redhat", "enterprise_linux"),
    "alpine": ("alpinelinux", "alpine_linux"),
    "freebsd": ("freebsd", "freebsd"),
    "openbsd": ("openbsd", "openbsd"),
    "windows": ("microsoft", "windows"),
}


class VulnerabilityCorrelator:
    """Orchestrates the 8-step vulnerability enrichment and risk assessment pipeline."""

    def __init__(self):
        self.intel_fetcher = threat_intel_fetcher

    # ---------------------------------------------------------------------- #
    # STEP 1: Ingest Nmap / Port findings
    # ---------------------------------------------------------------------- #
    def step_1_ingest(self, scan_data_or_ports: Any) -> List[Dict[str, Any]]:
        """Extracts individual open port / service targets from raw scan data or port list."""
        items: List[Dict[str, Any]] = []

        if isinstance(scan_data_or_ports, dict):
            # Format from NmapScanner JSON
            hosts = scan_data_or_ports.get("hosts", [])
            for h in hosts:
                ip = h.get("ip", "127.0.0.1")
                for p in h.get("ports", []):
                    items.append({
                        "ip": ip,
                        "port": p.get("port", 0),
                        "protocol": p.get("protocol", "tcp"),
                        "service": p.get("service", "unknown"),
                        "product": p.get("product", ""),
                        "version": p.get("version", ""),
                        "extrainfo": p.get("extrainfo", ""),
                        "cpe": p.get("cpe", []),
                        "scripts": p.get("scripts", {}),
                    })
        elif isinstance(scan_data_or_ports, list):
            items = scan_data_or_ports
        return items

    # ---------------------------------------------------------------------- #
    # STEP 2: Product + Version Normalization
    # ---------------------------------------------------------------------- #
    def step_2_product_version(self, item: Dict[str, Any]) -> Tuple[str, str]:
        """Normalizes product name and cleans version string."""
        raw_product = (item.get("product") or item.get("service") or "").strip()
        raw_version = (item.get("version") or "").strip()

        # If product is empty but extrainfo or scripts has product info
        if not raw_product and item.get("service"):
            raw_product = item.get("service")

        # Strip OS trailing noise from version (e.g., "2.4.49 (Ubuntu)")
        clean_version = re.sub(r"\s*\([^)]*\)", "", raw_version).strip()
        # Strip trailing release tags
        clean_product = re.sub(r"[\(\)\[\]]", "", raw_product).strip()

        return clean_product, clean_version

def extract_verified_cpe_from_banner(banner: str) -> Optional[str]:
    """
    Extracts a standardized NIST CPE 2.3 string deterministically from raw HTTP headers,
    Server response headers, SSH banners, FTP banners, database banners, etc.
    Returns None if no verified pattern is matched.
    """
    if not banner or not isinstance(banner, str):
        return None

    b = banner.strip()

    # 1. Microsoft IIS (e.g. "Server: Microsoft-IIS/10.0", "Microsoft-IIS/8.5")
    m = re.search(r"(?:microsoft-iis|iis)[ /]([0-9]+(?:\.[0-9]+)*)", b, re.I)
    if m:
        return f"cpe:2.3:a:microsoft:internet_information_services:{m.group(1)}:*:*:*:*:*:*:*"

    # 2. Apache HTTP Server (e.g. "Server: Apache/2.4.49 (Unix)", "Apache/2.2.15")
    m = re.search(r"apache(?:[ -]httpd)?[ /]([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:apache:http_server:{m.group(1)}:*:*:*:*:*:*:*"

    # 3. Apache Tomcat (e.g. "Apache Tomcat/9.0.41", "Tomcat/8.5.5")
    m = re.search(r"(?:apache[ -])?tomcat[ /]([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:apache:tomcat:{m.group(1)}:*:*:*:*:*:*:*"

    # 4. Nginx (e.g. "Server: nginx/1.20.1", "nginx/1.18.0")
    m = re.search(r"nginx[ /]([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:f5:nginx:{m.group(1)}:*:*:*:*:*:*:*"

    # 5. OpenSSH (e.g. "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "OpenSSH_7.4")
    m = re.search(r"openssh[_-]?([0-9]+(?:\.[0-9]+)+(?:p[0-9]+)?)", b, re.I)
    if m:
        return f"cpe:2.3:a:openbsd:openssh:{m.group(1)}:*:*:*:*:*:*:*"

    # 6. Dropbear SSH (e.g. "SSH-2.0-dropbear_2020.81")
    m = re.search(r"dropbear[_-]?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:{m.group(1)}:*:*:*:*:*:*:*"

    # 7. vsFTPd (e.g. "220 (vsFTPd 3.0.3)", "vsftpd 2.3.4")
    m = re.search(r"vsftpd[ /]?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:vsftpd_project:vsftpd:{m.group(1)}:*:*:*:*:*:*:*"

    # 8. ProFTPD (e.g. "220 ProFTPD 1.3.5 Server")
    m = re.search(r"proftpd[ /]?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:proftpd:proftpd:{m.group(1)}:*:*:*:*:*:*:*"

    # 9. Pure-FTPd (e.g. "220---------- Welcome to Pure-FTPd [privsep] 1.0.49 ----------")
    m = re.search(r"pure-ftpd.*?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:pureftpd:pure-ftpd:{m.group(1)}:*:*:*:*:*:*:*"

    # 10. MySQL / MariaDB (e.g. "5.7.34-0ubuntu0.18.04.1", "MySQL 8.0.28")
    if "mariadb" in b.lower():
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", b)
        if m:
            return f"cpe:2.3:a:mariadb:mariadb:{m.group(1)}:*:*:*:*:*:*:*"
    elif "mysql" in b.lower() or re.search(r"^[0-9]+\.[0-9]+\.[0-9]+", b):
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", b)
        if m:
            return f"cpe:2.3:a:oracle:mysql:{m.group(1)}:*:*:*:*:*:*:*"

    # 11. PostgreSQL (e.g. "PostgreSQL 13.3", "PostgreSQL 9.6")
    m = re.search(r"postgres(?:ql)?[ /]?([0-9]+(?:\.[0-9]+)*)", b, re.I)
    if m:
        return f"cpe:2.3:a:postgresql:postgresql:{m.group(1)}:*:*:*:*:*:*:*"

    # 12. Redis (e.g. "redis_version:6.0.9")
    m = re.search(r"redis(?:_version)?[ :v]?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:redis:redis:{m.group(1)}:*:*:*:*:*:*:*"

    # 13. MongoDB (e.g. "MongoDB 4.4.6")
    m = re.search(r"mongodb[ /v]?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:mongodb:mongodb:{m.group(1)}:*:*:*:*:*:*:*"

    # 14. Samba (e.g. "Samba 4.15.0", "Samba 3.6.3")
    m = re.search(r"samba[ /]?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:samba:samba:{m.group(1)}:*:*:*:*:*:*:*"

    # 15. HAProxy (e.g. "HAProxy 2.4.8")
    m = re.search(r"haproxy[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:haproxy:haproxy:{m.group(1)}:*:*:*:*:*:*:*"

    # 16. Caddy (e.g. "Caddy v2.6.4")
    m = re.search(r"caddy[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:caddyserver:caddy:{m.group(1)}:*:*:*:*:*:*:*"

    # 17. Lighttpd (e.g. "lighttpd/1.4.59")
    m = re.search(r"lighttpd[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:lighttpd:lighttpd:{m.group(1)}:*:*:*:*:*:*:*"

    # 18. Traefik (e.g. "Traefik/v2.5.3")
    m = re.search(r"traefik[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:traefik:traefik:{m.group(1)}:*:*:*:*:*:*:*"

    # 19. Squid (e.g. "squid/4.13")
    m = re.search(r"squid[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:squid-cache:squid:{m.group(1)}:*:*:*:*:*:*:*"

    # 20. Varnish (e.g. "Varnish 6.5.1")
    m = re.search(r"varnish(?:_cache)?[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:varnish_software:varnish_cache:{m.group(1)}:*:*:*:*:*:*:*"

    # 21. Eclipse Jetty (e.g. "Jetty(9.4.43.v20210629)")
    m = re.search(r"jetty(?:\(([0-9]+(?:\.[0-9]+)+)[^\)]*\)|[ /:v\s]+([0-9]+(?:\.[0-9]+)+))", b, re.I)
    if m:
        ver = m.group(1) or m.group(2)
        return f"cpe:2.3:a:eclipse:jetty:{ver}:*:*:*:*:*:*:*"

    # 22. Werkzeug / Gunicorn Python servers
    m = re.search(r"werkzeug[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:palletsprojects:werkzeug:{m.group(1)}:*:*:*:*:*:*:*"
    m = re.search(r"gunicorn[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:gunicorn:gunicorn:{m.group(1)}:*:*:*:*:*:*:*"

    # 23. Node.js / Express
    if "express" in b.lower():
        m = re.search(r"express[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
        if m:
            return f"cpe:2.3:a:expressjs:express:{m.group(1)}:*:*:*:*:*:*:*"
    elif "node" in b.lower():
        m = re.search(r"node\.?js[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
        if m:
            return f"cpe:2.3:a:nodejs:node.js:{m.group(1)}:*:*:*:*:*:*:*"

    # 24. PHP (e.g. "PHP/7.4.21", "X-Powered-By: PHP/8.1.2")
    m = re.search(r"php[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:php:php:{m.group(1)}:*:*:*:*:*:*:*"

    # 25. Grafana (e.g. "Grafana v8.3.0")
    m = re.search(r"grafana[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:grafana:grafana:{m.group(1)}:*:*:*:*:*:*:*"

    # 26. Jenkins (e.g. "Jenkins 2.289.1", "X-Jenkins: 2.303.1")
    m = re.search(r"jenkins[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:jenkins:jenkins:{m.group(1)}:*:*:*:*:*:*:*"

    # 27. Elasticsearch (e.g. "Elasticsearch 7.10.2")
    m = re.search(r"elasticsearch[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:elastic:elasticsearch:{m.group(1)}:*:*:*:*:*:*:*"

    # 28. WordPress (e.g. "WordPress 5.8.1")
    m = re.search(r"wordpress[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:wordpress:wordpress:{m.group(1)}:*:*:*:*:*:*:*"

    # 29. Drupal (e.g. "Drupal 9.2.4")
    m = re.search(r"drupal[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:drupal:drupal:{m.group(1)}:*:*:*:*:*:*:*"

    # 30. Joomla (e.g. "Joomla! 3.9.28")
    m = re.search(r"joomla!?\s*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:joomla:joomla:{m.group(1)}:*:*:*:*:*:*:*"

    # 31. Mosquitto MQTT (e.g. "mosquitto version 2.0.11")
    m = re.search(r"mosquitto.*?([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:eclipse:mosquitto:{m.group(1)}:*:*:*:*:*:*:*"

    # 32. RabbitMQ (e.g. "RabbitMQ 3.8.14")
    m = re.search(r"rabbitmq[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:a:pivotal_software:rabbitmq:{m.group(1)}:*:*:*:*:*:*:*"

    # 33. Cisco IOS (e.g. "Cisco IOS Software, 15.2(4)M1")
    m = re.search(r"cisco[ -]ios.*?([0-9]+(?:\.[0-9]+)+(?:\([0-9a-zA-Z]+\)[0-9a-zA-Z]*)?)", b, re.I)
    if m:
        return f"cpe:2.3:o:cisco:ios:{m.group(1)}:*:*:*:*:*:*:*"

    # 34. Fortinet FortiOS (e.g. "FortiOS v6.4.5")
    m = re.search(r"fortios[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:o:fortinet:fortios:{m.group(1)}:*:*:*:*:*:*:*"

    # 35. MikroTik RouterOS (e.g. "MikroTik RouterOS 6.48.2")
    m = re.search(r"(?:mikrotik\s+)?routeros[ /:v\s]*([0-9]+(?:\.[0-9]+)+)", b, re.I)
    if m:
        return f"cpe:2.3:o:mikrotik:routeros:{m.group(1)}:*:*:*:*:*:*:*"

    # 36. Already valid CPE string in banner
    if "cpe:2.3:" in b:
        cpe_match = re.search(r"(cpe:2\.3:[a-z0-9_:\.\-]+)", b, re.I)
        if cpe_match:
            return cpe_match.group(1)
    if "cpe:/" in b:
        cpe_match = re.search(r"cpe:/([a-z0-9_:\.\-]+)", b, re.I)
        if cpe_match:
            parts = cpe_match.group(1).split(":")
            part = parts[0] if len(parts) > 0 else "a"
            vendor = parts[1] if len(parts) > 1 else "unknown"
            prod = parts[2] if len(parts) > 2 else "unknown"
            ver = parts[3] if len(parts) > 3 else "*"
            return f"cpe:2.3:{part}:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"

    return None


class VulnerabilityCorrelator:
    """Orchestrates the 8-step vulnerability enrichment and risk assessment pipeline."""

    def __init__(self):
        self.intel_fetcher = threat_intel_fetcher

    # ---------------------------------------------------------------------- #
    # STEP 1: Ingest Nmap / Port findings
    # ---------------------------------------------------------------------- #
    def step_1_ingest(self, scan_data_or_ports: Any) -> List[Dict[str, Any]]:
        """Extracts individual open port / service targets from raw scan data or port list."""
        if isinstance(scan_data_or_ports, dict) and "ports" in scan_data_or_ports:
            return scan_data_or_ports.get("ports", [])
        if isinstance(scan_data_or_ports, list):
            return scan_data_or_ports
        return []

    # ---------------------------------------------------------------------- #
    # STEP 2: Technology & Exact Version Identification
    # ---------------------------------------------------------------------- #
    def step_2_tech_identification(self, port_info: Dict[str, Any]) -> Dict[str, Any]:
        """Identifies technology name, version, and banner from port scan output."""
        service = port_info.get("service", "unknown")
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        banner = port_info.get("banner", "")

        # Prefer banner version extraction if available
        if banner:
            clean_p, clean_v = extract_product_and_version(banner)
            if clean_p and not product:
                product = clean_p
            if clean_v and not version:
                version = clean_v

        return {
            "port": port_info.get("port"),
            "protocol": port_info.get("protocol", "tcp"),
            "service": service,
            "product": product or service,
            "version": version,
            "banner": banner,
            "cpe": port_info.get("cpe", []),
        }

    # ---------------------------------------------------------------------- #
    # STEP 3: CPE 2.3 Generation & Verified Extraction
    # ---------------------------------------------------------------------- #
    def step_3_cpe(
        self,
        product: str,
        version: str,
        existing_cpes: Optional[List[str]] = None,
        banner: Optional[str] = None,
    ) -> str:
        """
        Generates or validates standard NIST CPE 2.3 string.
        Adheres to Rule #1 & #4: Only produces verified CPE strings.
        Returns empty string if no verified CPE can be formed.
        """
        # 1. Check if raw banner yields a verified CPE
        if banner:
            banner_cpe = extract_verified_cpe_from_banner(banner)
            if banner_cpe:
                return banner_cpe

        # 2. Check existing scanner-provided CPEs
        if existing_cpes and len(existing_cpes) > 0:
            cpe0 = existing_cpes[0]
            if cpe0.startswith("cpe:/"):
                parts = cpe0.replace("cpe:/", "").split(":")
                part = parts[0] if len(parts) > 0 else "a"
                vendor = parts[1] if len(parts) > 1 else "unknown"
                prod = parts[2] if len(parts) > 2 else "unknown"
                ver = parts[3] if len(parts) > 3 else (version or "*")
                if vendor != "unknown" and prod != "unknown":
                    return f"cpe:2.3:{part}:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"
            elif cpe0.startswith("cpe:2.3:"):
                return cpe0

        # 3. Lookup verified product mapping (Exact match first, then longest substring)
        norm_key = product.lower().strip()
        if norm_key in PRODUCT_CPE_MAP:
            v, p = PRODUCT_CPE_MAP[norm_key]
            part = "o" if v in ["cisco", "fortinet", "mikrotik"] or "os" in p else "a"
            ver_str = version if version else "*"
            return f"cpe:2.3:{part}:{v}:{p}:{ver_str}:*:*:*:*:*:*:*"

        for key, (v, p) in sorted(PRODUCT_CPE_MAP.items(), key=lambda item: len(item[0]), reverse=True):
            if key in norm_key or norm_key in key:
                part = "o" if v in ["cisco", "fortinet", "mikrotik"] or "os" in p else "a"
                ver_str = version if version else "*"
                return f"cpe:2.3:{part}:{v}:{p}:{ver_str}:*:*:*:*:*:*:*"

        # Return empty string if unverified to prevent ungrounded CVE queries
        return ""

    # ---------------------------------------------------------------------- #
    # STEP 4: Multi-Source CVE Matching (Strictly Verified CPE Bound)
    # ---------------------------------------------------------------------- #
    def step_4_cve_matching(self, product: str, version: str, cpe: str) -> List[ThreatIntelResult]:
        """
        Queries 8 threat intel DBs for CVE matches strictly bound to verified CPE.
        Rule #1, #2, #4: Only query CVE databases with verified CPE strings.
        """
        if not cpe or "generic" in cpe or "unknown" in cpe:
            logger.info(f"Skipping CVE matching: No verified CPE for product '{product}' / version '{version}'")
            return []

        # Extract CPE components: cpe:2.3:part:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) < 6:
            return []

        cpe_vendor = parts[3]
        cpe_product = parts[4]
        cpe_version = parts[5]

        # Targeted query bound to verified CPE details
        queries = []
        if cpe_version and cpe_version != "*":
            queries.append(f"{cpe_product} {cpe_version}")
            if product and product.lower() != cpe_product.lower():
                queries.append(f"{product} {cpe_version}")
        else:
            queries.append(cpe_product)

        results: List[ThreatIntelResult] = []
        for q in queries:
            res = self.intel_fetcher.search_all(q, max_per_source=4)
            results.extend(res)

        # Deduplicate and assert product correlation
        unique_results = {}
        for r in results:
            if r.id not in unique_results:
                unique_results[r.id] = r

        return list(unique_results.values())

    # ---------------------------------------------------------------------- #
    # STEP 5: CVSS Scoring & Vector Extraction
    # ---------------------------------------------------------------------- #
    def step_5_cvss(self, intel_result: ThreatIntelResult) -> Tuple[Optional[float], str, str]:
        """Extracts CVSS score, severity tier, and CVSS vector string."""
        score = intel_result.cvss_score
        severity = intel_result.severity or "UNKNOWN"
        vector = intel_result.extra.get("cvss_vector", "")
        if not vector and score:
            if score >= 9.0:
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            elif score >= 7.0:
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"

        return score, severity, vector

    # ---------------------------------------------------------------------- #
    # STEP 6: CISA KEV Verification
    # ---------------------------------------------------------------------- #
    def step_6_cisa_kev(self, cve_id: str) -> Tuple[bool, Dict[str, Any]]:
        """Checks if the CVE is in the active CISA Known Exploited Vulnerabilities catalog."""
        kev_feed = self.intel_fetcher._get_cisa_kev_feed()
        for item in kev_feed:
            if item.get("cveID", "").upper() == cve_id.upper():
                return True, {
                    "cve_id": item.get("cveID"),
                    "vendor_project": item.get("vendorProject"),
                    "product": item.get("product"),
                    "vulnerability_name": item.get("vulnerabilityName"),
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "required_action": item.get("requiredAction"),
                    "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse", "Unknown"),
                }
        return False, {}

    # ---------------------------------------------------------------------- #
    # STEP 7: Exploit Availability Assessment
    # ---------------------------------------------------------------------- #
    def step_7_exploit_availability(self, cve_id: str, title: str, description: str) -> Tuple[bool, List[str], Dict[str, Any]]:
        """Identifies weaponized PoCs, ExploitDB IDs, Metasploit modules, Rapid7 entries."""
        sources = []
        details = {}

        # Query ExploitDB specifically for this CVE
        try:
            edb_results = self.intel_fetcher.fetch_exploitdb(cve_id, max_results=2)
            if edb_results:
                sources.append("ExploitDB")
                details["exploitdb_ids"] = [r.id for r in edb_results]
                details["exploitdb_urls"] = [r.url for r in edb_results]
        except Exception:
            pass

        # Query Metasploit modules
        try:
            msf_results = self.intel_fetcher.fetch_metasploit(cve_id, max_results=2)
            if msf_results:
                sources.append("Metasploit")
                details["metasploit_modules"] = [r.id for r in msf_results]
        except Exception:
            pass

        # Query Vulners
        try:
            vulners_results = self.intel_fetcher.fetch_vulners(cve_id, max_results=2)
            if any("exploit" in r.tags for r in vulners_results):
                sources.append("Vulners Exploit Feed")
        except Exception:
            pass

        is_available = len(sources) > 0 or "RCE" in title.upper() or "EXPLOIT" in description.upper()
        if not sources and is_available:
            sources.append("Public PoC / GitHub")

        return is_available, sources, details

    # ---------------------------------------------------------------------- #
    # STEP 8: Explainable Confidence Scoring
    # ---------------------------------------------------------------------- #
    def step_8_confidence(
        self,
        product: str,
        version: str,
        cpe: str,
        cve_id: str,
        cvss_score: Optional[float],
        is_cisa_kev: bool,
        exploit_available: bool,
        source_count: int,
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Calculates an exact 0-100% confidence rating with breakdown:
          - Exact Version Match: +30%
          - CPE Normalization: +20%
          - Multi-Source Corroboration: +20%
          - CISA KEV Active Exploitation: +15%
          - Weaponized Exploit / MSF Module: +15%
        """
        score = 0.0
        breakdown = {}

        # 1. Version Precision (Max +30%)
        if version and version != "*":
            score += 30.0
            breakdown["version_match"] = {"pts": 30, "reason": f"Exact target version '{version}' verified"}
        elif product:
            score += 15.0
            breakdown["version_match"] = {"pts": 15, "reason": f"Product identified without exact subversion"}
        else:
            breakdown["version_match"] = {"pts": 0, "reason": "Generic port service"}

        # 2. CPE Validity (Max +20%)
        if "unknown" not in cpe and "generic" not in cpe:
            score += 20.0
            breakdown["cpe_normalization"] = {"pts": 20, "reason": f"Standardized NIST CPE '{cpe}' validated"}
        else:
            score += 10.0
            breakdown["cpe_normalization"] = {"pts": 10, "reason": "Heuristic CPE constructed"}

        # 3. Multi-Source Threat Intel Corroboration (Max +20%)
        if source_count >= 3:
            score += 20.0
            breakdown["multi_source"] = {"pts": 20, "reason": f"Corroborated across {source_count} security databases"}
        elif source_count >= 1:
            score += 10.0
            breakdown["multi_source"] = {"pts": 10, "reason": "Confirmed by single threat feed"}

        # 4. CISA KEV (Max +15%)
        if is_cisa_kev:
            score += 15.0
            breakdown["cisa_kev"] = {"pts": 15, "reason": "Listed in CISA Known Exploited Vulnerabilities catalog (Active In-The-Wild Threat)"}
        else:
            breakdown["cisa_kev"] = {"pts": 0, "reason": "Not in active CISA KEV catalog"}

        # 5. Exploit Availability (Max +15%)
        if exploit_available:
            score += 15.0
            breakdown["exploit_availability"] = {"pts": 15, "reason": "Public PoC or weaponized Metasploit module verified available"}
        else:
            breakdown["exploit_availability"] = {"pts": 0, "reason": "Theoretical vulnerability / No public PoC mapped"}

        # Clamp score between 0.0 and 100.0
        final_score = round(min(max(score, 10.0), 100.0), 1)

        # Tier assignment
        if final_score >= 85.0:
            level = "CONFIRMED"
        elif final_score >= 65.0:
            level = "HIGH"
        elif final_score >= 45.0:
            level = "PROBABLE"
        else:
            level = "POTENTIAL"

        return final_score, level, breakdown

    # ---------------------------------------------------------------------- #
    # MASTER ENRICHMENT PIPELINE (Executes the full 8 steps)
    # ---------------------------------------------------------------------- #
    def run_full_pipeline(self, scan_data_or_ports: Any) -> Dict[str, Any]:
        """Executes the complete 8-step pipeline on given port/scan findings."""
        start_time = time.time()
        raw_items = self.step_1_ingest(scan_data_or_ports)

        enriched_vulnerabilities: List[VulnerabilityRecord] = []
        services_recorded: List[ServiceRecord] = []
        pipeline_trace: List[Dict[str, Any]] = []

        for item in raw_items:
            # Step 1
            ip = item.get("ip", "127.0.0.1")
            port = item.get("port", 0)
            proto = item.get("protocol", "tcp")

            # Step 2
            product, version = self.step_2_product_version(item)
            raw_banner = item.get("banner", "") or item.get("extrainfo", "")

            # Step 3 (Verified CPE extraction)
            cpe = self.step_3_cpe(product, version, item.get("cpe", []), banner=raw_banner)

            # Record Service
            srv = ServiceRecord(
                port=port,
                protocol=proto,
                service=item.get("service", "unknown"),
                product=product,
                version=version,
                extrainfo=item.get("extrainfo", ""),
                cpe=[cpe] if cpe else [],
                banner=raw_banner,
                scripts_output=item.get("scripts", {}),
                ip=ip,
            )
            services_recorded.append(srv)

            # Step 4
            intel_matches = self.step_4_cve_matching(product, version, cpe)

            port_trace = {
                "port": port,
                "product": product,
                "version": version,
                "cpe": cpe,
                "cve_matches_count": len(intel_matches),
                "vulnerabilities": [],
            }

            for intel in intel_matches[:5]:
                # Step 5
                cvss_score, cvss_severity, cvss_vector = self.step_5_cvss(intel)

                # Step 6
                is_cisa_kev, cisa_details = self.step_6_cisa_kev(intel.id)

                # Step 7
                exploit_available, exploit_sources, exploit_details = self.step_7_exploit_availability(
                    intel.id, intel.title, intel.description
                )

                # Step 8
                conf_score, conf_level, conf_breakdown = self.step_8_confidence(
                    product=product,
                    version=version,
                    cpe=cpe,
                    cve_id=intel.id,
                    cvss_score=cvss_score,
                    is_cisa_kev=is_cisa_kev,
                    exploit_available=exploit_available,
                    source_count=len(intel_matches),
                )

                vuln_record = VulnerabilityRecord(
                    cve_id=intel.id,
                    title=intel.title,
                    product=product,
                    version=version,
                    cpe=cpe,
                    cvss_score=cvss_score,
                    cvss_severity=cvss_severity,
                    cvss_vector=cvss_vector,
                    is_cisa_kev=is_cisa_kev,
                    cisa_kev_details=cisa_details,
                    exploit_available=exploit_available,
                    exploit_sources=exploit_sources,
                    exploit_details=exploit_details,
                    confidence_score=conf_score,
                    confidence_level=conf_level,
                    confidence_breakdown=conf_breakdown,
                    port=port,
                    ip=ip,
                    remediation=f"Upgrade {product} to the latest stable release or apply vendor security patch for {intel.id}.",
                    reference_urls=[intel.url] if intel.url else [],
                )
                enriched_vulnerabilities.append(vuln_record)
                port_trace["vulnerabilities"].append(vuln_record.to_dict())

            pipeline_trace.append(port_trace)

        # Sort vulnerabilities by CVSS score and confidence descending
        enriched_vulnerabilities.sort(
            key=lambda v: ((v.cvss_score or 0.0) * 1.5 + v.confidence_score), reverse=True
        )

        duration = round(time.time() - start_time, 2)

        return {
            "success": True,
            "duration_s": duration,
            "total_services": len(services_recorded),
            "total_vulnerabilities": len(enriched_vulnerabilities),
            "services": [s.to_dict() for s in services_recorded],
            "vulnerabilities": [v.to_dict() for v in enriched_vulnerabilities],
            "pipeline_trace": pipeline_trace,
            "chain_steps": [
                "Nmap",
                "Product + Version",
                "CPE",
                "CVE Matching",
                "CVSS",
                "CISA KEV",
                "Exploit Availability",
                "Confidence",
            ],
        }


# Global singleton
vuln_correlator = VulnerabilityCorrelator()
