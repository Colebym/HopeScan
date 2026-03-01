import ipaddress
import socket
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from fingerprinting import (
    grab_banner,
    get_dns_version,
    get_smb_version,
    get_ldap_info
)

MAX_THREADS = 300  # tweakable

SERVICE_CVE_KEYWORDS = {
    "SSH": "OpenSSH",
    "SMB/CIFS": "Microsoft Windows SMB",
    "RPC": "Microsoft Windows RPC",
    "HTTP": "Apache",
    "HTTPS": "Apache",
    "FTP": "vsftpd",
    "Domain Name Server": "BIND",
    "Kerberos": "Windows Kerberos",
    "NetBIOS/SMB": "Microsoft Windows SMB",
    "LDAP": "Active Directory",
    "idap": "Active Directory",
    "kpasswd": "Kerberos",
    "http-rpc-epmap": "Microsoft RPC",
    "idaps": "Active Directory"
}

# Load local CVE database
with open("cves.json", "r") as f:
    LOCAL_CVE_DB = json.load(f)


def scan_ports(target_ip, start_port, end_port, scan_type):
    open_ports = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, scan_type): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    duration = time.time() - start_time

    open_ports.sort(key=lambda x: x["port"])

    # Attach CVEs
    for entry in open_ports:
        entry["cves"] = get_cves_for_port(entry)

    return {
        "target": target_ip,
        "ports": open_ports,
        "duration": round(duration, 2)
    }


def scan_port(target_ip, port, scan_type):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if scan_type.lower() == "basic":
        sock.settimeout(0.1)
    else:
        sock.settimeout(0.5)

    try:
        sock.connect((target_ip, port))

        if scan_type.lower() == "basic":
            return {
                "port": port,
                "service": "Unknown",
                "version": "Unknown"
            }
        else:
            return identify_service(target_ip, port, scan_type)

    except OSError:
        return None

    finally:
        sock.close()



def identify_service(target_ip, port, scan_type):
    """
    Detects service name and version for common ports.
    Returns a dict: {"port": port, "service": service_name, "version": version}
    Version is preserved for display; CVE lookup uses a separate cleaning function.
    """

    service_name = "Unknown"
    version = "Unknown"

    # --- Predefined common ports (fallback only) ---
    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "Domain Name Server",
        80: "HTTP",
        88: "Kerberos",
        110: "POP3",
        135: "RPC",
        139: "NetBIOS/SMB",
        143: "IMAP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB/CIFS",
        464: "kpasswd",
        593: "http-rpc-epmap",
        636: "LDAPS",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP",
    }

    if port in common_ports:
        service_name = common_ports[port]

    try:
        banner = advanced_banner_probe(target_ip, port)

        # =========================================================
        # ENUM MODE – Deep Fingerprinting
        # =========================================================
        if scan_type.lower() == "enum":

            # --- DNS ---
            if port == 53:
                dns_version = get_dns_version(target_ip)
                if dns_version:
                    service_name = "Domain Name Server"
                    version = dns_version

            # --- SMB ---
            elif port in [139, 445]:
                smb_version = get_smb_version(target_ip)
                if smb_version:
                    service_name = "SMB/CIFS"
                    version = smb_version

            # --- LDAP ---
            elif port in [389, 636]:
                ldap_info = get_ldap_info(target_ip)
                if ldap_info:
                    service_name = "LDAP" if port == 389 else "LDAPS"
                    version = ldap_info.split("\n")[0][:200]

            # --- HTTP / HTTPS ---
            elif port in [80, 8080, 8000, 443]:
                http_banner = grab_banner(target_ip, port)
                if http_banner:
                    service_name = "HTTPS" if port == 443 else "HTTP"
                    for line in http_banner.split("\n"):
                        if "Server:" in line:
                            version = line.split("Server:")[-1].strip()
                            break

        # =========================================================
        # Banner Fallback Logic (Used if enum fingerprint fails
        # OR if running non-enum detection modes)
        # =========================================================

        # --- SSH ---
        if "SSH" in banner:
            service_name = "SSH"
            if "SSH-2.0-" in banner:
                version = banner.replace("SSH-2.0-", "").strip()
            else:
                version = banner.strip()

        # --- FTP ---
        elif "FTP" in banner:
            service_name = "FTP"
            parts = banner.split(" ")
            version = parts[-1] if parts else "Unknown"

        # --- SMTP ---
        elif port in [25, 587] and banner.startswith("220"):
            service_name = "SMTP"
            parts = banner.split(" ")
            version = parts[1] if len(parts) > 1 else "Unknown"

        # --- POP3 ---
        elif port == 110 and banner.startswith("+OK"):
            service_name = "POP3"
            parts = banner.split(" ")
            version = parts[1] if len(parts) > 1 else "Unknown"

        # --- IMAP ---
        elif port == 143 and banner.startswith("* OK"):
            service_name = "IMAP"
            parts = banner.split(" ")
            version = parts[2] if len(parts) > 2 else "Unknown"

        # --- Generic fallback for known services ---
        elif banner and version == "Unknown":
            version = banner[:200]

    except:
        pass

    return {
        "port": port,
        "service": service_name,
        "version": version or "Unknown"
    }


def advanced_banner_probe(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((target_ip, port))

        # HTTP probe
        if port in [80, 8080, 8000, 443]:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")

        data = sock.recv(2048).decode(errors="ignore")
        sock.close()
        return data.strip()

    except:
        return ""


def lookup_cves(service_name, version="Unknown"):
    service_entry = LOCAL_CVE_DB.get(service_name, {})
    if version != "Unknown":
        major_version = version.split(".")[0]
        cves = service_entry.get(major_version)
        if cves:
            return cves
    return service_entry.get("default", [])

def get_cves_for_port(entry):
    """
    Returns a list of CVEs for a given port entry from the local CVE JSON.
    Uses full version first for matching, then falls back to generic service name.
    entry = {"port": 22, "service": "SSH", "version": "OpenSSH 9.5"}
    """
    service_name = entry['service']
    version_full = entry['version']  # keep full version for display
    service_keyword = SERVICE_CVE_KEYWORDS.get(service_name, service_name)

    cves = []

    cve_data = LOCAL_CVE_DB

    # Try to get CVEs for full version first
    key_full = f"{service_keyword} {version_full}"
    if key_full in cve_data:
        cves = cve_data[key_full]

    # Fallback to generic service CVEs if none found
    if not cves and service_keyword in cve_data:
        cves = cve_data[service_keyword]

    return cves


def save_results(target_ip, open_ports, start_port, end_port, duration):
    filename = f"hopescan_{target_ip.replace('.', '_')}.json"

    data = {
        "target": target_ip,
        "port_range": {
            "start": start_port,
            "end": end_port
        },
        "open_ports": sorted(open_ports),
        "scan_duration_seconds": round(duration, 2)
    }

    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

    print(f"Results saved to {filename}")
