HopeScan

<img width="1536" height="340" alt="logo" src="https://github.com/user-attachments/assets/ed7d085d-aee2-48fa-bf26-def67fca62b5" />

HopeScan is a modern, fast, and lightweight network scanner for discovering open ports, enumerating services, and identifying known vulnerabilities (CVEs) on your target systems. Designed for security professionals, penetration testers, and CTF enthusiasts, HopeScan provides both a CLI and GUI interface with a sleek dark theme.

Features

Fast Port Scanning – Scan ranges of ports with multithreading for speed.

Service Enumeration – Detect common services and attempt to determine versions.

CVE Matching – Lookup known vulnerabilities from a local CVE database.

CVSS Severity Coloring – Highlight critical vulnerabilities for quick prioritization.

Scan History Panel – Keep track of previous scans (GUI version).

Flexible Interfaces – CLI and GUI options for different use cases.

Save Results – Export scan results as JSON files.

Installation

Clone the repository:

git clone https://github.com/colebym/HopeScan.git
cd HopeScan

Install required Python packages:

pip install -r requirements.txt

Launch:

GUI Mode:

python gui.py

CLI Mode:

python cli.py
Usage
CLI Example
$ python cli.py
--- HopeScan ---
1 - Basic Port Scan
2 - Service Enumeration Scan
3 - Exit

Follow the prompts to enter target IP or domain and port range.

GUI Example

Enter target IP/domain.

Select scan type: Basic or Enumeration.

Specify port range (default 1–1024).

Click Start Scan.

View results in the main panel and save as JSON.

CVE Database

HopeScan uses a local JSON database of CVEs (cves.json) for offline vulnerability matching.

Each detected service is cross-referenced to known CVEs.

CVSS scores are color-coded for easy visibility:

Low (0–3.9) – Green

Medium (4–6.9) – Yellow

High (7–8.9) – Orange

Critical (9–10) – Red

Release Notes

v1.0 – Initial release

v2.0 – Major update: GUI, improved scanning

v3.0 – Current: service fingerprinting, CVE matching, scan history panel, performance improvements

Download releases from the GitHub releases page
.

Contributing

Contributions are welcome! Please fork the repository and submit pull requests.
Guidelines:

Keep feature changes separate in branches.

Maintain Python 3.10+ compatibility.

Follow PEP8 style conventions.

License

MIT License – See LICENSE file.

Disclaimer

HopeScan is intended for educational and authorized security testing only. Unauthorized scanning of networks you do not own or have explicit permission to test may be illegal. The author is not responsible for any misuse.
