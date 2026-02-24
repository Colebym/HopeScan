------------
HopeScan v1
------------

Basic TCP Port Scanner in Python

A beginner-friendly yet fully functional TCP port scanner that scans an IPv4 address for open ports (1–1024), validates user input, and measures scan duration.


---------
Features
---------

IPv4 Input Validation: Ensures only valid IP addresses are scanned.

TCP Port Scanning: Checks ports 1–1024 for open TCP connections.

Timeout Handling: Skips unresponsive ports after 2 seconds.

Open Ports Reporting: Displays open ports on separate lines.

Scan Timing: Measures total scan duration for performance awareness.

Clean Architecture: Separate functions for input handling and scanning.


----------------
Getting Started
---------------
Prerequisites:

Python 3.x installed
Git installed (for version control)

No external packages are required.


-----------------
Running HopeScan
-----------------
Clone the repository:

> git clone https://github.com/colebym/HopeScan.git

Navigate to the project folder:

> cd HopeScan

Run the scanner:

> python mainV1.py

Enter the target IPv4 address when prompted.

Wait for the scan to complete — the scanner will output open ports and total scan time.


---------------
Example Output
---------------
Enter target IP: 127.0.0.1

Scanning ports...

Open Ports Found:

135

445

Scan completed in 8.72 seconds.


-------------------------
Future Improvements (v2+)
--------------------------
Add multi-threading for faster scans

Allow custom port ranges

Port service details + versions

Implement a GUI with real-time progress

Add domain name resolution

Add option to list common CVE's for service versions found


------------------
Project Structure
------------------
HopeScan/

├─ HopeScan.py         # Main Python script

├─ README.md           # Project documentation

└─ .gitignore          # Exclude IDE & OS files


--------
License
--------
MIT License — free to use and modify.
