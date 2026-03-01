
<img width="1536" height="340" alt="logo" src="https://github.com/user-attachments/assets/f60b1a03-0d9d-4119-9dca-58e64617e317" />

<p align="center">
  <em>Modern, fast, and lightweight network scanner with CVE enumeration</em>
</p>

---

<h2>Features</h2>
<ul>
  <li><strong>Fast Port Scanning</strong> – Multi-threaded scans for speed</li>
  <li><strong>Service Enumeration</strong> – Detect services and versions</li>
  <li><strong>CVE Matching</strong> – Lookup known vulnerabilities from a local database</li>
  <li><strong>CVSS Severity Coloring</strong> – Visualize vulnerability criticality</li>
  <li><strong>Scan History Panel</strong> – Keep track of previous scans (GUI)</li>
  <li><strong>Flexible Interfaces</strong> – CLI and GUI available</li>
  <li><strong>Save Results</strong> – Export scans as JSON files</li>
</ul>

---

<h2>Installation</h2>

<pre style="background-color:#1a1a1a;color:#e6e6e6;padding:10px;border-radius:6px;">
# Clone repository
git clone https://github.com/colebym/HopeScan.git
cd HopeScan

# Install dependencies
pip install -r requirements.txt
</pre>

<h2>Launch</h2>

<ul>
  <li><strong>GUI Mode:</strong> <code>python gui.py</code></li>
  <li><strong>CLI Mode:</strong> <code>python cli.py</code></li>
</ul>

---

<h2>Usage</h2>

<h3>CLI Example</h3>

<pre style="background-color:#1a1a1a;color:#e6e6e6;padding:10px;border-radius:6px;">
$ python cli.py
--- HopeScan ---
1 - Basic Port Scan
2 - Service Enumeration Scan
3 - Exit
</pre>

<p>Follow the prompts to input target IP/domain and port range.</p>

<h3>GUI Example</h3>

<ul>
  <li>Enter the target IP or domain.</li>
  <li>Select scan type: <strong>Basic</strong> or <strong>Enumeration</strong>.</li>
  <li>Specify port range (default: 1–1024).</li>
  <li>Click <strong>Start Scan</strong>.</li>
  <li>View results in the main panel; save results as JSON.</li>
</ul>

---

<h2>CVE Database</h2>

<p>HopeScan uses a local <code>cves.json</code> file to cross-reference detected services to known vulnerabilities. CVSS scores are color-coded:</p>

<table>
  <tr>
    <th>Severity</th>
    <th>CVSS Range</th>
    <th>Color</th>
  </tr>
  <tr><td>Low</td><td>0.0 - 3.9</td><td style="color:#2ecc71;">Green</td></tr>
  <tr><td>Medium</td><td>4.0 - 6.9</td><td style="color:#f1c40f;">Yellow</td></tr>
  <tr><td>High</td><td>7.0 - 8.9</td><td style="color:#ff7a00;">Orange</td></tr>
  <tr><td>Critical</td><td>9.0 - 10.0</td><td style="color:#e74c3c;">Red</td></tr>
</table>

---

<h2>Release Notes</h2>

<ul>
  <li><strong>v1.0</strong> – Initial release</li>
  <li><strong>v2.0</strong> – GUI, improved scanning</li>
  <li><strong>v3.0</strong> – Service fingerprinting, CVE matching, scan history panel, performance improvements</li>
</ul>

<p>Download releases from the <a href="https://github.com/colebym/HopeScan/releases">GitHub releases page</a>.</p>

---

<h2>Contributing</h2>

<p>Contributions are welcome! Please fork the repository and submit pull requests. Guidelines:</p>

<ul>
  <li>Use separate branches for new features.</li>
  <li>Maintain Python 3.10+ compatibility.</li>
  <li>Follow PEP8 style conventions.</li>
</ul>

---

<h2>License</h2>

<p>MIT License – see <code>LICENSE</code> file.</p>

---

<h2>Disclaimer</h2>

<p>HopeScan is intended for <strong>educational and authorized security testing only</strong>. Unauthorized scanning of networks you do not own or have explicit permission to test may be illegal. The author is not responsible for misuse.</p>
