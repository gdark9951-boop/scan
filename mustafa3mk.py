# Advanced Website Fingerprint & Lightweight IDS (Flask Web UI)
# UI: Modern Cyber HUD Design
# Identity: Mustafa v2 (Enhanced)

import sys
import subprocess

def install_dependencies():
    """Self-healing: Automatically install missing libraries"""
    required = ["requests", "urllib3", "flask", "flask-cors"]
    for lib in required:
        try:
            __import__(lib)
        except ImportError:
            print(f"[!] Library '{lib}' missing. Installing now...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            print(f"[+] '{lib}' installed successfully.")

# Execute check before imports
install_dependencies()

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib
import time
import statistics
import difflib
import socket
import ssl
import json
import re
import os
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import urllib3
import random

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_FILE = "fingerprints_db.json"
TIMEOUT = 5  # Reduced from 10 to 5 seconds
ROUNDS = 2   # Reduced from 5 to 2 rounds

# --- Top 20 Critical Ports (Optimized for Speed) ---
NMAP_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 
    9200: 'ElasticSearch', 27017: 'MongoDB', 5900: 'VNC'
}

# --- Top 15 High-Risk Paths (Optimized) ---
SENSITIVE_PATHS = [
    ".env", ".git/config", "wp-config.php", "config.php", 
    "phpinfo.php", "admin/", "login.php", "wp-login.php",
    "backup.sql", "database.sql", ".htaccess", 
    "composer.json", "package.json", "xmlrpc.php", "id_rsa"
]

# --- Top 10 Subdomains (Optimized) ---
SUBDOMAIN_LIST = [
    "www", "dev", "api", "admin", "test", "mail",
    "staging", "portal", "vpn", "blog"
]

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

# ---------------- Utilities ----------------

def get_session():
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    s.headers.update(HEADERS)
    return s

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def sha256(data: str):
    return hashlib.sha256(data.encode()).hexdigest()

# ---------------- Deep Probe Modules ----------------

def probe_banner(ip, port):
    """Real service identification via banner grabbing"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        
        # Send basic probe
        if port in [80, 8080]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass  # FTP auto-sends banner
        elif port in [22, 23]:
            pass  # SSH/Telnet auto-sends banner
        elif port == 25:
            pass  # SMTP auto-sends banner
        else:
            sock.send(b"\r\n")
        
        banner = sock.recv(1024).decode('utf-8', 'ignore').strip()
        sock.close()
        return banner[:200] if banner else None
    except Exception:
        return None

def probe_ports(domain):
    """Deep Port Scan (Nmap-Style)"""
    try:
        ip = socket.gethostbyname(domain)
    except:
        return [f"DNS resolution failed for {domain}"]
    
    results = []
    
    def scan_item(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            banner = probe_banner(ip, port)
            banner_str = f" | {banner}" if banner else ""
            return f"Port {port} ({name}) OPEN{banner_str}"
        return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_item, port, name): port for port, name in NMAP_PORTS.items()}
        for future in futures:
            res = future.result()
            if res:
                results.append(res)
    
    return results if results else ["No open ports found in standard scan"]

def path_recon(base_url):
    """Active Path Discovery: Checks for real-world file exposures"""
    found = []
    session = get_session()
    
    def check_path(path):
        url = base_url.rstrip('/') + '/' + path
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=False, verify=False)
            if r.status_code in [200, 301, 302, 403]:
                return f"{path} [EXIST] ({r.status_code})"
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_path, SENSITIVE_PATHS)
        found = [r for r in results if r]
    
    return found if found else ["No sensitive paths discovered"]

def subdomain_recon(domain):
    """Fast Subdomain Enumeration via DNS resolution"""
    found = []
    
    def check_sub(sub):
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return f"{full} -> {ip}"
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_sub, SUBDOMAIN_LIST)
        found = [r for r in results if r]
    
    return found if found else ["No subdomains found"]

def probe_robots(url):
    try:
        r = get_session().get(f"{url}/robots.txt", timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            lines = [l for l in r.text.split('\n') if l.strip() and not l.strip().startswith('#')][:10]
            summary = "\n".join(lines)
            if len(lines) < len(r.text.split('\n')): summary += "\n... (Truncated)"
            return {"status": "Found", "content": summary}
        else:
            return {"status": "Not Found (404)", "content": ""}
    except:
        return {"status": "Unreachable", "content": ""}

def extract_links(html):
    if not html: return {"internal": 0, "external": 0, "total": 0}
    links = re.findall(r'href=[\"\'](.+?)[\"\']', html)
    internal = 0
    external = 0
    for l in links:
        if l.startswith('http'):
            external += 1
        elif l.startswith('/') or l.startswith('.'):
            internal += 1
    return {"internal": internal, "external": external, "total": len(links)}

def detect_data_leaks(base_url, html_content=""):
    """Detect exposed files, leaked emails, API keys, and sensitive information"""
    leaks = {
        "exposed_files": [],
        "leaked_emails": [],
        "api_keys_found": [],
        "sensitive_patterns": []
    }
    
    session = get_session()
    
    # 1. Check for exposed sensitive files (already in SENSITIVE_PATHS)
    for path in SENSITIVE_PATHS[:10]:  # Check top 10 only for speed
        try:
            url = f"{base_url.rstrip('/')}/{path}"
            r = session.head(url, timeout=3, allow_redirects=False)
            if r.status_code in [200, 403]:  # 200 = accessible, 403 = exists but forbidden
                status = "CRITICAL - Accessible" if r.status_code == 200 else "WARNING - Exists (Forbidden)"
                leaks["exposed_files"].append(f"{path} [{status}]")
        except:
            pass
    
    # 2. Extract emails from page content
    if html_content:
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = list(set(re.findall(email_pattern, html_content)))
        leaks["leaked_emails"] = emails[:10]  # Limit to 10
    
    # 3. Detect API key patterns
    if html_content:
        api_patterns = {
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "Generic API": r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
            "Secret Token": r'secret[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
            "Bearer Token": r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'
        }
        
        for name, pattern in api_patterns.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                leaks["api_keys_found"].append(f"{name} pattern detected")
    
    # 4. Check robots.txt for leaks
    try:
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        r = session.get(robots_url, timeout=3)
        if r.status_code == 200:
            # Extract emails from robots.txt
            robots_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', r.text)
            leaks["leaked_emails"].extend(robots_emails)
            leaks["leaked_emails"] = list(set(leaks["leaked_emails"]))[:10]
            
            # Check for sensitive paths in robots.txt
            if 'admin' in r.text.lower() or 'backup' in r.text.lower():
                leaks["sensitive_patterns"].append("Admin/Backup paths found in robots.txt")
    except:
        pass
    
    # 5. Check for directory listing
    try:
        r = session.get(base_url, timeout=3)
        if 'Index of /' in r.text or 'Directory Listing' in r.text:
            leaks["sensitive_patterns"].append("CRITICAL: Directory Listing Enabled")
    except:
        pass
    
    return leaks

# ---------------- Core Probes ----------------

def probe_http_and_meta(url, rounds=ROUNDS):
    timings, headers_snaps, status_codes = [], [], []
    last_headers = {}
    last_content = ""
    session = get_session()
    
    for _ in range(rounds):
        start = time.time()
        try:
            r = session.get(url, timeout=TIMEOUT)
            end = time.time()
            timings.append(end - start)
            status_codes.append(r.status_code)
            last_headers = dict(r.headers)
            last_content = r.text
            last_content_store = r.text
            headers_snaps.append("".join(f"{k}:{v}" for k, v in sorted(r.headers.items())))
        except Exception:
            pass 

    if not timings:
        return None

    avg = round(statistics.mean(timings), 4)
    jitter = round(statistics.stdev(timings), 4) if len(timings) > 1 else 0.0
    
    # Extract Metadata & Links
    title = "N/A"
    desc = "N/A"
    emails = []
    
    if last_content:
        t_m = re.search(r'<title>(.*?)</title>', last_content, re.IGNORECASE | re.DOTALL)
        if t_m: title = t_m.group(1).strip()
        
        d_m = re.search(r'<meta\s+name=["\']description["\']\s+content=[\"\'](.+?)["\']', last_content, re.IGNORECASE)
        if d_m: desc = d_m.group(1).strip()
        
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', last_content)))
    
    links = extract_links(last_content)

    return {
        "avg_response_time": avg,
        "jitter": jitter,
        "status_codes": status_codes,
        "headers": last_headers,
        "last_content": last_content_store if 'last_content_store' in locals() else "",
        "metadata": {"title": title, "description": desc, "emails": emails},
        "links": links
    }

def probe_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {"ip": ip}
    except:
        return {"ip": "Unknown"}

def probe_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": cert.get('issuer'),
                    "not_before": cert.get('notBefore'),
                    "not_after": cert.get('notAfter')
                }
    except Exception as e:
        return {"issuer": [[(str(e),)]], "not_before": "N/A", "not_after": "N/A"}

def detect_waf(headers):
    server = headers.get('Server', '').lower()
    powered = headers.get('X-Powered-By', '').lower()
    clues = server + powered
    wafs = []
    if 'cloudflare' in clues: wafs.append('Cloudflare')
    if 'akamai' in clues: wafs.append('Akamai')
    if 'imperva' in clues: wafs.append('Imperva')
    return wafs or ['None Detected']

def security_headers_score(headers):
    required = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
    present = [h for h in required if h in headers]
    score = int((len(present) / len(required)) * 100) if required else 0
    return {"score": score, "present": present}

def vulnerability_advisor(scan_data):
    """Metasploit-style Intelligence Engine: Analyzes ALL signals for critical vectors"""
    intel = []
    headers = scan_data.get('http', {}).get('headers', {})
    ports = scan_data.get('ports', [])
    paths = scan_data.get('recon_paths', [])
    
    for p in paths:
        if "[EXIST]" in p:
            intel.append(f"[CRITICAL] FILE EXPOSURE: {p} - High risk of data leak.")
        if ".env" in p or "config" in p:
            intel.append(f"[CRITICAL] CONFIG LEAK: Sensitive credentials in {p}")
        if ".git" in p:
            intel.append("[CRITICAL] SOURCE LEAK: .git repository exposed.")
        if "wp-config" in p or "wp-login" in p:
            intel.append("[INFO] Target uses WordPress. Check for plugin CVEs.")
        if "xmlrpc.php" in p:
            intel.append("[MEDIUM] XML-RPC Enabled: Vulnerable to SSRF/Brute Force.")

    # 2. Web Vulnerabilities (OWASP Based)
    if 'Content-Security-Policy' not in headers:
        intel.append("[LOW] Missing CSP: Potential XSS/Injection vector.")
    if 'Strict-Transport-Security' not in headers:
        intel.append("[MEDIUM] Missing HSTS: Vulnerable to SSL Stripping / MITM.")
    if 'X-Frame-Options' not in headers:
        intel.append("[LOW] Missing X-Frame-Options: Risk of Clickjacking.")

    # 3. Port-Specific Intelligence (Metasploit/Nmap Vectors)
    for p in ports:
        p_lower = p.lower()
        if 'port 21' in p_lower:
            intel.append("[HIGH] FTP Detected: Check for 'anonymous' login or Cleartext exploits.")
        if 'port 22' in p_lower:
            intel.append("[MEDIUM] SSH Detected: Bruteforce target. Check for 'libssh' auth bypass.")
        if 'port 23' in p_lower:
            intel.append("[CRITICAL] Telnet Detected: Legacy protocol. All data sent in cleartext.")
        if 'port 445' in p_lower or 'smb' in p_lower:
            intel.append("[CRITICAL] SMB Detected: Potential EternalBlue target.")
        if 'port 3306' in p_lower or 'mysql' in p_lower:
            intel.append("[HIGH] MySQL Exposed: Potential SQLi vector.")
        if 'port 3389' in p_lower or 'rdp' in p_lower:
            intel.append("[CRITICAL] RDP Exposed: Target for BlueKeep.")
        if 'port 2049' in p_lower:
            intel.append("[HIGH] NFS Share Exposed: Check for misconfigured exports.")
        if 'port 6379' in p_lower:
            intel.append("[CRITICAL] Redis Exposed: Potential RCE via config manipulation.")

    # 4. Server Header Intel
    server = headers.get('Server', '').lower()
    if 'apache/2.2' in server:
        intel.append("[HIGH] Outdated Apache 2.2: Multiple CVEs (RCE/DoS) known.")
    if 'nginx/1.10' in server:
        intel.append("[MEDIUM] Outdated Nginx 1.10: Known vulnerabilities.")

    return intel if intel else ["[INFO] No immediate critical vulnerabilities detected."]

# ---------------- Exploitation Research Engine ----------------

def exploit_research(vulns):
    """Research exploits for discovered vulnerabilities"""
    exploits = []
    for v in vulns:
        if "EternalBlue" in v:
            exploits.append("MSF: exploit/windows/smb/ms17_010_eternalblue")
        if "BlueKeep" in v:
            exploits.append("MSF: exploit/windows/rdp/cve_2019_0708_bluekeep_rce")
        if "Redis" in v and "RCE" in v:
            exploits.append("MSF: exploit/linux/redis/redis_replication_cmd_exec")
    return exploits if exploits else ["No automatic exploits available."]

def generate_scanner_commands(scan_data):
    """Generate scanner commands based on scan results"""
    cmds = []
    domain = scan_data['url'].replace('https://', '').replace('http://', '').split('/')[0]
    cmds.append(f"nmap -sV -p- {domain}")
    cmds.append(f"nikto -h {scan_data['url']}")
    return cmds

def metasploit_console_report(scan_data):
    """Generate Metasploit-style console report"""
    report = []
    report.append("="*60)
    report.append("METASPLOIT FRAMEWORK - SCAN REPORT")
    report.append("="*60)
    report.append(f"Target: {scan_data['url']}")
    report.append(f"Timestamp: {scan_data['timestamp']}")
    report.append("")
    report.append("VULNERABILITIES:")
    for v in scan_data.get('vulns', []):
        report.append(f"  {v}")
    return "\n".join(report)

def content_diff_engine(scan_data):
    """Analyze content differences"""
    return ["Content diff analysis not implemented yet."]

def analyze(url):
    """Main analysis function"""
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    
    with ThreadPoolExecutor(max_workers=7) as executor:
        f_http = executor.submit(probe_http_and_meta, url)
        f_dns = executor.submit(probe_dns, domain)
        f_ssl = executor.submit(probe_ssl, domain)
        f_ports = executor.submit(probe_ports, domain)
        f_robots = executor.submit(probe_robots, url)
        f_recon = executor.submit(path_recon, url)
        f_subs = executor.submit(subdomain_recon, domain)
    
    http_res = f_http.result()
    if not http_res: raise Exception("Target Unreachable (Blocked or Offline)")
    
    # Detect data leaks using HTTP content
    html_content = http_res.get('html_snippet', '')
    data_leaks = detect_data_leaks(url, html_content)
    
    results = {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "http": http_res,
        "dns": f_dns.result(),
        "ssl": f_ssl.result(),
        "ports": f_ports.result(),
        "recon_paths": f_recon.result(),
        "subdomains": f_subs.result(),
        "robots": f_robots.result(),
        "waf": detect_waf(http_res['headers']),
        "security": security_headers_score(http_res['headers']),
        "data_leaks": data_leaks  # NEW: Add data leaks to results
    }
    results["vulns"] = vulnerability_advisor(results)
    results["exploit_intel"] = exploit_research(results["vulns"])
    results["audit_cmds"] = generate_scanner_commands(results)
    results["msf_report"] = metasploit_console_report(results)
    results["diff_data"] = content_diff_engine(results)
    return results

# ---------------- Flask Web Server ----------------

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    """Serve the main UI"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for scanning"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400
    
    try:
        result = analyze(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("Mustafa & Ahmed: Universal Website Scanner")
    print("Web UI Server Starting...")
    print("=" * 60)
    print("\n[*] Open your browser and navigate to:")
    print("[*] http://127.0.0.1:5000")
    print("\n[*] Press CTRL+C to stop the server\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
