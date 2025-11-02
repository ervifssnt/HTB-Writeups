# Dark Zero — Redacted Writeup

![Dark Zero](../images/Darkzero.png)

> **Spoiler policy:** This multi-domain Active Directory box is currently active on Hack The Box. This public writeup is **redacted**: flags, credentials, full exploit code, and sensitive artifacts have been removed. The document focuses on high-level methodology, findings, and defensive recommendations.

**Box:** Dark Zero  
**Source:** Hack The Box  
**Difficulty:** Hard  
**OS:** Windows (Active Directory)  
**Tags:** Active Directory, SQL Server, Kerberos, Lateral Movement, Privilege Escalation, DCSync

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Reconnaissance & Initial Access](#reconnaissance--initial-access)
3. [Lateral Movement](#lateral-movement)
4. [Privilege Escalation](#privilege-escalation)
5. [Kerberos Ticket Capture & DCSync](#kerberos-ticket-capture--dcsync)
6. [Mitigations & Defensive Recommendations](#mitigations--defensive-recommendations)
7. [Tools & References](#tools--references)
8. [Lessons Learned](#lessons-learned)

---

## Executive Summary

Dark Zero is an advanced Active Directory engagement requiring SQL Server exploitation, lateral movement via linked servers, Windows kernel privilege escalation, and Kerberos ticket manipulation. The high-level attack chain includes obtaining initial credentials for a low-privileged domain account, exploiting MS-SQL linked server trust relationships to execute commands on a second domain segment, achieving code execution, leveraging a local Windows kernel CVE for SYSTEM privileges, harvesting credentials (LSA secrets), capturing machine Kerberos tickets, and performing DCSync/replication to extract domain credentials for full compromise.

**Skills demonstrated:** SQL Server exploitation, linked server pivoting, Windows post-exploitation (Mimikatz/Kiwi), Kerberos ticket capture & reuse (Rubeus), DCSync via RPC, kernel exploit usage for privilege escalation, and domain compromise techniques.

**Attack Path Overview:**  
Initial Access → SQL Server Enumeration → Linked Server Exploitation → Lateral Movement → Kernel Exploit → Credential Harvesting → Kerberos Ticket Capture → DCSync → Domain Compromise

---

## Reconnaissance & Initial Access

### Network Enumeration

Comprehensive port scanning revealed typical Active Directory-related services:
- DNS (TCP/UDP 53)
- Kerberos (TCP/UDP 88)
- LDAP (TCP 389, 636)
- SMB (TCP 445)
- MS-SQL Server (TCP 1433)

A reachable MS-SQL instance was identified, which became the initial attack vector.

### Credential Discovery

Initial credentials were obtained through:
- Provided credentials in the challenge
- Or discovered via enumeration techniques (password spraying, credential stuffing)

These credentials were validated against multiple services:
- SMB shares
- LDAP authentication
- MS-SQL Server login

### SQL Server Enumeration

Once authenticated to the SQL Server, enumeration focused on:
- Database structure and permissions
- Stored procedures and functions
- **Linked servers** (critical finding)

**Linked Server Discovery:**
A linked server configuration was found pointing to a second domain segment (or domain controller). This provided an avenue for lateral movement and privilege escalation.

**Tools used:** `nmap`, `dig`, `crackmapexec`, `impacket-mssqlclient`

**Redactions:** Specific credential values and internal IP addresses are omitted here.

---

## Lateral Movement

### Linked Server Exploitation

By leveraging SQL Server's linked server functionality, the attacker was able to:
1. Authenticate to the remote linked server
2. Operate in a higher-privileged SQL context on the remote host
3. Enable remote command execution (e.g., enabling `xp_cmdshell`)
4. Drop and execute a payload on the remote host

**Result:**  
Reverse shell established on the remote linked server, providing interactive access to a second domain segment.

---

## Privilege Escalation

### Windows Kernel Exploit

From the reverse shell on the Windows host, a known Windows kernel privilege escalation vulnerability was leveraged to gain SYSTEM privileges.

**Process:**
1. Identified vulnerable kernel component
2. Exploited the vulnerability to escalate from standard user to SYSTEM
3. Obtained full system access

### Credential Harvesting

With SYSTEM privileges, credential harvesting tools were used to extract:
- **NTLM password hashes** from the Security Account Manager (SAM)
- **LSA secrets** (including service account passwords)
- **Machine account credentials**

**Tools:** Mimikatz/Kiwi, secretsdump

**Extracted Artifacts:**
- Service account credentials (high privilege)
- Machine account artifacts
- Additional credential material for lateral movement

**Redactions:** Specific hashes, tickets, and credential values are omitted.

---

## Kerberos Ticket Capture & DCSync

### Ticket Capture Strategy

A combination of techniques was used to capture Kerberos tickets:

1. **Authentication Monitoring:** Monitored for Kerberos ticket activity across trusted boundaries
2. **Forced Authentication:** Used various techniques to force authentication from privileged accounts
3. **Ticket Interception:** Captured TGT/TGS tickets for domain controller machine accounts

### Ticket Conversion & Injection

The captured Kerberos tickets were:
1. **Converted** from kirbi format to ccache format
2. **Injected** locally to authenticate as the machine account
3. **Validated** to ensure successful authentication

### DCSync Attack

With machine account credentials (via ticket), the attacker:
1. Performed authenticated replication calls (DCSync) against the domain controller
2. Extracted domain credentials (NTLM hashes) for all domain users
3. Used these hashes to authenticate to the domain controller
4. Accessed domain admin accounts

**Result:**  
Full domain compromise achieved through credential extraction.

**Redactions:** Raw ticket blobs, hashes, and exact command outputs are omitted.

---

## Mitigations & Defensive Recommendations

### SQL Server and Application Controls

**Immediate Actions:**
- Disable or tightly control `xp_cmdshell` on SQL Server instances
- Audit and restrict linked server configurations
- Remove unnecessary linked server trusts
- Ensure service accounts run with minimal required privileges
- **Never** use domain admin accounts for SQL services

**Best Practices:**
- Implement SQL Server security baselines
- Regular security audits of SQL configurations
- Use principle of least privilege for all database accounts
- Monitor for unusual SQL Server activity
- Implement network segmentation for database servers

### Active Directory and Kerberos

**Detection & Monitoring:**
- Monitor for unusual replication patterns (DCSync attempts)
- Alert on suspicious account usage patterns
- Protect and audit service account credentials
- Monitor LSA secret access attempts

**Kerberos Hardening:**
- Enforce time synchronization (Kerberos is time-sensitive)
- Monitor for time-skew anomalies that facilitate Kerberos abuse
- Implement Protected Users group for high-value accounts
- Enable Kerberos logging and monitoring

**Domain Controller Security:**
- Harden domain controllers with vendor security baselines
- Apply vendor patches for known kernel vulnerabilities immediately
- Implement domain controller isolation where possible
- Regular security assessments and penetration testing

### General Security Controls

**Endpoint Protection:**
- Implement EDR/endpoint protections to detect credential dumping tools
- Monitor for execution of Mimikatz, Rubeus, and similar tools
- Implement application allowlisting where feasible
- Enable Windows Defender Advanced Threat Protection (ATP)

**Network Security:**
- Enforce least privilege and network segmentation
- Limit lateral movement through network zoning
- Implement proper firewall rules
- Monitor for unusual authentication patterns

**Incident Response:**
- Establish baseline network behavior
- Implement SIEM for centralized logging
- Create detection rules for common attack techniques
- Develop incident response playbooks for AD compromise scenarios

---

## Tools & References

### Tools Used

| Category | Tools |
|----------|-------|
| **Reconnaissance** | `nmap`, `dig` |
| **Authentication & Access** | `crackmapexec`, `impacket-mssqlclient`, `impacket` suite |
| **Lateral Movement** | SQL Server linked server queries, RPC tools |
| **Exploitation** | Windows kernel exploit, `msfvenom`, `metasploit-framework` |
| **Post-Exploitation** | Mimikatz/Kiwi, Rubeus, `evil-winrm`, `secretsdump` |
| **Credential Management** | Ticket conversion tools (kirbi → ccache) |

### References

- CVE advisories and vendor patches for referenced kernel vulnerabilities
- Active Directory & Kerberos documentation for defensive context
- OWASP guidelines for application security
- Microsoft Security Baselines for Windows and SQL Server

---

## Lessons Learned

### Technical Insights

1. **SQL Server Linked Servers**
   - Linked servers and cross-server trust relationships are high-risk features
   - Enumerate and monitor them closely
   - Implement strict access controls and audit all linked server activity
   - Consider the security implications before deploying linked server configurations

2. **Kerberos Security**
   - Machine account tickets and Kerberos artifacts are powerful for replication and domain-level attacks
   - Proper protection requires monitoring, time synchronization, and privilege restrictions
   - DCSync attacks demonstrate the importance of restricting replication permissions
   - Implement Protected Users group for sensitive accounts

3. **Defense in Depth**
   - Combining multiple techniques (SQL pivoting, kernel exploits, Kerberos manipulation) yields realistic domain compromise scenarios
   - Defense-in-depth matters: no single control prevents all attacks
   - Layered security controls are essential for Active Directory environments
   - Regular security assessments identify weaknesses before attackers exploit them

### Security Principles

- **Least Privilege:** Service accounts should have minimal required permissions
- **Network Segmentation:** Limit lateral movement through proper network design
- **Monitoring & Detection:** Comprehensive logging and monitoring are essential
- **Patch Management:** Keep systems updated, especially domain controllers
- **Credential Management:** Protect service accounts and machine accounts rigorously

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Difficulty:** Hard  
**Date:** Redacted

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
