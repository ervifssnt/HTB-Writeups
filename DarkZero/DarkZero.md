# Dark Zero — Redacted Writeup

> **Spoiler policy:** This multi-domain AD box is currently active on Hack The Box. This public writeup is **redacted**: flags, credentials, full exploit code, and sensitive artifacts have been removed. The document focuses on high-level methodology, findings, and defensive recommendations.

**Box:** Dark Zero  
**Source:** Hack The Box  
**Difficulty:** Hard  
**OS:** Windows (Active Directory)  

---

## Executive summary
Dark Zero is an advanced Active Directory engagement requiring SQL Server exploitation, lateral movement via linked servers, Windows kernel privilege escalation, and Kerberos ticket manipulation. The high-level attack chain includes obtaining initial credentials for a low-privileged domain account, exploiting MS-SQL linked server trust relationships to execute commands on a second domain segment, achieving code execution, leveraging a local Windows kernel CVE for SYSTEM privileges, harvesting credentials (LSA secrets), capturing machine Kerberos tickets, and performing DCSync/replication to extract domain credentials for full compromise.

**Skills demonstrated:** SQL Server exploitation, linked server pivoting, Windows post-exploitation (Mimikatz/Kiwi), Kerberos ticket capture & reuse (Rubeus), DCSync via RPC, kernel exploit usage for privilege escalation, and domain compromise techniques.

---

## Reconnaissance & initial access (high-level)
Comprehensive port scanning revealed typical AD-related services (DNS, Kerberos, LDAP, SMB) and a reachable MS-SQL instance. A set of provided or discovered credentials validated against SMB/LDAP/MS-SQL allowed authenticated interactions with the SQL service. Using SQL Server enumeration (linked servers discovery), a linked server pointing to a second domain segment (or controller) was found — this provided an avenue for lateral movement and privilege escalation by leveraging server-side execution (`xp_cmdshell` or equivalent) on the linked server context.

**Tools used:** `nmap`, `dig`, `crackmapexec`, `impacket-mssqlclient`

**Redactions:** specific credential values and internal IP addresses are omitted here.

---

## Lateral movement & execution
By leveraging linked server functionality, the attacker was able to authenticate as a higher-privileged SQL context on the remote linked host and enable remote command execution (e.g., enabling `xp_cmdshell`). This allowed dropping and executing a payload on the remote host, leading to a reverse shell and subsequent interactive access.

## Privilege escalation on Windows host (high-level)
From the reverse shell, a known Windows kernel privilege escalation was leveraged to gain SYSTEM privileges. With SYSTEM, credential harvesting tools (Kiwi/Mimikatz) were used to dump NTLM hashes and LSA secrets, which yielded service account credentials and machine account artifacts.

---

## Kerberos ticket capture & DCSync
A combination of monitoring for Kerberos ticket activity and forcing authentication across the trusted boundary allowed capturing a machine TGT/TGS for a domain controller machine account. That ticket was converted and injected locally (kirbi → ccache workflow), enabling authenticated replication calls (DCSync) against the domain controller and extraction of domain credentials (NTLM hashes). These hashes were then used to authenticate to the domain controller and access the domain admin account, completing domain compromise.

**Redactions:** raw ticket blobs, hashes, and exact command outputs are omitted.

---

## Mitigations & defensive recommendations
**SQL Server and Application Controls**
- Disable or tightly control `xp_cmdshell`.
- Audit and restrict linked server configurations and remove unnecessary trusts.
- Ensure service accounts do not run with excessive privileges and avoid using domain admin accounts for SQL services.

**Active Directory and Kerberos**
- Monitor for unusual replication and account usage patterns (DCSync attempts).
- Protect and audit service account credentials and LSA secrets.
- Enforce time sync and monitor for time-skew anomalies that facilitate Kerberos abuse.
- Harden domain controllers and apply vendor patches for known kernel vulnerabilities.

**General**
- Implement EDR/endpoint protections to detect credential dumping and Rubeus/Mimikatz usage.
- Enforce least privilege and network segmentation to limit lateral movement.

---

## Tools & references
- `nmap`, `dig`, `crackmapexec`, `impacket`, `msfvenom`, `metasploit-framework`, Mimikatz/Kiwi, Rubeus, `evil-winrm`
- CVE advisories and vendor patches for referenced kernel vulnerabilities
- AD & Kerberos documentation for defensive context

---

## Lessons learned
1. SQL Server linked servers and cross-server trust relationships are high-risk features — enumerate and monitor them closely.
2. Machine account tickets and Kerberos artifacts can be powerful for replication and domain-level attacks if not properly protected.
3. Combining multiple techniques (SQL pivoting, kernel exploits, Kerberos manipulation) yields realistic domain compromise scenarios — defense-in-depth matters.
