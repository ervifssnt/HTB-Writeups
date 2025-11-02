# Expressway — Redacted Writeup

![Expressway](../images/Expressway.png)

> **Spoiler policy:** This machine is currently active on Hack The Box. This public writeup is **redacted** to avoid spoilers: flags, credentials, full exploit code, and sensitive artifacts have been removed. The document focuses on methodology, findings, and high-level mitigation advice.

**Box:** Expressway  
**Source:** Hack The Box  
**Difficulty:** Easy  
**OS:** Linux  
**Tags:** IPsec VPN, IKE, UDP Enumeration, PSK Cracking, Privilege Escalation, CVE-2025-32463

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Enumeration](#enumeration)
3. [Initial Access](#initial-access)
4. [Post-Access and Privilege Escalation](#post-access-and-privilege-escalation)
5. [Mitigations & Defensive Notes](#mitigations--defensive-notes)
6. [Tools & References](#tools--references)
7. [Lessons Learned](#lessons-learned)

---

## Executive Summary

Expressway is an Easy-rated Linux box focused on IPsec/IKE (VPN) enumeration and Linux privilege escalation. The attack path demonstrates UDP service enumeration to discover an IPsec endpoint (IKE), capturing PSK parameters via Aggressive Mode, cracking the PSK offline, and leveraging a local sudo-related privilege escalation (public CVE) to obtain root.

**Skills demonstrated:** UDP scanning, IKE/IPsec protocol enumeration, PSK cracking (offline), VPN configuration testing, Linux privilege escalation analysis, exploit understanding (CVE analysis).

**Attack Path Overview:**  
UDP Enumeration → IKE Service Discovery → Aggressive Mode PSK Capture → PSK Cracking → VPN Authentication → Initial Access → Local Privilege Escalation → Root

---

## Enumeration

### Initial TCP Scan

A standard TCP service scan was performed against the target host:

**Results:**
- SSH service identified on standard port (TCP 22)
- No other publicly accessible TCP services found

**Analysis:**  
The limited TCP service exposure suggested additional services might be running on:
- UDP ports (commonly overlooked)
- Non-standard ports
- Behind VPN/tunnel requirements

This prompted a comprehensive UDP scan to discover additional attack surface.

### UDP Scanning

Performing a UDP scan against common ports revealed:

**Key Discoveries:**
- IPsec/IKE service on UDP 500 (ISAKMP)
- NAT traversal behavior on UDP 4500

**Significance:**  
The target exposed an IPsec VPN endpoint, which represents a high-value attack surface for protocol-specific enumeration and potential authentication bypass techniques.

**Tools used:** `nmap` (UDP scanning), `ike-scan`

### IKE/IPsec Enumeration

Using IKE-specific enumeration tools and techniques:

**IKE Protocol Analysis:**
1. **IKE Version Detection:** Confirmed IKEv1 support
2. **Authentication Methods:** Identified XAUTH (Extended Authentication) support
3. **Cryptographic Suites:** Retrieved negotiated cipher suites (DH group, encryption, hash algorithms)

**Aggressive Mode Enumeration:**
- Performed IKEv1 Aggressive Mode probes
- Captured PSK-related parameters suitable for offline cracking

**Critical Finding:**  
IKEv1 Aggressive Mode is known to leak pre-shared key (PSK) hash material during the initial handshake, making it vulnerable to offline dictionary attacks.

---

## Initial Access

### PSK Capture and Cracking

**Process:**

1. **PSK Parameter Capture**
   - Aggressive Mode enumeration allowed capturing PSK-derived handshake data
   - Extracted hash material for offline analysis

2. **Offline PSK Cracking**
   - Used wordlist-based attacks (e.g., `rockyou.txt`)
   - Employed specialized IKE cracking tools
   - Successfully cracked the pre-shared key

3. **VPN Authentication**
   - Used the cracked PSK to complete Phase 1 of the IPsec connection
   - XAUTH credentials were required for Phase 2 authentication
   - Employed enumeration/credential techniques to proceed

**Result:**  
Authenticated session obtained as a low-privileged user on the target system.

**Note:** Explicit PSK value and any discovered credentials are redacted in this public writeup.

---

## Post-Access and Privilege Escalation

### Local Enumeration

Once a low-privileged shell was obtained, local enumeration activities included:

**System Analysis:**
- Service enumeration
- Process analysis
- File system exploration
- Configuration file review

### Privilege Escalation via CVE

**Discovery:**
- Found references to a sudo-related CVE in local files
- Identified a recent sudo NSS/chroot loading vulnerability
- Located or created exploit code targeting this vulnerability

**Exploitation Method:**
The exploit involved:
1. Crafting a controlled chroot environment
2. Leveraging the way `sudo` resolves user identities via NSS (Name Service Switch) libraries
3. Forcing `sudo` to load a malicious library constructor as root
4. Executing arbitrary code with root privileges

**Result:**  
Successfully escalated from low-privileged user to root.

**Redactions:** The exploit source, compilation commands, and any direct exploit payloads have been removed from this public version.

---

## Mitigations & Defensive Notes

### VPN Security

**IKE Protocol:**
- **Disable IKEv1 Aggressive Mode** — Migrate to IKEv2 where Aggressive Mode weaknesses are not present for PSK disclosure
- **Use IKEv2** — IKEv2 provides stronger security properties and does not suffer from Aggressive Mode vulnerabilities
- **Authentication Methods:**
  - Prefer certificate-based VPN authentication over pre-shared keys where possible
  - If PSKs must be used, ensure they are strong, high-entropy values not based on common wordlists
  - Use complex, randomly generated PSKs (minimum 20+ characters, mixed case, numbers, symbols)

**Best Practices:**
- Implement proper VPN logging and monitoring
- Use strong Diffie-Hellman groups (avoid weak groups like Group 2)
- Regularly rotate VPN credentials
- Implement rate limiting to prevent brute force attacks
- Consider implementing certificate-based authentication for production environments

### System Security

**Sudo Security:**
- Keep `sudo` and related system packages up to date to receive patches for NSS/chroot related CVEs
- Implement automated patch management
- Monitor security advisories for sudo and NSS library updates

**Monitoring & Detection:**
- Monitor for unusual sudo invocations
- Alert on `sudo -R` or uncommon flags where applicable
- Implement audit logging for privilege escalation events
- Use security monitoring tools to detect exploit attempts

**General Hardening:**
- Apply security baselines and hardening guides
- Implement least privilege access controls
- Regular security assessments and penetration testing
- Comprehensive logging and monitoring

---

## Tools & References

### Tools Used

| Category | Tools |
|----------|-------|
| **Scanning** | `nmap` (TCP/UDP scanning) |
| **VPN Enumeration** | `ike-scan` (IKE/IKEv1 enumeration) |
| **Cracking** | Wordlists (e.g., `rockyou.txt`), specialized IKE cracking tools |
| **Exploitation** | CVE-specific exploit code (redacted) |
| **System Analysis** | Standard Linux enumeration tools |

### References

- Public advisories and CVE details for the relevant sudo vulnerability (consult vendor advisories)
- IKE/IPsec protocol documentation (RFC 2409, RFC 4306)
- VPN security best practices and hardening guides
- OWASP guidelines and security resources

---

## Lessons Learned

### Technical Insights

1. **UDP Service Enumeration**
   - Always include UDP scanning in initial enumeration
   - Important services (VPNs, DNS over UDP, SNMP, etc.) can be missed by TCP-only scans
   - UDP scanning requires different techniques and may take longer but reveals critical attack surface

2. **Protocol-Level Knowledge**
   - Deep understanding of protocols (IKE v1 Aggressive Mode) translates directly into practical attack paths
   - Protocol vulnerabilities often provide reliable exploitation methods
   - Reading RFC documentation and security advisories is valuable for both attack and defense

3. **Vulnerability Management**
   - Keeping systems patched is critical (sudo CVE example)
   - Understanding how vulnerabilities work enables both exploitation and detection
   - Regular security assessments identify unpatched systems before attackers

### Documentation and Redaction

1. **Responsible Disclosure**
   - Documentation and artifacts (screenshots, config snippets) are useful for reproducing methodology in a safe, private setting
   - Must be redacted for public sharing to avoid spoiling active challenges
   - Balance between educational value and maintaining challenge integrity

2. **Educational Value**
   - Redacted writeups still provide value by explaining methodology and defensive recommendations
   - Focus on techniques and mitigations rather than step-by-step exploit details
   - Encourage readers to research and understand vulnerabilities themselves

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Difficulty:** Easy  
**Date:** Redacted

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
