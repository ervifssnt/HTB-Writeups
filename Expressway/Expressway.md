# Expressway — Redacted Writeup

> **Spoiler policy:** This machine is currently active on Hack The Box. This public writeup is **redacted** to avoid spoilers: flags, credentials, full exploit code, and sensitive artifacts have been removed. The document focuses on methodology, findings, and high-level mitigation advice.

**Box:** Expressway  
**Source:** Hack The Box  
**Difficulty:** Easy  
**OS:** Linux  

---

## Executive summary
Expressway is an Easy-rated Linux box focused on IPsec/IKE (VPN) enumeration and Linux privilege escalation. The attack path demonstrates UDP service enumeration to discover an IPsec endpoint (IKE), capturing PSK parameters via Aggressive Mode, cracking the PSK offline, and leveraging a local sudo-related privilege escalation (public CVE) to obtain root.

**Skills demonstrated:** UDP scanning, IKE/IPsec protocol enumeration, PSK cracking (offline), VPN configuration testing, Linux privilege escalation analysis, exploit understanding (CVE analysis).

---

## Enumeration

### Initial TCP scan
A standard TCP service scan showed only an SSH service on the host's public TCP ports. This suggested additional services on UDP or non-standard ports should be checked.

### UDP scanning
Performing a UDP scan against common ports revealed an IPsec/IKE service on UDP 500 (ISAKMP) and related NAT traversal behavior on UDP 4500. This indicated the target exposed an IPsec VPN endpoint — a high-value surface for further protocol-specific enumeration.

**Tools used:** `nmap`, `ike-scan`

### IKE/IPsec enumeration
Using IKE-specific probes (ike-scan and nmap IKE scripts) confirmed IKEv1 support with XAUTH and provided details about the negotiated suites (e.g., DH group and cipher families). An Aggressive Mode probe returned PSK-related parameters suitable for offline cracking (this is a known weakness of IKEv1 Aggressive Mode).

---

## Initial access (high-level)
Aggressive Mode enumeration allowed capturing the PSK-derived handshake data. The captured PSK parameters were cracked offline using a wordlist; this yielded a readable pre-shared key. With the PSK validated, Phase 1 of an IPsec connection could be completed, at which point XAUTH credentials were required for user authentication. Enumeration/credential techniques were then used to proceed toward an authenticated session as a low-privileged user.

**Note:** explicit PSK value and any discovered credentials are redacted in this public writeup.

---

## Post-access and privilege escalation (high-level)
Once a low-privileged shell was obtained, local enumeration discovered a set of scripts and an exploit flow referencing a sudo-related CVE (referenced generically as a recent sudo NSS/chroot loading issue). The exploit method involved crafting a controlled chroot environment and leveraging the way `sudo` resolves identities via NSS libraries to run a constructor in a library as root — resulting in privilege escalation.

**Redactions:** the exploit source, compilation commands, and any direct exploit payloads have been removed from this public version.

---

## Mitigations & defensive notes
- Disable IKEv1 Aggressive Mode or migrate to IKEv2 where Aggressive Mode weaknesses are not present for PSK disclosure.
- Prefer certificate-based VPN authentication over pre-shared keys where possible.
- Use strong, high-entropy PSKs not based on common wordlists.
- Keep `sudo` and related system packages up to date to receive patches for NSS/chroot related CVEs.
- Monitor for unusual sudo invocations and chroot usage; alert on `sudo -R` or uncommon flags where applicable.

---

## Tools & references
- `nmap` (TCP/UDP scanning)
- `ike-scan` (IKE/IKEv1 enumeration)
- Wordlists for offline cracking (e.g., rockyou for demonstration)
- Public advisories and CVE details for the relevant sudo vulnerability (consult vendor advisories)

---

## Lessons learned
1. Always include UDP scanning in initial enumeration; important services (VPNs, DNS over UDP, etc.) can be missed by TCP-only scans.
2. Protocol-level knowledge (IKE v1 Aggressive Mode) translates directly into practical attack paths.
3. Documentation and artifacts (screenshots, config snippets) are useful for reproducing methodology in a safe, private setting but must be redacted for public sharing.
