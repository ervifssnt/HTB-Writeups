# Dark Zero — Hack The Box (Sanitized)

**Difficulty:** Hard  
**Platform:** Windows / Active Directory  
**Author:** Erviano Florentino Susanto  
**Date:** October 17, 2025

---

## Summary
This sanitized report documents a multi-domain Active Directory compromise. Sensitive details (IPs, credentials, flags, hashes, ticket blobs) are redacted. The purpose of the public writeup is to show methodology and defensive insights, not to publish secrets.

High-level scenario: initial low-privilege SQL access → linked-server lateral movement → remote command execution → local kernel LPE (CVE-2024-30088) → credential harvesting → Kerberos ticket capture → Pass-the-Ticket and DCSync → domain compromise.

---

## Quick facts
- **OS:** Windows Server (AD)  
- **Core technologies:** Microsoft SQL Server, Kerberos, Windows kernel exploit  
- **Key CVE referenced:** CVE-2024-30088 (Windows kernel LPE)  
- **Sanitized artifacts:** `<REDACTED_IP>`, `<REDACTED_CREDENTIALS>`, `<REDACTED_FLAG>`, `<REDACTED_HASH>`, `<REDACTED_TICKET>`

---

## High-level attack flow (Mermaid)
```mermaid
flowchart TD
  A[Initial Access: <REDACTED_CREDENTIALS>] --> B[MS-SQL Server Enumeration]
  B --> C[Linked Server Discovery]
  C --> D[Use linked server → enable xp_cmdshell → RCE on remote host]
  D --> E[Deploy reverse shell → establish session as service account]
  E --> F[Local Privilege Escalation: CVE-2024-30088 → SYSTEM]
  F --> G[Credential Harvesting (Kiwi / LSA secrets)]
  G --> H[Rubeus: Monitor for machine TGTs → capture <REDACTED_TICKET>]
  H --> I[Pass-the-Ticket + DCSync → extract domain NTLM hash]
  I --> J[Pass-the-Hash / Domain Admin → full domain compromise]
