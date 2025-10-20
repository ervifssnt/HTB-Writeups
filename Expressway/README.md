
---

# `Expressway/README.md` (sanitized)
```markdown
# Expressway — Hack The Box (Sanitized)

**Difficulty:** Easy  
**Platform:** Linux / IPsec VPN exploitation  
**Author:** Erviano Florentino Susanto  
**Date:** November 17, 2025

---

## Summary
Sanitized writeup covering a VPN-based access vector and subsequent Linux privilege escalation via a sudo NSS library injection (CVE-2025-32463). All secrets (PSKs, flags, IPs) are redacted in this public version.

High-level scenario: UDP enumeration → IKEv1 Aggressive Mode probe → capture PSK hash → offline cracking → VPN Phase 1 success → XAUTH prompt → internal access (user `ike`) → discovered exploit scripts → local sudo NSS exploit → root.

---

## Quick facts
- **OS:** Linux  
- **Core technologies:** IPsec / IKE (ISAKMP), VPN, sudo / NSS library loading  
- **Key CVE referenced:** CVE-2025-32463 (sudo NSS library injection)  
- **Sanitized artifacts:** `<REDACTED_IP>`, `<REDACTED_PSK_HASH>`, `<REDACTED_PSK>`, `<REDACTED_FLAG>`

---

## High-level attack flow (Mermaid)
```mermaid
flowchart TD
  A[UDP scan → discover ISAKMP (500/4500)] --> B[IKEv1 Aggressive Mode probe]
  B --> C[Capture PSK hash (redacted)]
  C --> D[Offline PSK cracking → PSK found (redacted)]
  D --> E[VPN Phase 1 success → XAUTH required]
  E --> F[Obtain foothold as user 'ike' (sanitized)]
  F --> G[Enumerate home directory → find exploit scripts]
  G --> H[Execute NSS-library-based sudo -R exploit (CVE-2025-32463)]
  H --> I[Root shell obtained → root flag redacted]

