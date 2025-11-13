# Hack The Box Writeups — by Erviano Florentino Susanto

This repository showcases my practical penetration-testing experience through sanitized writeups from Hack The Box machines.  
Each writeup demonstrates a full exploitation path — from enumeration to privilege escalation — with redacted sensitive data for ethical sharing.

---

## 📂 Included Machines

| Box | OS | Difficulty | Focus Areas |
|-----|----|-------------|--------------|
| [Hercules](./Hercules) | Windows | Insane | Active Directory • LDAP Injection • Shadow Credentials • AD CS (ESC3) • Kerberos Delegation |
| [Dark Zero](./DarkZero) | Windows | Hard | Active Directory • SQL Server • Kerberos • Lateral Movement |
| [Guardian](./Guardian) | Linux | Hard | Web Application • XSS • CSRF • LFI • PHP Filter Chains • Binary Exploitation |
| [Giveback](./Giveback) | Linux | Medium | WordPress GiveWP RCE • Kubernetes RBAC • PHP-CGI • Container Escape (runc) |
| [CodePartTwo](./CodePartTwo) | Linux | Easy | js2py RCE (CVE-2024-28397) • Hash Cracking • Sudo Misconfiguration |
| [Conversor](./Conversor) | Linux | Easy | XSLT Injection • Cron RCE • Weak Hash Cracking • needrestart Sudo |
| [Expressway](./Expressway) | Linux | Easy | IPsec VPN • UDP Enumeration • Privilege Escalation (CVE-2025-32463) |
| [Outbound](./Outbound) | Linux | Easy | Roundcube RCE (CVE-2025-49113) • Database Decryption • Below CVE-2025-27591 |
| [Soulmate](./Soulmate) | Linux | Easy | CrushFTP Auth Bypass (CVE-2025-31161) • Web Shell • Erlang SSH (root) |

Each folder contains a detailed **README.md** explaining methodology, key takeaways, and defensive recommendations.  
Sensitive data such as IPs, credentials, and flags are replaced with placeholders.

---

## 🧠 Skills Demonstrated

- Network and service enumeration (TCP/UDP)
- Active Directory and Kerberos exploitation
- SQL Server linked-server abuse
- Windows kernel and Linux privilege escalation (CVE analysis)
- Credential extraction and ticket manipulation
- Post-exploitation, persistence, and defense evasion concepts
- Responsible reporting and secure operational practices

---

## 🌐 Portfolio & Contact

- **Website:** [https://ervifssnt.github.io/portfolio/](https://ervifssnt.github.io/portfolio/)  
- **Email:** susantoerviano@gmail.com  
- **LinkedIn:** *https://www.linkedin.com/in/erviano-susanto-647490386/*

---

## ⚖️ Disclaimer

All testing described here was performed exclusively on **Hack The Box** infrastructure or authorized lab environments.  
These writeups are for **educational and demonstration purposes only**.  
No real-world systems were targeted or harmed.  
All sensitive information (IP addresses, credentials, flags, hashes, ticket blobs) has been **sanitized** prior to publication.

---

## 📜 License

This repository’s text content is shared under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** license.  
You may share or adapt the material for non-commercial use, with proper credit.

---

> *“Security through understanding, not obscurity.”*  
> — Erviano Florentino Susanto
