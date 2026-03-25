"""
Telnet Honeypot v2 - Zaawansowany fake shell z wirtualnym filesystem.
Haker mysli ze dostal dostep do prawdziwego Linuxa.
Session recording, sudo trap, fake download simulation.
"""

import asyncio
import random
import time
from datetime import datetime, timezone


# ===== VIRTUAL FILESYSTEM =====
VIRT_FS = {
    "/": {"type": "dir", "children": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"]},
    "/etc": {"type": "dir", "children": ["passwd", "shadow", "hosts", "hostname", "resolv.conf", "ssh", "crontab", "sudoers", "fstab", "network", "nginx"]},
    "/etc/passwd": {"type": "file", "content": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
postgres:x:112:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash
"""},
    "/etc/shadow": {"type": "file", "content": """root:$6$rOzQf7mK$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:19421:0:99999:7:::
daemon:*:19421:0:99999:7:::
admin:$6$kJ9mNpQx$yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy:19421:0:99999:7:::
mysql:!:19421:0:99999:7:::
""", "perm": "restricted"},
    "/etc/hosts": {"type": "file", "content": "127.0.0.1\tlocalhost\n127.0.1.1\tserver01\n192.168.1.100\tserver01.local\n10.0.0.5\tdb-master\n10.0.0.6\tdb-slave\n"},
    "/etc/hostname": {"type": "file", "content": "server01\n"},
    "/etc/resolv.conf": {"type": "file", "content": "nameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch local\n"},
    "/etc/ssh": {"type": "dir", "children": ["sshd_config", "ssh_host_rsa_key", "ssh_host_ed25519_key"]},
    "/etc/ssh/sshd_config": {"type": "file", "content": "Port 22\nPermitRootLogin no\nPubkeyAuthentication yes\nPasswordAuthentication yes\nMaxAuthTries 3\n"},
    "/etc/crontab": {"type": "file", "content": "# m h dom mon dow user command\n*/5 * * * * root /opt/backup.sh\n0 2 * * * admin /home/admin/scripts/db_backup.sh\n"},
    "/etc/fstab": {"type": "file", "content": "/dev/sda1 / ext4 errors=remount-ro 0 1\n/dev/sda2 /boot ext4 defaults 0 2\n/dev/sdb1 /data xfs defaults 0 0\n"},
    "/etc/nginx": {"type": "dir", "children": ["nginx.conf", "sites-enabled"]},
    "/etc/nginx/nginx.conf": {"type": "file", "content": "worker_processes auto;\nevents { worker_connections 768; }\nhttp {\n  include /etc/nginx/sites-enabled/*;\n  server {\n    listen 80;\n    server_name server01.local;\n    root /var/www/html;\n  }\n}\n"},
    "/home": {"type": "dir", "children": ["admin"]},
    "/home/admin": {"type": "dir", "children": ["Desktop", "Documents", "Downloads", ".bash_history", ".bashrc", ".profile", ".ssh", "scripts", "backup.tar.gz"]},
    "/home/admin/.bash_history": {"type": "file", "content": """mysql -u root -p
cd /var/www/html
nano config.php
systemctl restart nginx
apt update && apt upgrade -y
cat /var/log/auth.log | grep Failed
ssh admin@10.0.0.5
scp backup.tar.gz admin@10.0.0.6:/backup/
crontab -e
tail -f /var/log/syslog
docker ps
git pull origin main
"""},
    "/home/admin/.bashrc": {"type": "file", "content": "export PATH=$PATH:/usr/local/bin\nexport EDITOR=nano\nalias ll='ls -la'\nalias ..='cd ..'\n"},
    "/home/admin/.ssh": {"type": "dir", "children": ["authorized_keys", "known_hosts", "id_rsa"]},
    "/home/admin/.ssh/authorized_keys": {"type": "file", "content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... admin@workstation\n"},
    "/home/admin/.ssh/id_rsa": {"type": "file", "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbm...\n[FAKE KEY - THIS IS A HONEYPOT]\n-----END OPENSSH PRIVATE KEY-----\n", "perm": "restricted"},
    "/home/admin/scripts": {"type": "dir", "children": ["db_backup.sh", "deploy.sh", "monitor.py"]},
    "/home/admin/scripts/db_backup.sh": {"type": "file", "content": "#!/bin/bash\nmysqldump -u admin -pS3cretDB! --all-databases > /backup/db_$(date +%F).sql\n"},
    "/home/admin/Desktop": {"type": "dir", "children": []},
    "/home/admin/Documents": {"type": "dir", "children": ["passwords.txt", "network_diagram.pdf", "server_inventory.xlsx"]},
    "/home/admin/Documents/passwords.txt": {"type": "file", "content": """# Internal Service Passwords - DO NOT SHARE
# Last updated: 2024-02-15

MySQL root: S3cretDB!
PostgreSQL: pg_admin_2024
Redis: r3d1s_S3cure
MongoDB: m0ng0_Adm1n!
Admin panel: admin / P@ssw0rd123
VPN: vpn_user / VpN_2024!
Backup server (10.0.0.6): backup / B4ckup_S3rv3r

# AWS credentials (dev environment)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""},
    "/home/admin/Downloads": {"type": "dir", "children": []},
    "/var": {"type": "dir", "children": ["log", "www", "lib"]},
    "/var/log": {"type": "dir", "children": ["syslog", "auth.log", "nginx"]},
    "/var/log/auth.log": {"type": "file", "content": """Mar 15 10:22:01 server01 sshd[1234]: Accepted password for admin from 10.0.0.1 port 52432 ssh2
Mar 15 10:25:33 server01 sshd[1235]: Failed password for root from 185.143.223.15 port 44821 ssh2
Mar 15 10:25:35 server01 sshd[1235]: Failed password for root from 185.143.223.15 port 44821 ssh2
Mar 15 10:25:37 server01 sshd[1235]: Failed password for root from 185.143.223.15 port 44821 ssh2
Mar 15 10:30:12 server01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl restart nginx
"""},
    "/var/www": {"type": "dir", "children": ["html"]},
    "/var/www/html": {"type": "dir", "children": ["index.html", "config.php", "wp-config.php", ".env"]},
    "/var/www/html/config.php": {"type": "file", "content": """<?php
$db_host = 'localhost';
$db_user = 'webapp';
$db_pass = 'W3bApp_DB_2024!';
$db_name = 'production_db';
$secret_key = 'a1b2c3d4e5f6g7h8i9j0_FAKE_HONEYPOT';
?>
"""},
    "/var/www/html/.env": {"type": "file", "content": """APP_ENV=production
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=webapp
DB_PASSWORD=W3bApp_DB_2024!
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=r3d1s_S3cure
MAIL_HOST=smtp.gmail.com
MAIL_USERNAME=admin@server01.local
MAIL_PASSWORD=GM41l_P@ss!
"""},
    "/tmp": {"type": "dir", "children": []},
    "/opt": {"type": "dir", "children": ["backup.sh"]},
    "/opt/backup.sh": {"type": "file", "content": "#!/bin/bash\ntar czf /backup/full_backup_$(date +%F).tar.gz /var/www /home /etc\n"},
    "/proc": {"type": "dir", "children": ["cpuinfo", "meminfo", "version"]},
    "/proc/cpuinfo": {"type": "file", "content": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\ncpu MHz\t\t: 2400.000\ncache size\t: 35840 KB\ncpu cores\t: 4\n"},
    "/proc/meminfo": {"type": "file", "content": "MemTotal:        8167940 kB\nMemFree:         1234567 kB\nMemAvailable:    4567890 kB\nBuffers:          234567 kB\nCached:          2345678 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n"},
    "/proc/version": {"type": "file", "content": "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-044) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP\n"},
}

FAKE_PS = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169436 13284 ?        Ss   08:15   0:02 /sbin/init
root       234  0.0  0.0  72296  6780 ?        Ss   08:15   0:00 /usr/sbin/sshd -D
root       456  0.0  0.1 107984 12340 ?        Ss   08:15   0:01 /usr/lib/systemd/systemd-journald
www-data  1234  0.0  0.3 274948 23456 ?        S    08:16   0:05 nginx: worker process
www-data  1235  0.0  0.3 274948 23100 ?        S    08:16   0:04 nginx: worker process
mysql     2345  0.2  2.5 1789456 198765 ?      Sl   08:16   0:45 /usr/sbin/mysqld
root      3456  0.0  0.1 156789 12345 ?        Ss   08:16   0:00 /usr/sbin/cron -f
redis     4567  0.1  0.5 234567 45678 ?        Ssl  08:16   0:15 /usr/bin/redis-server 127.0.0.1:6379
admin     5678  0.0  0.0  21468  5124 pts/0    Ss   {time}   0:00 -bash
admin     5690  0.0  0.0  38520  3456 pts/0    R+   {time}   0:00 ps aux"""

FAKE_TOP = """top - {time} up 47 days, 3:15,  1 user,  load average: 0.12, 0.08, 0.05
Tasks: 128 total,   1 running, 127 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.3 us,  0.8 sy,  0.0 ni, 96.5 id,  0.3 wa,  0.0 hi,  0.1 si,  0.0 st
MiB Mem :   7976.5 total,   1205.6 free,   3421.2 used,   3349.7 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   4123.4 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
 2345 mysql     20   0 1789456 198765  12345 S   1.3   2.5   0:45.12 mysqld
 4567 redis     20   0  234567  45678   8901 S   0.7   0.5   0:15.34 redis-server
 1234 www-data  20   0  274948  23456   5678 S   0.3   0.3   0:05.67 nginx
    1 root      20   0  169436  13284   8452 S   0.0   0.1   0:02.01 systemd
  234 root      20   0   72296   6780   5890 S   0.0   0.1   0:00.45 sshd"""

FAKE_NETSTAT = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      234/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1233/nginx
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1233/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      2345/mysqld
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      4567/redis-server
tcp6       0      0 :::22                   :::*                    LISTEN      234/sshd"""


MOTD = """
Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 System information as of {date}

  System load:  0.12               Processes:             128
  Usage of /:   34.2% of 49.09GB   Users logged in:       1
  Memory usage: 42%                IPv4 address for eth0: 192.168.1.100
  Swap usage:   0%                 IPv4 address for eth1: 10.0.0.100

  * Ubuntu Pro delivers the most comprehensive open source security.

Last login: {lastlogin} from 10.0.0.1
"""


class TelnetHoneypot:
    def __init__(self, port: int = 2323, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "telnet"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        username = ""
        password = ""
        commands = []
        session_log = []
        cwd = "/home/admin"
        env = {
            "HOME": "/home/admin",
            "USER": "admin",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
            "HOSTNAME": "server01",
            "LANG": "en_US.UTF-8",
        }

        try:
            # Login
            writer.write(b"\r\nserver01 login: ")
            await writer.drain()
            try:
                user_data = await asyncio.wait_for(reader.readline(), timeout=60)
                username = user_data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                return

            writer.write(b"Password: ")
            await writer.drain()
            try:
                pass_data = await asyncio.wait_for(reader.readline(), timeout=60)
                password = pass_data.decode("utf-8", errors="replace").strip()
            except asyncio.TimeoutError:
                return

            # Log credentials
            if self.manager:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details={
                        "action": "login_attempt",
                        "username": username[:100],
                        "password": password[:100],
                    },
                )

            env["USER"] = username or "admin"

            # MOTD
            now = datetime.now(timezone.utc)
            motd = MOTD.format(
                date=now.strftime("%a %b %d %H:%M:%S UTC %Y"),
                lastlogin=now.strftime("%a %b %d %H:%M:%S %Y"),
            )
            writer.write(motd.encode())
            await writer.drain()

            # Shell loop
            while True:
                prompt = f"{env['USER']}@server01:{cwd}$ "
                writer.write(prompt.encode())
                await writer.drain()

                try:
                    cmd_data = await asyncio.wait_for(reader.readline(), timeout=300)
                except asyncio.TimeoutError:
                    break
                if not cmd_data:
                    break

                cmd = cmd_data.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue

                commands.append(cmd[:500])
                session_log.append({"time": time.time(), "cmd": cmd[:500]})

                # Log command
                if self.manager:
                    self.manager.log_event(
                        honeypot_type=self.name,
                        source_ip=source_ip,
                        source_port=source_port,
                        details={
                            "action": "command_executed",
                            "command": cmd[:500],
                            "cwd": cwd,
                            "username": env["USER"],
                        },
                    )

                # Process command
                if cmd in ("exit", "logout", "quit"):
                    writer.write(b"logout\r\n")
                    await writer.drain()
                    break

                response, cwd = self._process_command(cmd, cwd, env)
                # Simulate typing delay
                await asyncio.sleep(random.uniform(0.05, 0.15))
                writer.write(response.encode())
                await writer.drain()

            # Session summary
            if self.manager:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details={
                        "action": "session_ended",
                        "username": username[:100],
                        "commands": commands[:200],
                        "total_commands": len(commands),
                        "session_duration_s": round(time.time() - session_log[0]["time"], 1) if session_log else 0,
                    },
                )

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _resolve_path(self, path: str, cwd: str) -> str:
        """Rozwiazuje sciezke wzgledem cwd."""
        if not path or path == ".":
            return cwd
        if path == "~":
            return "/home/admin"
        if path.startswith("~/"):
            path = "/home/admin/" + path[2:]
        if not path.startswith("/"):
            path = cwd.rstrip("/") + "/" + path
        # Normalize
        parts = []
        for p in path.split("/"):
            if p == "" or p == ".":
                continue
            if p == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        return "/" + "/".join(parts) if parts else "/"

    def _ls(self, path: str, flags: str = "") -> str:
        """Listuje zawartosc katalogu."""
        entry = VIRT_FS.get(path)
        if not entry:
            return f"ls: cannot access '{path}': No such file or directory\n"
        if entry["type"] == "file":
            return path.split("/")[-1] + "\n"

        children = entry.get("children", [])
        if not children:
            return ""

        if "-l" in flags or "-la" in flags or "-al" in flags:
            lines = [f"total {len(children) * 4}"]
            for name in sorted(children):
                child_path = (path.rstrip("/") + "/" + name) if path != "/" else ("/" + name)
                child = VIRT_FS.get(child_path, {})
                if child.get("type") == "dir":
                    lines.append(f"drwxr-xr-x 2 admin admin 4096 Mar 15 10:22 {name}")
                else:
                    size = len(child.get("content", "")) if child else 0
                    lines.append(f"-rw-r--r-- 1 admin admin {size:>5} Mar 15 10:22 {name}")
            return "\n".join(lines) + "\n"
        else:
            # Kolorowy output
            items = []
            for name in sorted(children):
                child_path = (path.rstrip("/") + "/" + name) if path != "/" else ("/" + name)
                child = VIRT_FS.get(child_path, {})
                if child and child.get("type") == "dir":
                    items.append(name + "/")
                else:
                    items.append(name)
            return "  ".join(items) + "\n"

    def _process_command(self, cmd: str, cwd: str, env: dict) -> tuple[str, str]:
        """Przetwarza komende i zwraca (output, nowy_cwd)."""
        parts = cmd.split()
        if not parts:
            return "", cwd

        base = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        # --- CD ---
        if base == "cd":
            target = args[0] if args else "~"
            new_path = self._resolve_path(target, cwd)
            entry = VIRT_FS.get(new_path)
            if entry and entry["type"] == "dir":
                return "", new_path
            else:
                return f"bash: cd: {target}: No such file or directory\n", cwd

        # --- LS ---
        if base == "ls":
            flags = ""
            target = cwd
            for a in args:
                if a.startswith("-"):
                    flags += a
                else:
                    target = self._resolve_path(a, cwd)
            return self._ls(target, flags), cwd

        # --- CAT ---
        if base == "cat":
            if not args:
                return "", cwd
            path = self._resolve_path(args[0], cwd)
            entry = VIRT_FS.get(path)
            if not entry:
                return f"cat: {args[0]}: No such file or directory\n", cwd
            if entry["type"] == "dir":
                return f"cat: {args[0]}: Is a directory\n", cwd
            if entry.get("perm") == "restricted":
                return f"cat: {args[0]}: Permission denied\n", cwd
            return entry.get("content", "") + "\n", cwd

        # --- PWD ---
        if base == "pwd":
            return cwd + "\n", cwd

        # --- WHOAMI ---
        if base == "whoami":
            return env.get("USER", "admin") + "\n", cwd

        # --- ID ---
        if base == "id":
            return f"uid=1000({env['USER']}) gid=1000({env['USER']}) groups=1000({env['USER']}),27(sudo)\n", cwd

        # --- UNAME ---
        if base == "uname":
            if "-a" in args:
                return "Linux server01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n", cwd
            return "Linux\n", cwd

        # --- HOSTNAME ---
        if base == "hostname":
            return "server01\n", cwd

        # --- ENV ---
        if base == "env" or base == "printenv":
            return "\n".join(f"{k}={v}" for k, v in env.items()) + "\n", cwd

        # --- ECHO ---
        if base == "echo":
            text = " ".join(args)
            # Expand env vars
            for k, v in env.items():
                text = text.replace(f"${k}", v).replace(f"${{{k}}}", v)
            return text + "\n", cwd

        # --- EXPORT ---
        if base == "export":
            if args and "=" in args[0]:
                key, val = args[0].split("=", 1)
                env[key] = val
            return "", cwd

        # --- PS ---
        if base == "ps":
            now_str = datetime.now(timezone.utc).strftime("%H:%M")
            return FAKE_PS.format(time=now_str) + "\n", cwd

        # --- TOP ---
        if base == "top" or base == "htop":
            now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            return FAKE_TOP.format(time=now_str) + "\n(press q to quit - simulated)\n", cwd

        # --- NETSTAT ---
        if base == "netstat" or base == "ss":
            return FAKE_NETSTAT + "\n", cwd

        # --- IFCONFIG ---
        if base == "ifconfig" or (base == "ip" and "addr" in args):
            return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 1234567  bytes 987654321 (987.6 MB)
        TX packets 654321  bytes 123456789 (123.4 MB)

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.100  netmask 255.255.255.0  broadcast 10.0.0.255
        ether 02:42:ac:11:00:03  txqueuelen 0  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
""", cwd

        # --- HISTORY ---
        if base == "history":
            return VIRT_FS.get("/home/admin/.bash_history", {}).get("content", "") + "\n", cwd

        # --- SUDO ---
        if base == "sudo":
            return "[sudo] password for {}: \nSorry, try again.\n[sudo] password for {}: \nsudo: 3 incorrect password attempts\n".format(env["USER"], env["USER"]), cwd

        # --- WGET / CURL ---
        if base in ("wget", "curl"):
            url = args[0] if args else ""
            return f"Connecting to {url}... failed: Connection timed out.\n", cwd

        # --- RM ---
        if base == "rm":
            return f"rm: cannot remove: Operation not permitted\n", cwd

        # --- CHMOD ---
        if base in ("chmod", "chown", "chgrp"):
            return f"{base}: changing permissions: Operation not permitted\n", cwd

        # --- MKDIR ---
        if base == "mkdir":
            return f"mkdir: cannot create directory: Permission denied\n", cwd

        # --- FIND ---
        if base == "find":
            return "/home/admin/Documents/passwords.txt\n/var/www/html/.env\n/var/www/html/config.php\n/etc/ssh/sshd_config\n", cwd

        # --- GREP ---
        if base == "grep":
            pattern = args[0] if args else ""
            return f"Binary file matches\n", cwd

        # --- DF ---
        if base == "df":
            return """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        49G   17G   30G  37% /
/dev/sda2       976M  130M  780M  15% /boot
/dev/sdb1       200G   89G  111G  45% /data
tmpfs           3.9G     0  3.9G   0% /dev/shm
""", cwd

        # --- FREE ---
        if base == "free":
            return """              total        used        free      shared  buff/cache   available
Mem:        8167940     3421200     1234567      123456     3512173     4567890
Swap:       2097148           0     2097148
""", cwd

        # --- UPTIME ---
        if base == "uptime":
            return f" {datetime.now(timezone.utc).strftime('%H:%M:%S')} up 47 days,  3:15,  1 user,  load average: 0.12, 0.08, 0.05\n", cwd

        # --- W / WHO ---
        if base in ("w", "who"):
            return f"{env['USER']}   pts/0    {datetime.now(timezone.utc).strftime('%H:%M')}   0.00s  0.00s -bash\n", cwd

        # --- DATE ---
        if base == "date":
            return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y") + "\n", cwd

        # --- HEAD / TAIL ---
        if base in ("head", "tail"):
            if args:
                path = self._resolve_path(args[-1], cwd)
                entry = VIRT_FS.get(path)
                if entry and entry["type"] == "file":
                    lines = entry.get("content", "").splitlines()
                    if base == "head":
                        return "\n".join(lines[:10]) + "\n", cwd
                    else:
                        return "\n".join(lines[-10:]) + "\n", cwd
            return "", cwd

        # --- WHICH ---
        if base == "which":
            if args:
                return f"/usr/bin/{args[0]}\n", cwd
            return "", cwd

        # --- SYSTEMCTL ---
        if base == "systemctl":
            return "Failed to connect to bus: Permission denied\n", cwd

        # --- APT / YUM ---
        if base in ("apt", "apt-get", "yum", "dnf"):
            return "E: Could not open lock file - open (13: Permission denied)\n", cwd

        # --- DOCKER ---
        if base == "docker":
            return """CONTAINER ID   IMAGE          COMMAND                  STATUS          PORTS
a1b2c3d4e5f6   nginx:latest   "nginx -g 'daemon of…"  Up 47 days      0.0.0.0:80->80/tcp
f6e5d4c3b2a1   mysql:5.7      "docker-entrypoint.s…"  Up 47 days      127.0.0.1:3306->3306/tcp
""", cwd

        # --- GIT ---
        if base == "git":
            return "fatal: not a git repository\n", cwd

        # --- HELP ---
        if base == "help":
            return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nType 'help' for shell built-ins.\n", cwd

        # --- UNKNOWN ---
        return f"bash: {base}: command not found\n", cwd

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client, "0.0.0.0", self.port
        )
        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
