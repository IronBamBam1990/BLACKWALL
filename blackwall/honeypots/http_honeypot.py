"""
HTTP Honeypot v2 - Fake panel admina z wieloma trap pages.
Router admin, WordPress login, phpMyAdmin, fake .env, directory listing z backup.
"""

import asyncio
from datetime import datetime, timezone
from urllib.parse import parse_qs

# ===== TRAP PAGES =====

PAGE_ROUTER_LOGIN = """<!DOCTYPE html>
<html><head><title>Router Admin Panel</title>
<style>
body{font-family:Arial;background:#1a1a2e;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login-box{background:#16213e;padding:40px;border-radius:10px;box-shadow:0 0 20px rgba(0,0,0,0.5);width:350px}
h2{color:#e94560;text-align:center;margin-bottom:30px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #0f3460;border-radius:5px;background:#1a1a2e;color:#fff;box-sizing:border-box}
button{width:100%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:16px;margin-top:15px}
.info{color:#666;font-size:11px;text-align:center;margin-top:15px}
</style></head><body>
<div class="login-box">
<h2>&#x1F512; Admin Panel</h2>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
<div class="info">Firmware v4.2.1 | Default: admin/admin</div>
</div></body></html>"""

PAGE_WORDPRESS = """<!DOCTYPE html>
<html><head><title>WordPress &rsaquo; Log In</title>
<style>
body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif}
#login{width:320px;margin:0 auto;padding:8% 0 0}
.login h1 a{background-image:url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MDAgNDAwIj48cGF0aCBmaWxsPSIjMDA3MmE4IiBkPSJNMjAwIDBoMjAwdjIwMEgyMDB6Ii8+PC9zdmc+);width:84px;height:84px;display:block;margin:0 auto 25px}
#loginform{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
label{font-size:14px;color:#1d2327}
input[type=text],input[type=password]{width:100%;padding:3px 5px;margin:2px 6px 16px 0;border:1px solid #8c8f94;border-radius:4px;font-size:24px;box-sizing:border-box}
input[type=submit]{background:#2271b1;border:1px solid #2271b1;color:#fff;padding:0 12px;font-size:13px;height:36px;border-radius:3px;cursor:pointer;width:100%}
</style></head><body class="login">
<div id="login">
<h1><a href="/"></a></h1>
<form id="loginform" method="POST" action="/wp-login.php">
<p><label for="user_login">Username or Email<br>
<input type="text" name="log" id="user_login" size="20" autocapitalize="off"></label></p>
<p><label for="user_pass">Password<br>
<input type="password" name="pwd" id="user_pass" size="20"></label></p>
<p><input type="submit" value="Log In" id="wp-submit"></p>
</form>
<p><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div></body></html>"""

PAGE_PHPMYADMIN = """<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>
body{font-family:sans-serif;background:#eff1f3;margin:0;padding:40px}
.container{max-width:500px;margin:0 auto;background:#fff;border-radius:5px;padding:30px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}
h1{color:#333;font-size:20px;border-bottom:2px solid #e76f51;padding-bottom:10px;margin-bottom:20px}
label{display:block;margin:10px 0 5px;font-size:13px;color:#555}
input[type=text],input[type=password],select{width:100%;padding:8px;border:1px solid #ccc;border-radius:3px;box-sizing:border-box;font-size:14px}
select{height:38px}
button{background:#e76f51;color:#fff;border:none;padding:10px 20px;border-radius:3px;cursor:pointer;font-size:14px;margin-top:15px}
.version{color:#999;font-size:11px;text-align:center;margin-top:20px}
</style></head><body>
<div class="container">
<h1>phpMyAdmin 5.2.1</h1>
<form method="POST" action="/phpmyadmin/index.php">
<label>Username:</label>
<input type="text" name="pma_username" value="">
<label>Password:</label>
<input type="password" name="pma_password">
<label>Server Choice:</label>
<select name="server"><option>localhost (127.0.0.1)</option><option>db-master (10.0.0.5)</option></select>
<br><button type="submit">Go</button>
</form>
<div class="version">phpMyAdmin 5.2.1 | MySQL 5.7.42</div>
</div></body></html>"""

PAGE_ENV = """APP_NAME=ProductionApp
APP_ENV=production
APP_KEY=base64:aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789FAKE=
APP_DEBUG=false
APP_URL=https://server01.local

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=production_db
DB_USERNAME=webapp
DB_PASSWORD=W3bApp_DB_2024!

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=r3d1s_S3cure
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=admin@server01.local
MAIL_PASSWORD=GM41l_P@ss!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=production-uploads

STRIPE_KEY=pk_live_FAKE_KEY_HONEYPOT
STRIPE_SECRET=sk_live_FAKE_SECRET_HONEYPOT
"""

PAGE_BACKUP_DIR = """<!DOCTYPE html>
<html><head><title>Index of /backup/</title></head><body>
<h1>Index of /backup/</h1>
<pre>
<a href="../">../</a>
<a href="full_backup_2024-03-10.tar.gz">full_backup_2024-03-10.tar.gz</a>     10-Mar-2024 02:00  2.3G
<a href="full_backup_2024-03-11.tar.gz">full_backup_2024-03-11.tar.gz</a>     11-Mar-2024 02:00  2.3G
<a href="db_dump_2024-03-12.sql">db_dump_2024-03-12.sql</a>            12-Mar-2024 02:00  456M
<a href="ssh_keys_backup.tar">ssh_keys_backup.tar</a>               08-Mar-2024 15:30   12K
<a href="credentials.xlsx">credentials.xlsx</a>                  01-Mar-2024 09:15   45K
<a href=".htpasswd">.htpasswd</a>                         15-Feb-2024 11:20    1K
</pre></body></html>"""

PAGE_401 = """<html><body><h1>401 - Invalid Credentials</h1><p>Access denied. This attempt has been logged.</p><a href="/">Try again</a></body></html>"""
PAGE_403 = """<html><body><h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>"""
PAGE_404 = """<html><body><h1>404 Not Found</h1></body></html>"""

# Mapowanie URL -> page
TRAP_PAGES = {
    "/": "router",
    "/login": "router",
    "/admin": "router",
    "/admin/login": "router",
    "/wp-login.php": "wordpress",
    "/wp-admin": "wordpress",
    "/wordpress/wp-login.php": "wordpress",
    "/phpmyadmin": "phpmyadmin",
    "/phpmyadmin/": "phpmyadmin",
    "/phpmyadmin/index.php": "phpmyadmin",
    "/pma": "phpmyadmin",
    "/myadmin": "phpmyadmin",
    "/.env": "env",
    "/backup": "backup_dir",
    "/backup/": "backup_dir",
}

PAGE_MAP = {
    "router": PAGE_ROUTER_LOGIN,
    "wordpress": PAGE_WORDPRESS,
    "phpmyadmin": PAGE_PHPMYADMIN,
    "env": PAGE_ENV,
    "backup_dir": PAGE_BACKUP_DIR,
}


class HTTPHoneypot:
    def __init__(self, port: int = 8080, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "http"

    def _make_response(self, status: str, body: str, content_type: str = "text/html") -> bytes:
        now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        headers = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {content_type}; charset=UTF-8\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"Server: Apache/2.4.41 (Ubuntu)\r\n"
            f"X-Powered-By: PHP/7.4.3\r\n"
            f"Date: {now}\r\n"
            f"Connection: close\r\n"
            f"Set-Cookie: PHPSESSID=fake_{id(self):x}; path=/; HttpOnly\r\n"
            f"\r\n"
        )
        return headers.encode() + body.encode()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        try:
            request_data = b""
            try:
                request_data = await asyncio.wait_for(reader.read(16384), timeout=30)
            except asyncio.TimeoutError:
                pass

            if not request_data:
                return

            request_text = request_data.decode("utf-8", errors="replace")
            lines = request_text.split("\r\n")
            request_line = lines[0] if lines else ""

            # Parse headers and body
            headers = {}
            body = ""
            header_done = False
            for line in lines[1:]:
                if not header_done:
                    if line == "":
                        header_done = True
                    elif ":" in line:
                        key, val = line.split(":", 1)
                        headers[key.strip().lower()] = val.strip()
                else:
                    body += line

            parts = request_line.split(" ")
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else "/"

            # Clean path
            path_clean = path.split("?")[0].rstrip("/") or "/"

            # Log request
            details = {
                "action": "http_request",
                "method": method,
                "path": path[:500],
                "request_line": request_line[:500],
                "user_agent": headers.get("user-agent", "unknown")[:300],
                "referer": headers.get("referer", "")[:200],
                "content_type": headers.get("content-type", "")[:100],
                "headers": {k: v[:200] for k, v in list(headers.items())[:20]},
            }

            # Check POST credentials
            if method == "POST" and body:
                try:
                    params = parse_qs(body)
                    creds = {}
                    # Router login
                    for ufield in ("username", "log", "pma_username", "user", "email"):
                        if ufield in params:
                            creds["username"] = params[ufield][0][:100]
                            break
                    for pfield in ("password", "pwd", "pma_password", "pass"):
                        if pfield in params:
                            creds["password"] = params[pfield][0][:100]
                            break
                    if creds:
                        details["credentials"] = creds
                        details["action"] = "login_attempt"
                        # Dodaj form type
                        if "pma_username" in params:
                            details["form_type"] = "phpmyadmin"
                        elif "log" in params:
                            details["form_type"] = "wordpress"
                        else:
                            details["form_type"] = "generic"
                except Exception:
                    pass

                if body:
                    details["body_preview"] = body[:2000]

            if self.manager:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details=details,
                )

            # Serve response
            if method == "POST":
                response = self._make_response("401 Unauthorized", PAGE_401)
            elif path_clean in TRAP_PAGES:
                page_key = TRAP_PAGES[path_clean]
                page_content = PAGE_MAP[page_key]
                ct = "text/plain" if page_key == "env" else "text/html"
                response = self._make_response("200 OK", page_content, ct)
            elif any(path_clean.startswith(p) for p in ("/backup/", "/uploads/")):
                response = self._make_response("403 Forbidden", PAGE_403)
            else:
                response = self._make_response("404 Not Found", PAGE_404)

            writer.write(response)
            await writer.drain()

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

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
