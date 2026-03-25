"""
SMTP Honeypot - Symuluje serwer pocztowy.
Zbiera credentials z AUTH, loguje spam-boty probuajce wyslac maile.
"""

import asyncio
import base64


class SMTPHoneypot:
    def __init__(self, port: int = 2525, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "smtp"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        mail_from = ""
        rcpt_to = []
        mail_data = ""
        auth_user = ""
        auth_pass = ""
        commands = []
        auth_state = None  # None, "user", "pass"

        try:
            # SMTP Banner
            writer.write(b"220 mail.server01.local ESMTP Postfix (Ubuntu)\r\n")
            await writer.drain()

            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=60)
                except asyncio.TimeoutError:
                    break

                if not line:
                    break

                cmd = line.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue

                commands.append(cmd[:300])
                cmd_upper = cmd.upper()

                # AUTH LOGIN flow
                if auth_state == "user":
                    try:
                        auth_user = base64.b64decode(cmd).decode("utf-8", errors="replace")
                    except Exception:
                        auth_user = cmd
                    writer.write(b"334 UGFzc3dvcmQ6\r\n")  # Base64("Password:")
                    auth_state = "pass"
                    await writer.drain()
                    continue

                if auth_state == "pass":
                    try:
                        auth_pass = base64.b64decode(cmd).decode("utf-8", errors="replace")
                    except Exception:
                        auth_pass = cmd
                    auth_state = None

                    # Log credentials
                    if self.manager:
                        self.manager.log_event(
                            honeypot_type=self.name,
                            source_ip=source_ip,
                            source_port=source_port,
                            details={
                                "action": "login_attempt",
                                "username": auth_user[:100],
                                "password": auth_pass[:100],
                                "method": "AUTH LOGIN",
                            },
                        )
                    writer.write(b"535 5.7.8 Authentication failed\r\n")
                    await writer.drain()
                    continue

                # EHLO/HELO
                if cmd_upper.startswith("EHLO") or cmd_upper.startswith("HELO"):
                    hostname = cmd[5:].strip() if len(cmd) > 5 else ""
                    writer.write(
                        b"250-mail.server01.local Hello " + hostname.encode()[:100] + b"\r\n"
                        b"250-SIZE 52428800\r\n"
                        b"250-8BITMIME\r\n"
                        b"250-STARTTLS\r\n"
                        b"250-AUTH LOGIN PLAIN CRAM-MD5\r\n"
                        b"250-ENHANCEDSTATUSCODES\r\n"
                        b"250-PIPELINING\r\n"
                        b"250 CHUNKING\r\n"
                    )

                # AUTH
                elif cmd_upper.startswith("AUTH LOGIN"):
                    # Moze byc AUTH LOGIN <base64_user> w jednej linii
                    parts = cmd.split()
                    if len(parts) >= 3:
                        try:
                            auth_user = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                        except Exception:
                            auth_user = parts[2]
                        writer.write(b"334 UGFzc3dvcmQ6\r\n")
                        auth_state = "pass"
                    else:
                        writer.write(b"334 VXNlcm5hbWU6\r\n")  # Base64("Username:")
                        auth_state = "user"

                elif cmd_upper.startswith("AUTH PLAIN"):
                    # AUTH PLAIN <base64(null+user+null+pass)>
                    parts = cmd.split()
                    if len(parts) >= 3:
                        try:
                            decoded = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
                            creds = decoded.split("\x00")
                            if len(creds) >= 3:
                                auth_user = creds[1]
                                auth_pass = creds[2]
                        except Exception:
                            pass

                        if self.manager:
                            self.manager.log_event(
                                honeypot_type=self.name,
                                source_ip=source_ip,
                                source_port=source_port,
                                details={
                                    "action": "login_attempt",
                                    "username": auth_user[:100],
                                    "password": auth_pass[:100],
                                    "method": "AUTH PLAIN",
                                },
                            )
                    writer.write(b"535 5.7.8 Authentication failed\r\n")

                # STARTTLS
                elif cmd_upper.startswith("STARTTLS"):
                    writer.write(b"454 4.7.0 TLS not available\r\n")

                # MAIL FROM
                elif cmd_upper.startswith("MAIL FROM"):
                    mail_from = cmd[10:].strip().strip("<>")[:200]
                    writer.write(b"250 2.1.0 Ok\r\n")

                # RCPT TO
                elif cmd_upper.startswith("RCPT TO"):
                    rcpt = cmd[8:].strip().strip("<>")[:200]
                    rcpt_to.append(rcpt)
                    writer.write(b"250 2.1.5 Ok\r\n")

                # DATA
                elif cmd_upper == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()

                    # Zbieraj dane az do "."
                    data_lines = []
                    while True:
                        try:
                            data_line = await asyncio.wait_for(reader.readline(), timeout=30)
                        except asyncio.TimeoutError:
                            break
                        decoded = data_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        if decoded == ".":
                            break
                        data_lines.append(decoded)
                        if len(data_lines) > 500:  # Limit
                            break

                    mail_data = "\n".join(data_lines)

                    # Log spam attempt
                    if self.manager:
                        self.manager.log_event(
                            honeypot_type=self.name,
                            source_ip=source_ip,
                            source_port=source_port,
                            details={
                                "action": "mail_attempt",
                                "from": mail_from,
                                "to": rcpt_to[:20],
                                "data_preview": mail_data[:2000],
                                "data_lines": len(data_lines),
                            },
                        )
                    writer.write(b"554 5.7.1 Transaction failed: spam detected\r\n")

                # QUIT
                elif cmd_upper == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break

                # NOOP
                elif cmd_upper == "NOOP":
                    writer.write(b"250 2.0.0 Ok\r\n")

                # RSET
                elif cmd_upper == "RSET":
                    mail_from = ""
                    rcpt_to = []
                    mail_data = ""
                    writer.write(b"250 2.0.0 Ok\r\n")

                # VRFY (user enumeration attempt)
                elif cmd_upper.startswith("VRFY"):
                    user = cmd[5:].strip() if len(cmd) > 5 else ""
                    if self.manager:
                        self.manager.log_event(
                            honeypot_type=self.name,
                            source_ip=source_ip,
                            source_port=source_port,
                            details={"action": "vrfy_attempt", "user": user[:100]},
                        )
                    writer.write(b"252 2.5.2 Cannot VRFY user\r\n")

                else:
                    writer.write(b"502 5.5.2 Error: command not recognized\r\n")

                await writer.drain()

            # Sesja summary
            if self.manager and commands:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details={
                        "action": "session_summary",
                        "commands": commands[:50],
                        "auth_user": auth_user[:100],
                        "mail_from": mail_from,
                        "rcpt_to": rcpt_to[:20],
                        "had_mail_data": bool(mail_data),
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
