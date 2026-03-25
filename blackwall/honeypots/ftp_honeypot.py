"""
FTP Honeypot - Symuluje serwer FTP.
Loguje proby logowania, komendy, proby transferu plikow.
"""

import asyncio


class FTPHoneypot:
    def __init__(self, port: int = 2121, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "ftp"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        username = ""
        commands = []

        try:
            # FTP banner
            writer.write(b"220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.1.1]\r\n")
            await writer.drain()

            while True:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=60)
                except asyncio.TimeoutError:
                    break

                if not data:
                    break

                cmd = data.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue

                commands.append(cmd[:200])
                cmd_upper = cmd.upper()

                if cmd_upper.startswith("USER"):
                    username = cmd[5:].strip() if len(cmd) > 5 else ""
                    writer.write(f"331 Password required for {username}\r\n".encode())
                elif cmd_upper.startswith("PASS"):
                    password = cmd[5:].strip() if len(cmd) > 5 else ""
                    # Loguj credentials
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
                    # Zawsze odmow (po chwili - symuluj sprawdzanie)
                    await asyncio.sleep(0.5)
                    writer.write(b"530 Login incorrect.\r\n")
                elif cmd_upper.startswith("QUIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break
                elif cmd_upper.startswith("SYST"):
                    writer.write(b"215 UNIX Type: L8\r\n")
                elif cmd_upper.startswith("FEAT"):
                    writer.write(b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
                elif cmd_upper.startswith("LIST") or cmd_upper.startswith("NLST"):
                    writer.write(b"550 Permission denied.\r\n")
                elif cmd_upper.startswith("RETR") or cmd_upper.startswith("STOR"):
                    writer.write(b"550 Permission denied.\r\n")
                    if self.manager:
                        self.manager.log_event(
                            honeypot_type=self.name,
                            source_ip=source_ip,
                            source_port=source_port,
                            details={
                                "action": "file_transfer_attempt",
                                "command": cmd[:200],
                            },
                        )
                else:
                    writer.write(b"500 Unknown command.\r\n")

                await writer.drain()

            # Loguj sesje
            if self.manager and commands:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details={
                        "action": "session_summary",
                        "username": username[:100],
                        "commands": commands[:50],
                        "command_count": len(commands),
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
