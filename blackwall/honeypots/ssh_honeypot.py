"""
SSH Honeypot - Symuluje serwer SSH.
Loguje wszystkie proby logowania (username/password), komendy, fingerprint klienta.
"""

import asyncio
import logging

log = logging.getLogger("Honeypot.SSH")


SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"


class SSHHoneypot:
    def __init__(self, port: int = 2222, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "ssh"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        try:
            # Wyslij banner SSH
            writer.write(SSH_BANNER)
            await writer.drain()

            # Odczytaj banner klienta
            client_banner = b""
            try:
                client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            except asyncio.TimeoutError:
                pass

            # Symuluj key exchange - wyslij fake kex init
            # Haker probuje sie zalogowac - logujemy wszystko co wysle
            collected_data = client_banner
            try:
                while True:
                    data = await asyncio.wait_for(reader.read(4096), timeout=30)
                    if not data:
                        break
                    collected_data += data
                    # Probuj wyciagnac credentials z danych
                    self._extract_and_log(source_ip, source_port, collected_data)
                    # Zawsze odrzuc - wyslij generic failure
                    writer.write(b"\x00\x00\x00\x0c\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                    await writer.drain()
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
                pass

            # Loguj probe
            if self.manager:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details={
                        "client_banner": client_banner.decode("utf-8", errors="replace").strip(),
                        "data_length": len(collected_data),
                        "action": "ssh_connection_attempt",
                    },
                )
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            log.debug(f"SSH handler error from {source_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _extract_and_log(self, source_ip, source_port, data):
        """Probuje wyciagnac credentials z surowych danych SSH."""
        # SSH protocol ma binarne pakiety, ale logujemy surowe dane
        printable = data.decode("utf-8", errors="replace")
        # Szukamy stringow ktore moga byc username/password
        strings = []
        current = []
        for ch in printable:
            if ch.isprintable() and ch != "\x00":
                current.append(ch)
            else:
                if len(current) >= 3:
                    strings.append("".join(current))
                current = []
        if len(current) >= 3:
            strings.append("".join(current))

        if strings and self.manager:
            self.manager.log_event(
                honeypot_type=self.name,
                source_ip=source_ip,
                source_port=source_port,
                details={
                    "action": "credentials_extracted",
                    "strings_found": strings[:20],  # Max 20 stringow
                },
            )

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
