"""
MySQL Honeypot - Symuluje serwer MySQL 5.7.
Wysyla prawidlowy Greeting packet, zbiera credentials z Login Request.
"""

import asyncio
import struct
import os


class MySQLHoneypot:
    def __init__(self, port: int = 3307, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "mysql"

    def _build_greeting(self) -> bytes:
        """Buduje MySQL Server Greeting packet."""
        # Protocol version 10
        protocol_version = b"\x0a"
        # Server version string
        server_version = b"5.7.42-0ubuntu0.22.04.1-log\x00"
        # Connection ID
        conn_id = struct.pack("<I", 42)
        # Auth plugin data part 1 (8 bytes)
        auth1 = os.urandom(8)
        # Filler
        filler = b"\x00"
        # Capability flags (lower 2 bytes) - support ssl, secure_connection, plugin_auth
        cap_low = struct.pack("<H", 0xFFFF)
        # Character set (utf8)
        charset = b"\x21"
        # Status flags
        status = struct.pack("<H", 0x0002)  # SERVER_STATUS_AUTOCOMMIT
        # Capability flags (upper 2 bytes)
        cap_high = struct.pack("<H", 0x807F)
        # Length of all auth plugin data (21)
        auth_len = b"\x15"
        # Reserved (10 zero bytes)
        reserved = b"\x00" * 10
        # Auth plugin data part 2 (at least 13 bytes)
        auth2 = os.urandom(12) + b"\x00"
        # Auth plugin name
        auth_plugin = b"mysql_native_password\x00"

        payload = (
            protocol_version + server_version + conn_id + auth1 +
            filler + cap_low + charset + status + cap_high + auth_len +
            reserved + auth2 + auth_plugin
        )

        # MySQL packet header: length (3 bytes LE) + sequence (1 byte)
        length = struct.pack("<I", len(payload))[:3]
        sequence = b"\x00"

        return length + sequence + payload

    def _build_access_denied(self, username: str) -> bytes:
        """Buduje ERR_ACCESS_DENIED response."""
        # Error code 1045
        error = b"\xff"
        error_code = struct.pack("<H", 1045)
        # SQL state marker + state
        sql_state = b"#28000"
        # Error message
        msg = f"Access denied for user '{username}'@'connecting_host' (using password: YES)".encode()

        payload = error + error_code + sql_state + msg

        length = struct.pack("<I", len(payload))[:3]
        sequence = b"\x02"

        return length + sequence + payload

    def _parse_login(self, data: bytes) -> dict:
        """Parsuje Login Request packet i wyciaga username."""
        result = {"username": "", "database": "", "client_plugin": ""}
        try:
            if len(data) < 36:
                return result
            # Skip 4-byte header
            payload = data[4:]
            # Client capabilities (4 bytes)
            # Max packet size (4 bytes)
            # Charset (1 byte)
            # Reserved (23 zero bytes)
            offset = 4 + 4 + 1 + 23  # = 32

            # Username (null-terminated string)
            if offset < len(payload):
                end = payload.index(b"\x00", offset)
                result["username"] = payload[offset:end].decode("utf-8", errors="replace")
                offset = end + 1

            # Auth response length + data
            if offset < len(payload):
                auth_len = payload[offset]
                offset += 1 + auth_len

            # Database (null-terminated, if CLIENT_CONNECT_WITH_DB)
            if offset < len(payload):
                try:
                    end = payload.index(b"\x00", offset)
                    result["database"] = payload[offset:end].decode("utf-8", errors="replace")
                    offset = end + 1
                except ValueError:
                    pass

            # Client auth plugin
            if offset < len(payload):
                try:
                    end = payload.index(b"\x00", offset)
                    result["client_plugin"] = payload[offset:end].decode("utf-8", errors="replace")
                except ValueError:
                    pass

        except Exception:
            pass
        return result

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        try:
            # Wyslij MySQL Greeting
            greeting = self._build_greeting()
            writer.write(greeting)
            await writer.drain()

            # Odbierz Login Request
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=30)
            except asyncio.TimeoutError:
                return

            if not data:
                return

            # Parsuj login
            login_info = self._parse_login(data)

            if self.manager:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details={
                        "action": "login_attempt",
                        "username": login_info["username"][:100],
                        "database": login_info["database"][:100],
                        "client_plugin": login_info["client_plugin"][:100],
                        "data_length": len(data),
                    },
                )

            # Wyslij Access Denied
            err = self._build_access_denied(login_info["username"])
            writer.write(err)
            await writer.drain()

            # Czekaj czy klient proba ponownie
            try:
                retry = await asyncio.wait_for(reader.read(4096), timeout=5)
                if retry and self.manager:
                    retry_info = self._parse_login(retry)
                    self.manager.log_event(
                        honeypot_type=self.name,
                        source_ip=source_ip,
                        source_port=source_port,
                        details={
                            "action": "login_retry",
                            "username": retry_info["username"][:100],
                        },
                    )
            except asyncio.TimeoutError:
                pass

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
