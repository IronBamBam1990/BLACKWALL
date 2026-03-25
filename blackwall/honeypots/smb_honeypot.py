"""
SMB Honeypot - Symuluje udzial sieciowy SMB.
Loguje proby dostepu do plikow, credentials NTLM, nazwy maszyn.
"""

import asyncio
import struct


class SMBHoneypot:
    def __init__(self, port: int = 4450, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "smb"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        try:
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=30)
            except asyncio.TimeoutError:
                pass

            if not data:
                return

            details = {
                "action": "smb_connection_attempt",
                "data_length": len(data),
                "raw_hex_preview": data[:128].hex(),
            }

            # Parsuj SMB header
            if len(data) >= 4:
                # NetBIOS Session Service header
                nb_type = data[0]
                nb_length = struct.unpack(">I", b"\x00" + data[1:4])[0] if len(data) >= 4 else 0
                details["netbios_type"] = nb_type
                details["netbios_length"] = nb_length

            # Szukaj SMB magic bytes
            smb1_magic = b"\xffSMB"
            smb2_magic = b"\xfeSMB"
            if smb1_magic in data:
                details["smb_version"] = "SMB1"
                idx = data.index(smb1_magic)
                if len(data) > idx + 4:
                    details["smb_command"] = data[idx + 4]
            elif smb2_magic in data:
                details["smb_version"] = "SMB2/3"
                idx = data.index(smb2_magic)
                if len(data) > idx + 12:
                    details["smb2_command"] = struct.unpack("<H", data[idx + 12:idx + 14])[0]

            # Szukaj stringow (nazwy uzytkownikow, domen, maszyn)
            strings = self._extract_strings(data)
            if strings:
                details["extracted_strings"] = strings[:20]

            if self.manager:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details=details,
                )

            # Wyslij SMB Negotiate Response (odmowa)
            # Prosty SMB2 Negotiate Response z STATUS_ACCESS_DENIED
            smb2_error = self._build_smb2_error()
            writer.write(smb2_error)
            await writer.drain()

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _extract_strings(self, data: bytes) -> list:
        """Wyciaga printable stringi z surowych danych."""
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append("".join(current))
                current = []
        if len(current) >= 4:
            strings.append("".join(current))
        return strings

    def _build_smb2_error(self) -> bytes:
        """Buduje minimalny SMB2 error response."""
        # NetBIOS Session Service header (4 bytes): type=0x00, length=64
        nb_header = b"\x00" + struct.pack(">I", 64)[1:]  # 3-byte length
        # SMB2 header (64 bytes)
        smb2 = bytearray(64)
        smb2[0:4] = b"\xfeSMB"           # SMB2 magic
        struct.pack_into("<H", smb2, 4, 64)  # Header length
        struct.pack_into("<I", smb2, 8, 0xC0000022)  # STATUS_ACCESS_DENIED
        return nb_header + bytes(smb2)

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
