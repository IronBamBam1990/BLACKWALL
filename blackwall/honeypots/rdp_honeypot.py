"""
RDP Honeypot - Symuluje serwer Remote Desktop Protocol.
Loguje proby polaczenia RDP - source IP, handshake data.
"""

import asyncio
import struct


class RDPHoneypot:
    def __init__(self, port: int = 3390, manager=None):
        self.port = port
        self.manager = manager
        self.server = None
        self.name = "rdp"

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        try:
            # Czekaj na RDP Connection Request (X.224)
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=30)
            except asyncio.TimeoutError:
                pass

            if not data:
                return

            details = {
                "action": "rdp_connection_attempt",
                "data_length": len(data),
                "raw_hex_preview": data[:64].hex(),
            }

            # Parsuj X.224 Connection Request
            if len(data) >= 11:
                tpkt_version = data[0]
                tpkt_length = struct.unpack(">H", data[2:4])[0] if len(data) >= 4 else 0
                details["tpkt_version"] = tpkt_version
                details["tpkt_length"] = tpkt_length

                # Szukaj cookie/username w danych (RDP negotiation)
                try:
                    decoded = data.decode("utf-8", errors="replace")
                    if "Cookie:" in decoded:
                        cookie_start = decoded.index("Cookie:")
                        cookie_end = decoded.index("\r\n", cookie_start) if "\r\n" in decoded[cookie_start:] else len(decoded)
                        details["rdp_cookie"] = decoded[cookie_start:cookie_end][:200]
                except (ValueError, UnicodeDecodeError):
                    pass

            # Loguj probe
            if self.manager:
                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details=details,
                )

            # Wyslij RDP Negotiation Failure (symuluj ze serwer odrzuca)
            # X.224 Connection Confirm z failure
            response = bytes([
                0x03, 0x00, 0x00, 0x13,  # TPKT header
                0x0e,                      # X.224 length
                0xd0,                      # Connection Confirm
                0x00, 0x00,                # DST-REF
                0x00, 0x00,                # SRC-REF
                0x00,                      # Class 0
                0x02,                      # RDP Negotiation Failure
                0x00,                      # flags
                0x08, 0x00, 0x00, 0x00,    # length
                0x05, 0x00, 0x00, 0x00,    # HYBRID_REQUIRED_BY_SERVER
            ])
            writer.write(response)
            await writer.drain()

            # Czytaj jeszcze dane jesli haker kontynuuje
            try:
                extra = await asyncio.wait_for(reader.read(4096), timeout=5)
                if extra and self.manager:
                    self.manager.log_event(
                        honeypot_type=self.name,
                        source_ip=source_ip,
                        source_port=source_port,
                        details={
                            "action": "rdp_continued_attempt",
                            "extra_data_hex": extra[:128].hex(),
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
