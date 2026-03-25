"""
DNS Honeypot - Symuluje serwer DNS (UDP).
Loguje zapytania DNS, wykrywa DNS tunneling, exfiltracje danych.
"""

import asyncio
import struct
from datetime import datetime, timezone


# DNS record types
DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, manager=None):
        self.manager = manager
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        source_ip, source_port = addr

        try:
            query = self._parse_dns_query(data)
        except Exception:
            query = {"domain": "parse_error", "qtype": "?", "raw_hex": data[:64].hex()}

        # Log
        if self.manager:
            details = {
                "action": "dns_query",
                "domain": query.get("domain", "")[:253],
                "query_type": query.get("qtype", "?"),
                "query_id": query.get("id", 0),
            }

            # Wykryj potencjalny DNS tunneling (bardzo dlugie subdomeny)
            domain = query.get("domain", "")
            labels = domain.split(".")
            max_label = max((len(l) for l in labels), default=0)
            if max_label > 40 or len(domain) > 100:
                details["suspicious"] = True
                details["reason"] = "Possible DNS tunneling (long labels)"

            self.manager.log_event(
                honeypot_type="dns",
                source_ip=source_ip,
                source_port=source_port,
                details=details,
            )

        # Odpowiedz: REFUSED lub fake A record
        response = self._build_refused_response(data)
        if self.transport:
            self.transport.sendto(response, addr)

    def _parse_dns_query(self, data: bytes) -> dict:
        """Parsuje DNS query packet."""
        if len(data) < 12:
            return {"domain": "", "qtype": "?"}

        # Header
        query_id = struct.unpack(">H", data[0:2])[0]
        flags = struct.unpack(">H", data[2:4])[0]
        qdcount = struct.unpack(">H", data[4:6])[0]

        # Question section
        offset = 12
        domain_parts = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            if offset + length > len(data):
                break
            domain_parts.append(data[offset:offset + length].decode("utf-8", errors="replace"))
            offset += length

        domain = ".".join(domain_parts)

        # Query type
        qtype_num = 0
        if offset + 2 <= len(data):
            qtype_num = struct.unpack(">H", data[offset:offset + 2])[0]
        qtype = DNS_TYPES.get(qtype_num, str(qtype_num))

        return {
            "id": query_id,
            "domain": domain,
            "qtype": qtype,
            "qtype_num": qtype_num,
            "flags": flags,
        }

    def _build_refused_response(self, query_data: bytes) -> bytes:
        """Buduje DNS REFUSED response."""
        if len(query_data) < 12:
            return b""

        # Kopiuj query ID
        response = bytearray(query_data[:12])
        # Set response flag + REFUSED rcode
        response[2] = 0x81  # QR=1, RD=1
        response[3] = 0x05  # REFUSED
        # Answer count = 0
        response[6:8] = b"\x00\x00"
        response[8:10] = b"\x00\x00"
        response[10:12] = b"\x00\x00"
        # Append question section as-is
        response.extend(query_data[12:])

        return bytes(response)

    def error_received(self, exc):
        pass


class DNSHoneypot:
    def __init__(self, port: int = 5354, manager=None):
        self.port = port
        self.manager = manager
        self.transport = None
        self.protocol = None
        self.name = "dns"

    async def start(self):
        loop = asyncio.get_event_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(manager=self.manager),
            local_addr=("0.0.0.0", self.port),
        )
        # Keep alive
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        if self.transport:
            self.transport.close()
