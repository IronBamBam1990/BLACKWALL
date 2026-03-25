"""
Catch-All Port Listener - Nasluchuje na WSZYSTKICH popularnych portach.
Kazde polaczenie na dowolny port jest logowane.
Porty ktore juz maja dedykowany honeypot sa pominiete.
"""

import asyncio


# Najczesciej atakowane porty (oprócz tych z dedykowanymi honeypotami)
CATCH_ALL_PORTS = [
    # Remote access
    23,     # Telnet (real)
    3389,   # RDP (real)
    5900, 5901, 5902,  # VNC

    # Web
    80, 443, 8000, 8443, 8888, 9090, 9443,

    # Databases
    1433, 1434,   # MSSQL
    3306,         # MySQL (real)
    5432,         # PostgreSQL
    6379,         # Redis
    27017, 27018, # MongoDB
    9200, 9300,   # Elasticsearch
    5984,         # CouchDB
    11211,        # Memcached

    # Message queues
    5672, 15672,  # RabbitMQ
    9092,         # Kafka

    # File sharing
    21,    # FTP (real)
    69,    # TFTP
    873,   # rsync

    # Mail
    25, 110, 143, 465, 587, 993, 995,  # SMTP/POP3/IMAP

    # Directory
    389, 636,   # LDAP
    88,         # Kerberos

    # Monitoring
    161, 162,   # SNMP
    514,        # Syslog
    10050, 10051,  # Zabbix

    # Docker/Container
    2375, 2376,  # Docker API
    6443, 10250, # Kubernetes

    # CI/CD
    8081, 8082,  # Nexus/Artifactory
    9000,        # SonarQube/Portainer

    # C2 / Backdoor
    4444, 5555, 6666, 6667, 1337, 31337, 12345, 54321,
    4443, 9001, 9030,

    # IoT
    1883, 8883,  # MQTT
    502,         # Modbus
    47808,       # BACnet

    # Gaming / misc
    25565,  # Minecraft
    27015,  # Source Engine
]


class CatchAllHoneypot:
    def __init__(self, ports: list = None, manager=None, exclude_ports: set = None):
        self.ports = ports or CATCH_ALL_PORTS
        self.manager = manager
        self.exclude_ports = exclude_ports or set()
        self.servers = []
        self.name = "catchall"
        self.port = 0  # multiple ports
        self._active_ports = []

    async def handle_client(self, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        source_ip = addr[0] if addr else "unknown"
        source_port = addr[1] if addr else 0

        try:
            # Czytaj cokolwiek klient wysle
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=15)
            except asyncio.TimeoutError:
                pass

            # Loguj
            if self.manager:
                details = {
                    "action": "connection_attempt",
                    "target_port": port,
                    "data_length": len(data),
                }

                # Probuj wyciagnac printable stringi
                if data:
                    printable = data.decode("utf-8", errors="replace")
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
                    if strings:
                        details["strings"] = strings[:20]
                    details["hex_preview"] = data[:64].hex()

                    # Wykryj protokol
                    if data[:3] == b"GET" or data[:4] == b"POST" or data[:4] == b"HEAD":
                        details["protocol"] = "HTTP"
                    elif data[:4] == b"\x16\x03\x01\x00" or data[:4] == b"\x16\x03\x03\x00":
                        details["protocol"] = "TLS"
                    elif data[:4] == b"SSH-":
                        details["protocol"] = "SSH"
                    elif data[:4] == b"EHLO" or data[:4] == b"HELO":
                        details["protocol"] = "SMTP"
                    elif data[:4] == b"USER":
                        details["protocol"] = "FTP"
                    elif b"\xff\xfb" in data[:10] or b"\xff\xfd" in data[:10]:
                        details["protocol"] = "Telnet"
                    elif data[:4] == b"\x00\x00\x00\x00" or b"\xfeSMB" in data[:8]:
                        details["protocol"] = "SMB"
                    else:
                        details["protocol"] = "unknown"

                self.manager.log_event(
                    honeypot_type=self.name,
                    source_ip=source_ip,
                    source_port=source_port,
                    details=details,
                )

            # Zamknij polaczenie po krotkim opoznieniu
            await asyncio.sleep(0.5)

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Uruchom listenery na wszystkich portach."""
        tasks = []
        for port in self.ports:
            if port in self.exclude_ports:
                continue
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=port: self.handle_client(p, r, w),
                    "0.0.0.0",
                    port,
                )
                self.servers.append(server)
                self._active_ports.append(port)
            except OSError:
                # Port juz zajety (przez system lub inny honeypot) - pomijamy
                pass

        failed = len(self.ports) - len(self.exclude_ports) - len(self._active_ports)
        if self.manager:
            self.manager.logger.info(
                f"Catch-all: {len(self._active_ports)} ports bound, "
                f"{failed} failed (need admin for <1024)"
            )

        if self.servers:
            await asyncio.gather(
                *(srv.serve_forever() for srv in self.servers),
                return_exceptions=True,
            )

    async def stop(self):
        for srv in self.servers:
            try:
                srv.close()
                await srv.wait_closed()
            except Exception:
                pass
        self.servers.clear()

    def get_active_ports(self) -> list:
        return sorted(self._active_ports)
