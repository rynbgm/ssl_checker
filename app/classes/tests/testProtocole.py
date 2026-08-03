from __future__ import annotations
import os
import socket
import ssl
import struct
import time
from typing import List, Dict

from classes.tests.testBase import TestBase

# SSL2 ClientHello — header calculé dynamiquement
_SSL2_BODY = bytes([
    0x01,               # MSG-CLIENT-HELLO
    0x00, 0x02,         # Version SSL 2.0
    0x00, 0x09,         # Cipher specs length (3 x 3 bytes)
    0x00, 0x00,         # Session ID length
    0x00, 0x10,         # Challenge length (16 bytes)
    0x07, 0x00, 0xC0,   # SSL_CK_DES_192_EDE3_CBC_WITH_MD5
    0x05, 0x00, 0x80,   # SSL_CK_RC4_128_WITH_MD5
    0x03, 0x00, 0x80,   # SSL_CK_RC2_128_CBC_WITH_MD5
] + [0x01] * 16)        # Challenge

_SSL2_LEN = len(_SSL2_BODY)
SSL2_CLIENT_HELLO = bytes([0x80 | (_SSL2_LEN >> 8), _SSL2_LEN & 0xFF]) + _SSL2_BODY


def _build_ssl3_client_hello() -> bytes:
    """
    Construit un ClientHello SSL3 avec un champ Random valide :
    4 bytes timestamp + 28 bytes aléatoires.
    """
    timestamp = struct.pack("!I", int(time.time()))
    random_bytes = os.urandom(28)
    random_field = timestamp + random_bytes  # 32 bytes

    hello_body = bytes([
        0x03, 0x00,         # Version SSL 3.0
    ]) + random_field + bytes([
        0x00,               # Session ID length
        0x00, 0x02,         # Cipher suites length
        0x00, 0x0A,         # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x01,               # Compression methods length
        0x00,               # No compression
    ])

    handshake = bytes([0x01]) + struct.pack("!I", len(hello_body))[1:] + hello_body

    record = bytes([
        0x16,               # Content type: Handshake
        0x03, 0x00,         # Version SSL 3.0
    ]) + struct.pack("!H", len(handshake)) + handshake

    return record


class TestProtocole(TestBase):
    """
    Teste SSL2, SSL3 et TLS 1.0 → TLS 1.3
    """

    PROTOCOLES = [
        {"nom": "SSL 2.0", "type": "ssl2"},
        {"nom": "SSL 3.0", "type": "ssl3"},
        {"nom": "TLS 1.0", "version": ssl.TLSVersion.TLSv1},
        {"nom": "TLS 1.1", "version": ssl.TLSVersion.TLSv1_1},
        {"nom": "TLS 1.2", "version": ssl.TLSVersion.TLSv1_2},
        {"nom": "TLS 1.3", "version": ssl.TLSVersion.TLSv1_3},
    ]

    def lancer(self) -> None:
        resultat: List[Dict[str, bool]] = []

        for proto in self.PROTOCOLES:
            nom = proto["nom"]

            # SSL2
            if proto.get("type") == "ssl2":
                supporte = self._test_ssl2()
                resultat.append({"nom": nom, "supporte": supporte})
                continue

            # SSL3
            if proto.get("type") == "ssl3":
                supporte = self._test_ssl3()
                resultat.append({"nom": nom, "supporte": supporte})
                continue

            # TLS moderne
            version = proto.get("version")
            if version is None:
                resultat.append({"nom": nom, "supporte": False})
                continue

            supporte = self._test_tls_version(version)
            resultat.append({"nom": nom, "supporte": supporte})

        self.resultat = resultat

    def _test_ssl2(self) -> bool:
        """
        Teste SSL 2.0 avec un ClientHello minimal (raw socket).
        Vérifie que la réponse est bien un ServerHello SSL2 (0x80 ou 0x00)
        et non une alerte TLS (0x15).
        """
        try:
            with socket.create_connection((self.fqdn, int(self.port)), timeout=5) as sock:
                sock.sendall(SSL2_CLIENT_HELLO)
                data = sock.recv(1024)

            if len(data) < 3:
                return False

            # Alerte TLS — le serveur a rejeté la connexion
            if data[0] == 0x15:
                return False

            # ServerHello SSL2 — bit de poids fort = 1 (format court ou long)
            if data[0] & 0x80:
                return True

            return False

        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _test_ssl3(self) -> bool:
        """
        Teste SSL 3.0 avec un ClientHello valide (raw socket).
        Vérifie que la réponse est bien un ServerHello SSL3 (0x16 + 0x03 0x00)
        et non une alerte TLS (0x15).
        """
        ssl3_hello = _build_ssl3_client_hello()

        try:
            with socket.create_connection((self.fqdn, int(self.port)), timeout=5) as sock:
                sock.sendall(ssl3_hello)
                data = sock.recv(1024)

            if len(data) < 3:
                return False

            # Alerte TLS — le serveur a rejeté la connexion
            if data[0] == 0x15:
                return False

            # ServerHello SSL3 : Handshake (0x16) + version SSL3 (0x03 0x00)
            if data[0] == 0x16 and data[1] == 0x03 and data[2] == 0x00:
                return True

            return False

        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _test_tls_version(self, version: ssl.TLSVersion) -> bool:
        """
        Teste TLS 1.0 → 1.3 via ssl.SSLContext
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            # Permet TLS 1.0 / 1.1 sur OpenSSL modernes
            context.set_ciphers("DEFAULT:@SECLEVEL=1")

            with socket.create_connection((self.fqdn, int(self.port)), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.fqdn):
                    return True

        except (ssl.SSLError, ConnectionRefusedError, TimeoutError, OSError):
            return False
