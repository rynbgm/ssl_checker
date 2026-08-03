import os
import socket
import pandas as pd
from scapy.all import RandString
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSAlert, SSLv2, SSLv2ClientHello, SSLv2ServerHello
from scapy.layers.tls.extensions import (
    TLS_Ext_SupportedVersion_CH, TLS_Ext_ServerName, ServerName,
    TLS_Ext_SupportedGroups, TLS_Ext_SignatureAlgorithms,
    TLS_Ext_SupportedPointFormat, TLS_Ext_SessionTicket,
    TLS_Ext_EncryptThenMAC, TLS_Ext_ExtendedMasterSecret,
    TLS_Ext_PSKKeyExchangeModes, TLS_Ext_Unknown
)
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_KeyShare_CH, KeyShareEntry
from classes.tests.testBase import TestBase


class TestCipher(TestBase):
    def __init__(self, fqdn: str, port: str):
        super().__init__(fqdn, port)
        self.fqdn = fqdn
        self.port = port
        self.protocoles = {
            'SSL 2.0': 0x0200, 'SSL 3.0': 0x0300,
            'TLS 1.0': 0x0301, 'TLS 1.1': 0x0302,
            'TLS 1.2': 0x0303, 'TLS 1.3': 0x0304
        }
        self.sslv2_ciphers = {
            0x010080: "SSL2_RC4_128_WITH_MD5",
            0x0700c0: "SSL2_DES_192_EDE3_CBC_WITH_MD5"
        }
        x25519_key_bytes = b"\xbcG\x97\x83d\x1e\xf9^1\x0b;\xe1\xd5\xcb=\x3d9_\xfcA\x98V\x82\xc3\xc7\x13L\x9c\x9ee\x02Q"
        self.openssl_extensions = [
            TLS_Ext_ServerName(servernames=[ServerName(servername=self.fqdn.encode('utf-8'))]),
            TLS_Ext_SupportedPointFormat(ecpl=[0, 1, 2]),
            TLS_Ext_SupportedGroups(groups=[4588, 29, 23, 30, 24, 25, 256, 257]),
            TLS_Ext_SessionTicket(),
            TLS_Ext_EncryptThenMAC(),
            TLS_Ext_ExtendedMasterSecret(),
            TLS_Ext_SignatureAlgorithms(sig_algs=[
                2309, 2310, 2308, 1027, 1283, 1539, 2055, 2056, 2074, 2075,
                2076, 2057, 2058, 2059, 2052, 2053, 2054, 1025, 1281, 1537
            ]),
            TLS_Ext_SupportedVersion_CH(versions=[772]),
            TLS_Ext_PSKKeyExchangeModes(kxmodes=[1]),
            TLS_Ext_KeyShare_CH(client_shares=[
                KeyShareEntry(group=29, key_exchange=x25519_key_bytes),
            ]),
            TLS_Ext_Unknown(type=27, val=b"\x04\x00\x01\x00\x03")
        ]

    # --- SECTION : UTILITAIRES ---

    def _read_cipherList(self, istls3):
        """ Lit le fichier CSV de l'IANA pour récupérer la liste officielle des ciphers """
        base_dir = os.path.dirname(os.path.abspath(__file__))
        csv_path = os.path.join(base_dir, '../tls-parameters-4.csv')
        data = pd.read_csv(csv_path)
        data = data[~data['Description'].str.contains('Unassigned|Reserved', case=False, na=False)]
        mask = data['Description'].str.contains('TLS_AES|TLS_CHACH', case=False, na=False)
        data = data[mask] if istls3 else data[~mask]
        ciphers_hex, ciphers_des = [], []
        for _, row in data.iterrows():
            cipher_id = self._parse_cipher(row['Value'])
            if cipher_id is not None:
                ciphers_hex.append(cipher_id)
                ciphers_des.append(row['Description'])
        return ciphers_hex, ciphers_des

    def _parse_cipher(self, val_str):
        """ Convertit une valeur CSV "0x00,0x01" en entier 0x0001 """
        try:
            parts = str(val_str).replace('"', '').split(',')
            return int(parts[0], 16) * 256 + int(parts[1], 16) if len(parts) == 2 else None
        except Exception:
            return None

    def _tcp_connection(self, target, port):
        """ Établit une connexion TCP brute """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect((target, int(port)))
            return sock
        except Exception:
            return False

    # --- SECTION : FORGE DES PAQUETS ---

    def _forge_sslv2(self, sock, ciphers):
        """ Crée et envoie un paquet SSLv2 Client Hello """
        v2_pkg = SSLv2(msg=[SSLv2ClientHello(version=0x0200, ciphers=ciphers, challenge=RandString(16))])
        try:
            sock.send(bytes(v2_pkg))
            return True
        except Exception:
            return False

    def _build_tls13_extensions(self):
        """ Reconstruit les extensions TLS 1.3 avec un SNI frais """
        exts = [e for e in self.openssl_extensions if not isinstance(e, TLS_Ext_ServerName)]
        exts.insert(0, TLS_Ext_ServerName(servernames=[ServerName(servername=self.fqdn.encode('utf-8'))]))
        return exts

    def _forge_tls(self, sock, protocole_hex, ciphers):
        """ Crée et envoie un paquet TLS Client Hello avec extensions """
        version = 0x0303 if protocole_hex == 0x0304 else protocole_hex
        tls_ext = [
            TLS_Ext_ServerName(servernames=[ServerName(servername=self.fqdn.encode('utf-8'))]),
            TLS_Ext_SupportedGroups(groups=['x25519', 'secp256r1', 'secp384r1']),
            TLS_Ext_SupportedPointFormat(ecpl=[0]),
            TLS_Ext_SignatureAlgorithms(sig_algs=[
                "sha256+rsa", "sha256+ecdsa",
                "sha384+rsa", "sha384+ecdsa",
                "sha512+rsa", "sha1+rsa"
            ])
        ]
        exts = self._build_tls13_extensions() if protocole_hex >= 0x0304 else tls_ext
        tls_pkg = TLS(version=version, msg=[TLSClientHello(version=version, ciphers=ciphers, comp=[0], ext=exts)])
        try:
            sock.send(bytes(tls_pkg))
            return True
        except Exception:
            return False

    def _make_handshake(self, sock, protocole_hex, ciphers):
        """ Gère l'envoi et la réception du Handshake selon le protocole """
        success = self._forge_sslv2(sock, ciphers) if protocole_hex == 0x0200 else self._forge_tls(sock, protocole_hex, ciphers)
        if not success:
            return False
        try:
            response = sock.recv(4096)
            if not response:
                return False
            return SSLv2(response) if protocole_hex == 0x0200 else TLS(response)
        except Exception:
            return False

    # --- SECTION : EXTRACTION ROBUSTE (Sonar compliant) ---

    def _parse_server_hello_raw(self, msg):
        """ Parse un message brut pour extraire le cipher d'un ServerHello """
        try:
            raw_data = msg.load if hasattr(msg, 'load') else bytes(msg)
        except Exception:
            return None
        if len(raw_data) > 38 and raw_data[0] == 2:
            sess_id_len = raw_data[38]
            cipher_offset = 39 + sess_id_len
            if len(raw_data) >= cipher_offset + 2:
                return (raw_data[cipher_offset] << 8) + raw_data[cipher_offset + 1]
        return None

    def _extract_cipher_from_raw(self, pkt):
        """ Extrait le cipher depuis les messages bruts d'un paquet TLS """
        if not pkt.haslayer(TLS) or not hasattr(pkt[TLS], 'msg'):
            return None
        for msg in pkt[TLS].msg:
            cipher = self._parse_server_hello_raw(msg)
            if cipher is not None:
                return cipher
        return None

    def _extract_cipher_robust(self, pkt):
        """ Tente d'extraire le cipher d'un paquet même en cas de payload brut """
        if not pkt:
            return None
        if pkt.haslayer(TLSServerHello):
            return pkt[TLSServerHello].cipher
        return self._extract_cipher_from_raw(pkt)

    # --- SECTION : ÉNUMÉRATION ---

    def _enumerate_sslv2(self, target, port, proto_hex):
        """ Énumération spécifique pour le vieux SSLv2 """
        sock = self._tcp_connection(target, port)
        if not sock:
            return False, []
        ciphers = list(self.sslv2_ciphers.keys())
        pkt = self._make_handshake(sock, proto_hex, ciphers)
        accepted = []
        if pkt and pkt.haslayer(SSLv2ServerHello):
            for c in pkt[SSLv2ServerHello].ciphers:
                desc = self.sslv2_ciphers.get(c, f"UNKNOWN_SSLV2_{hex(c)}")
                accepted.append((c, desc))
        if sock:
            sock.close()
        return False, accepted

    def _get_single_cipher(self, target, port, proto_hex, chunk):
        """ Sous-fonction pour extraire un cipher et réduire la complexité """
        sock = self._tcp_connection(target, port)
        if not sock:
            return None
        pkt = self._make_handshake(sock, proto_hex, chunk)
        cipher = self._extract_cipher_robust(pkt)
        sock.close()
        return cipher

    def _process_tls_chunk(self, target, port, proto_hex, chunk, ciphers_hex, ciphers_des):
        """ Scanne un chunk de ciphers et retourne ceux acceptés par le serveur """
        accepted_in_chunk = []
        while chunk:
            cipher = self._get_single_cipher(target, port, proto_hex, chunk)
            if not cipher:
                break
            if cipher in ciphers_hex:
                desc = ciphers_des[ciphers_hex.index(cipher)]
                accepted_in_chunk.append((cipher, desc))
            if cipher in chunk:
                chunk.remove(cipher)
            else:
                break
        return accepted_in_chunk

    def _check_cipher_order_enforcement(self, target, port, proto_hex, accepted_hex):
        """ Vérifie si le serveur impose son propre ordre de préférence """
        if len(accepted_hex) < 2:
            return True
        c1, c2 = accepted_hex[0], accepted_hex[1]
        s1 = self._tcp_connection(target, port)
        r1 = self._make_handshake(s1, proto_hex, [c1, c2])
        if s1:
            s1.close()
        s2 = self._tcp_connection(target, port)
        r2 = self._make_handshake(s2, proto_hex, [c2, c1])
        if s2:
            s2.close()
        c1_extracted = self._extract_cipher_robust(r1)
        c2_extracted = self._extract_cipher_robust(r2)
        if c1_extracted is not None and c2_extracted is not None:
            return c1_extracted == c2_extracted
        return True

    def enumerate_ciphers(self, target, port, proto, ciphers_hex=None, ciphers_des=None):
        """ Fonction principale d'énumération """
        if proto not in self.protocoles:
            return False, []
        proto_hex = self.protocoles[proto]
        if proto_hex == 0x0200:
            return self._enumerate_sslv2(target, port, proto_hex)
        if not ciphers_hex:
            return False, []
        accepted = []
        for i in range(0, len(ciphers_hex), 10):
            chunk = ciphers_hex[i:i+10]
            accepted.extend(self._process_tls_chunk(target, port, proto_hex, chunk, ciphers_hex, ciphers_des))
        if not accepted:
            return False, []
        accepted_ids = [c[0] for c in accepted]
        enforced = self._check_cipher_order_enforcement(target, port, proto_hex, accepted_ids)
        if enforced:
            ordered_ids = self.sort_ciphers_by_server_preference(target, port, proto_hex, accepted_ids)
            final_list = []
            for hx in ordered_ids:
                desc = next((c[1] for c in accepted if c[0] == hx), f"UNKNOWN_{hex(hx)}")
                final_list.append((hx, desc))
            return True, final_list
        return False, accepted

    def sort_ciphers_by_server_preference(self, target, port, proto_hex, accepted_hex):
        """ Identifie l'ordre de préférence exact du serveur """
        ordered = []
        to_test = list(accepted_hex)
        while to_test:
            sock = self._tcp_connection(target, port)
            if not sock:
                break
            pkt = self._make_handshake(sock, proto_hex, to_test)
            pref = self._extract_cipher_robust(pkt)
            if sock:
                sock.close()
            if pref is not None:
                ordered.append(pref)
                try:
                    to_test.remove(pref)
                except ValueError:
                    break
            else:
                break
        return ordered

    def lancer(self, protocoles):
        """ Point d'entrée du testeur """
        self.resultat = {}
        c_hex_leg, c_des_leg = self._read_cipherList(False)
        c_hex_13, c_des_13 = self._read_cipherList(True)
        for p in protocoles:
            if p['supporte']:
                h, d = (c_hex_13, c_des_13) if p['nom'] == 'TLS 1.3' else (c_hex_leg, c_des_leg)
                order, suites = self.enumerate_ciphers(self.fqdn, self.port, p['nom'], h, d)
                self.resultat[p['nom']] = [order, [s[:2] for s in suites] if suites else []]