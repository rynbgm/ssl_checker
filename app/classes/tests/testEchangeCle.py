import os
import socket
from scapy.all import Ether, TCP
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSServerKeyExchange, Raw, TLSAlert
from scapy.layers.tls.extensions import (
    TLS_Ext_SupportedVersion_CH, TLS_Ext_ServerName, ServerName,
    TLS_Ext_SupportedGroups, TLS_Ext_SignatureAlgorithms,
    TLS_Ext_SupportedPointFormat, TLS_Ext_SessionTicket,
    TLS_Ext_EncryptThenMAC, TLS_Ext_ExtendedMasterSecret,
    TLS_Ext_PSKKeyExchangeModes, TLS_Ext_Unknown
)
from scapy.layers.tls.keyexchange_tls13 import TLS_Ext_KeyShare_CH, KeyShareEntry
from classes.tests.testBase import TestBase

class TestEchangeCle(TestBase):
    def __init__(self, fqdn: str, port: str):
        super().__init__(fqdn, port)
        self.fqdn = fqdn 
        self.port = port
        self.protocoles = {
            'SSL 2.0': 0x0200,
            'SSL 3.0': 0x0300,
            'TLS 1.0': 0x0301,
            'TLS 1.1': 0x0302,
            'TLS 1.2': 0x0303,
            'TLS 1.3': 0x0304
        }
        # Dictionnaire des courbes
        self.dict_curves = {
            256: {"nom": "FFDHE-2048", "taille": 2048},
            257: {"nom": "FFDHE-3072", "taille": 3072},
            258: {"nom": "FFDHE-4096", "taille": 4096},
            259: {"nom": "FFDHE-6144", "taille": 6144},
            260: {"nom": "FFDHE-8192", "taille": 8192},
            23:  {"nom": "secp256r1 (NIST P-256)", "taille": 3072},
            24:  {"nom": "secp384r1 (NIST P-384)", "taille": 7680},
            29:  {"nom": "X25519", "taille": 3072},
            4588:{"nom": "X25519MLKEM768 (PQC)", "taille": 7680}, 
            25497:{"nom": "X25519Kyber768", "taille": 7680}
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
            # Type 27: Compress Certificate (Valeur brute)
            TLS_Ext_Unknown(type=27, val=b"\x04\x00\x01\x00\x03")
        ]

    def _tcp_connection(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4.0)
        try:
            sock.connect((self.fqdn, int(self.port)))
            return sock
        except Exception:
            return False

    def _make_handshake(self, sock, protocole_hex, cipher_hex, curves_list=None): 
        record_version = 0x0303 if protocole_hex == 0x0304 else protocole_hex
        client_hello_version = 0x0303 if protocole_hex == 0x0304 else protocole_hex
        
        filtered_exts = []
        tls_ext = [
            TLS_Ext_ServerName(servernames=[ServerName(servername=self.fqdn.encode('utf-8'))]),                
            TLS_Ext_SupportedPointFormat(ecpl=[0]),
            TLS_Ext_SignatureAlgorithms(sig_algs=[
                "sha256+rsa", "sha256+ecdsa", 
                "sha384+rsa", "sha384+ecdsa", 
                "sha512+rsa", "sha1+rsa"
            ])
        ]
        
        for ext in self.openssl_extensions:
            if isinstance(ext, TLS_Ext_ServerName) or isinstance(ext, TLS_Ext_SupportedGroups):
                continue
            filtered_exts.append(ext)
            
        filtered_exts.insert(0, TLS_Ext_ServerName(servernames=[ServerName(servername=self.fqdn.encode('utf-8'))]))

        if curves_list:
            filtered_exts.append(TLS_Ext_SupportedGroups(groups=curves_list))
            tls_ext.append(TLS_Ext_SupportedGroups(groups=curves_list))

        tls_pkg = TLS(
            version=record_version,
            msg=[TLSClientHello(version=client_hello_version, ciphers=[cipher_hex], comp=[0], ext=tls_ext if protocole_hex < 0x0304 else filtered_exts)]
        )
        
        try:
            sock.send(bytes(tls_pkg))
            response_bytes = b""
            sock.settimeout(1.0)
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    response_bytes += chunk
                except socket.timeout:
                    break
            if not response_bytes: return False
            return TLS(response_bytes)
        except Exception:
            return False

    def _parse_raw_ske(self, raw_bytes, algo):
        '''Extraction taille de cle '''
        try:
            offset = 4 
            if algo == 'DHE': 
                p_len = int.from_bytes(raw_bytes[offset:offset+2], 'big')
                return p_len * 8
            elif algo == 'ECDHE':
                curve_type = raw_bytes[offset]
                offset += 1
                if curve_type == 3: # NamedCurve
                    curve_id = int.from_bytes(raw_bytes[offset:offset+2], 'big')
                    return curve_id
            elif algo == 'RSA_EXP':
                mod_len = int.from_bytes(raw_bytes[offset:offset+2], 'big')
                return mod_len * 8
        except Exception:
            return False
        return False

    def _enum_key(self, proto_hex, cipher_hex, algo, curves_list=None):
        sock = self._tcp_connection()
        if not sock: 
            return False
        
        try:
            pkt = self._make_handshake(sock, proto_hex, cipher_hex, curves_list)
            if not pkt:
                return False
            if pkt.haslayer(TLSAlert):
                return False
            if proto_hex == 0x0304: # TLS 1.3
                return self._extract_tls13_keyshare(pkt)

            return self._extract_tls12_ske(pkt, algo)
        finally:
            sock.close()

    def _extract_tls13_keyshare(self, pkt):
        res_parsed = self._get_parsed_keyshare(pkt)
        if res_parsed is not None:
            return res_parsed
        return self._search_raw_keyshare(pkt)

    def _get_parsed_keyshare(self, pkt):
        if not pkt.haslayer(TLSServerHello):
            return None
        for ext in pkt[TLSServerHello].ext:
            if getattr(ext, 'type', None) != 51:
                continue
            if hasattr(ext, 'server_share'):
                return ext.server_share.group
            if hasattr(ext, 'client_shares') and ext.client_shares:
                return ext.client_shares[0].group
        return None

    def _search_raw_keyshare(self, pkt):
        current_layer = pkt
        while current_layer:
            res = self._check_tls_messages_for_keyshare(current_layer)
            if res:
                return res
            current_layer = current_layer.payload
        return False

    def _check_tls_messages_for_keyshare(self, layer):
        if not layer.haslayer(TLS) or not hasattr(layer[TLS], 'msg'):
            return False
        for msg in layer[TLS].msg:
            res = self._parse_raw_tls13_msg(msg)
            if res:
                return res
        return False

    def _parse_raw_tls13_msg(self, msg):
        try:
            raw_data = msg.load if hasattr(msg, 'load') else bytes(msg)
        except Exception:
            return False
            
        if len(raw_data) <= 38 or raw_data[0] != 2: 
            return False
            
        sess_id_len = raw_data[38]
        offset = 39 + sess_id_len
        
        if offset + 5 > len(raw_data): 
            return False
            
        offset += 3 
        ext_len = int.from_bytes(raw_data[offset:offset+2], 'big')
        offset += 2
        
        return self._find_keyshare_in_extensions(raw_data, offset, ext_len)

    def _find_keyshare_in_extensions(self, raw_data, offset, ext_len):
        end_ext = offset + ext_len
        while offset + 4 <= min(end_ext, len(raw_data)):
            ext_type = int.from_bytes(raw_data[offset:offset+2], 'big')
            ext_item_len = int.from_bytes(raw_data[offset+2:offset+4], 'big')
            
            if ext_type == 51 and ext_item_len >= 2:
                return int.from_bytes(raw_data[offset+4:offset+6], 'big')
            offset += 4 + ext_item_len
        return False

    def _extract_tls12_ske(self, pkt, algo):
        """Point d'entrée principal pour l'extraction SKE (TLS <= 1.2)"""
        
        res_parsed = self._get_parsed_ske(pkt, algo)
        if res_parsed is not None:
            return res_parsed
            
        # 2. Sinon, extraction brute dans tous les fragments TLS non parsés
        return self._search_raw_ske(pkt, algo)

    def _get_parsed_ske(self, pkt, algo):
        """Parcourt les couches pour trouver un TLSServerKeyExchange déjà parsé"""
        current_layer = pkt
        while current_layer:
            if current_layer.haslayer(TLSServerKeyExchange):
                raw_payload = bytes(current_layer[TLSServerKeyExchange])
                res = self._parse_raw_ske(raw_payload, algo)
                if res: 
                    return res
            current_layer = current_layer.payload
        return None

    def _search_raw_ske(self, pkt, algo):
        """Recherche le SKE dans les données brutes si le parsing a échoué"""
        current_layer = pkt
        while current_layer:
            res = self._check_tls_messages_for_ske(current_layer, algo)
            if res:
                return res
            current_layer = current_layer.payload
        return False

    def _check_tls_messages_for_ske(self, layer, algo):
        """Vérifie chaque message d'une couche TLS spécifique"""
        if not layer.haslayer(TLS) or not hasattr(layer[TLS], 'msg'):
            return False
            
        for msg in layer[TLS].msg:
            res = self._parse_raw_tls12_msg(msg, algo)
            if res:
                return res
        return False

    def _parse_raw_tls12_msg(self, msg, algo):
        """Itère sur les octets bruts pour isoler le message de type 12 (SKE)"""
        try:
            raw_data = msg.load if hasattr(msg, 'load') else bytes(msg)
        except Exception:
            return False

        idx = 0
        while idx < len(raw_data) - 4:
            hs_type = raw_data[idx]
            hs_len = int.from_bytes(raw_data[idx+1:idx+4], 'big')
            
            # Clause de garde inversée : si ce n'est pas le type 12, on avance
            if hs_type != 12: 
                idx += 4 + hs_len
                continue
                
            # Si c'est le type 12 (ServerKeyExchange), on parse et on retourne
            res = self._parse_raw_ske(raw_data[idx:idx+4+hs_len], algo)
            if res: 
                return res
                
            idx += 4 + hs_len
            
        return False

    def enumerate_curves(self, proto_name, cipher_hex, algo):
        if proto_name not in self.protocoles:
            return []
            
        proto_hex = self.protocoles[proto_name]
        supported_curves = []
        current_curves_list = list(self.dict_curves.keys())

        while current_curves_list:
            chosen_curve_id = self._enum_key(proto_hex, cipher_hex, algo, current_curves_list)
            
            if chosen_curve_id and chosen_curve_id in current_curves_list:
                curve_info = self.dict_curves[chosen_curve_id]
                supported_curves.append(curve_info)
                current_curves_list.remove(chosen_curve_id)
            else:
                break
                
        return supported_curves

    def lancer(self, certificat, ciphers):
        self.resultat = {}
        self.algos_a_trouver = {'ECDHE', 'DHE', 'RSA', 'DH', 'ECDH'}
        
        self.rsa_eqev = {
            256: 3072,
            384: 7680,
            448: 15360,
            521: 15360
        }
        cle = certificat.get('cle_publique', {})
        
        for protocole, suites in ciphers.items():
            for cipher in suites[1]:
                if not self.algos_a_trouver:
                    break
                    
                if protocole == 'TLS 1.3':
                    self.resultat['TLS_1_3_ECDHE'] = self.enumerate_curves(protocole, cipher[0], 'ECDHE')
                    break 
                else:
                    self._traiter_cipher(protocole, cipher, cle)
                    
        return self.resultat 

    def _traiter_cipher(self, protocole, cipher, cle):
        nom_cipher = cipher[1]
        hex_cipher = cipher[0]

        ciphers_speciaux = {
            'TLS_DH_anon': 'DH_anon',
            'TLS_ECDH_anon': 'ECDH_anon',
            'TLS_RSA_RSA_EXPORT': 'RSA_EXPORT',
            'TLS_NULL': 'NULL'
        }
        
        for motif, cle_res in ciphers_speciaux.items():
            if motif in nom_cipher and cle_res not in self.resultat:
                self.resultat[cle_res] = 0
                return 

        if 'TLS_ECDHE' in nom_cipher and 'ECDHE' in self.algos_a_trouver:
            self.resultat['ECDHE'] = self.enumerate_curves(protocole, hex_cipher, 'ECDHE')
            self.algos_a_trouver.remove('ECDHE')
            return

        if 'TLS_DHE' in nom_cipher and 'DHE' in self.algos_a_trouver:
            self.resultat['DHE'] = self._enum_key(self.protocoles[protocole], hex_cipher, 'DHE')
            self.algos_a_trouver.remove('DHE')
            return

        if 'TLS_RSA' in nom_cipher and cle.get('type') == 'RSA' and 'RSA' in self.algos_a_trouver:
            self.resultat['RSA'] = cle.get('taille', 0)
            self.algos_a_trouver.remove('RSA')
            return

        if 'TLS_DH_' in nom_cipher and cle.get('type') == 'DH' and 'DH' in self.algos_a_trouver:
            self.resultat['DH'] = cle.get('taille', 0)
            self.algos_a_trouver.remove('DH')
            return

        if 'TLS_ECDH_' in nom_cipher and cle.get('type') == 'EC' and 'ECDH' in self.algos_a_trouver:
            taille_ec = cle.get('taille', 0)
            self.resultat['ECDH'] = {
                'nom': cle.get('courbe', ''),
                'taille': self.rsa_eqev.get(taille_ec, taille_ec)
            }
            self.algos_a_trouver.remove('ECDH')