from __future__ import annotations


import ssl
import socket
from typing import Dict, Any, List


class TestVulnConfig:

    def __init__(self, fqdn: str, port: int, ip: str):

        self.fqdn = fqdn
        self.port = port
        self.ip = ip
        self.timeout = 10

    def lancer(self, protocoles: List[Dict[str, Any]], ciphers: List[Dict[str, Any]]) -> Dict[str, Any]:
      
        try:
            vulnerabilites = []

            vulnerabilites.append(self._test_poodle(protocoles))
            vulnerabilites.append(self._test_sweet32(ciphers))
            vulnerabilites.append(self._test_rc4(ciphers))
            vulnerabilites.append(self._test_export_ciphers(ciphers))
            vulnerabilites.append(self._test_null_ciphers(ciphers))
            vulnerabilites.append(self._test_weak_dh(ciphers))

            vulnerables = [v for v in vulnerabilites if v.get('vulnerable')]
            resultats = {
                'erreur': False,
                'vulnerabilites': vulnerabilites,
                'nombre_vulnerabilites': len(vulnerables),
                'severite_globale': self._determiner_severite_globale(vulnerables)
            }

            return resultats

        except Exception as e:
            return {
                'erreur': True,
                'message': f'Erreur lors des tests de vulnérabilités: {str(e)}'
            }

    def _test_poodle(self, protocoles: List[Dict[str, Any]]) -> Dict[str, Any]:

        vulnerable = any(p.get('nom') == 'SSL 3.0' and p.get('supporte', False) for p in protocoles)

        return {
            'nom': 'POODLE',
            'cve': 'CVE-2014-3566',
            'vulnerable': vulnerable,
            'severite': 'HAUTE' if vulnerable else 'PAS VULNÉRABLE',
            'description': 'Padding Oracle On Downgraded Legacy Encryption - vulnérabilité dans SSLv3',
            'recommandation': 'Désactiver SSLv3 complètement' if vulnerable else 'SSLv3 désactivé',
            'details': 'SSLv3 est actif et vulnérable à POODLE' if vulnerable else 'SSLv3 non supporté'
        }

    def _test_sweet32(self, ciphers: List[Dict[str, Any]]) -> Dict[str, Any]:
       
        # SWEET32 affecte les ciphers utilisant 3DES
        ciphers_3des = [c for c in ciphers if '3DES' in c.get('nom', '')]

        vulnerable = len(ciphers_3des) > 0

        return {
            'nom': 'SWEET32',
            'cve': 'CVE-2016-2183',
            'vulnerable': vulnerable,
            'severite': 'MOYENNE' if vulnerable else 'PAS VULNÉRABLE',
            'description': 'Attaque sur les ciphers 64-bit block (3DES)',
            'recommandation': 'Désactiver tous les ciphers 3DES' if vulnerable else '3DES non utilisé',
            'details': f'{len(ciphers_3des)} cipher(s) 3DES trouvé(s)' if vulnerable else 'Aucun cipher 3DES',
            'ciphers_affectes': [c['nom'] for c in ciphers_3des] if vulnerable else []
        }

    def _test_rc4(self, ciphers: List[Dict[str, Any]]) -> Dict[str, Any]:
      
        ciphers_rc4 = [c for c in ciphers if 'RC4' in c.get('nom', '')]

        vulnerable = len(ciphers_rc4) > 0

        return {
            'nom': 'RC4 Cipher',
            'cve': 'CVE-2013-2566, CVE-2015-2808',
            'vulnerable': vulnerable,
            'severite': 'HAUTE' if vulnerable else 'PAS VULNÉRABLE',
            'description': 'Algorithme de chiffrement RC4 considéré comme non sécurisé',
            'recommandation': 'Désactiver tous les ciphers RC4' if vulnerable else 'RC4 non utilisé',
            'details': f'{len(ciphers_rc4)} cipher(s) RC4 trouvé(s)' if vulnerable else 'Aucun cipher RC4',
            'ciphers_affectes': [c['nom'] for c in ciphers_rc4] if vulnerable else []
        }

    def _test_export_ciphers(self, ciphers: List[Dict[str, Any]]) -> Dict[str, Any]:
       
        # Export ciphers contiennent généralement 'EXP' ou 'EXPORT' dans leur nom
        ciphers_export = [c for c in ciphers if 'EXP' in c.get('nom', '').upper() or 'EXPORT' in c.get('nom', '').upper()]

        vulnerable = len(ciphers_export) > 0

        return {
            'nom': 'Export Ciphers',
            'cve': 'CVE-2015-0204 (FREAK), CVE-2015-4000 (Logjam)',
            'vulnerable': vulnerable,
            'severite': 'CRITIQUE' if vulnerable else 'PAS VULNÉRABLE',
            'description': 'Ciphers d\'exportation avec clés faibles (40-56 bits)',
            'recommandation': 'Désactiver tous les ciphers d\'exportation' if vulnerable else 'Export ciphers désactivés',
            'details': f'{len(ciphers_export)} export cipher(s) trouvé(s)' if vulnerable else 'Aucun export cipher',
            'ciphers_affectes': [c['nom'] for c in ciphers_export] if vulnerable else []
        }

    def _test_null_ciphers(self, ciphers: List[Dict[str, Any]]) -> Dict[str, Any]:
     
        ciphers_null = [c for c in ciphers if 'NULL' in c.get('nom', '').upper() or 'anon' in c.get('nom', '').lower()]

        vulnerable = len(ciphers_null) > 0

        return {
            'nom': 'NULL Ciphers',
            'cve': 'N/A',
            'vulnerable': vulnerable,
            'severite': 'CRITIQUE' if vulnerable else 'PAS VULNÉRABLE',
            'description': 'Ciphers sans chiffrement ou avec authentification anonyme',
            'recommandation': 'Désactiver immédiatement tous les NULL ciphers' if vulnerable else 'NULL ciphers désactivés',
            'details': f'{len(ciphers_null)} NULL cipher(s) trouvé(s)' if vulnerable else 'Aucun NULL cipher',
            'ciphers_affectes': [c['nom'] for c in ciphers_null] if vulnerable else []
        }

    def _test_weak_dh(self, ciphers: List[Dict[str, Any]]) -> Dict[str, Any]:
      
        # Ciphers DH non-éphémères ou avec paramètres faibles
        ciphers_dh = [c for c in ciphers if c.get('key_exchange') in ['DH', 'ECDH'] and not c.get('forward_secrecy', False)]

        vulnerable = len(ciphers_dh) > 0

        return {
            'nom': 'Weak DH Parameters',
            'cve': 'CVE-2015-4000 (Logjam)',
            'vulnerable': vulnerable,
            'severite': 'MOYENNE' if vulnerable else 'PAS VULNÉRABLE',
            'description': 'Paramètres Diffie-Hellman statiques ou faibles',
            'recommandation': 'Utiliser uniquement DHE/ECDHE avec paramètres >= 2048 bits' if vulnerable else 'Configuration DH correcte',
            'details': f'{len(ciphers_dh)} cipher(s) DH statique trouvé(s)' if vulnerable else 'Aucun DH statique',
            'ciphers_affectes': [c['nom'] for c in ciphers_dh] if vulnerable else []
        }

    def _determiner_severite_globale(self, vulnerabilites: List[Dict[str, Any]]) -> str:
       
        if not vulnerabilites:
            return 'PAS VULNÉRABLE'

        severites = [v.get('severite', 'OK') for v in vulnerabilites]

        if 'CRITIQUE' in severites:
            return 'CRITIQUE'
        elif 'HAUTE' in severites:
            return 'HAUTE'
        elif 'MOYENNE' in severites:
            return 'MOYENNE'
        else:
            return 'FAIBLE'
