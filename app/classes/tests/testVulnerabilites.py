from __future__ import annotations
from typing import Dict, Any, List
from classes.tests.testBase import TestBase
from classes.tests.testsvuln.testHsts import TestHSTS
from classes.tests.testsvuln.testVulnConfig import TestVulnConfig
from classes.tests.testsvuln.testHeartbleed import TestHeartbleed


class TestVulnerabilites(TestBase):
    def __init__(self, fqdn: str, port: str):
        super().__init__(fqdn, port)
        self.protocoles: List[str] = []
        self.ciphers: List[Dict[str, Any]] = []
        self.test_hsts = TestHSTS(fqdn, int(port), '')
        self.test_vuln_config = TestVulnConfig(fqdn, int(port), '')
        self.test_heartbleed = TestHeartbleed(fqdn, int(port), '')

    def lancer(self, protocoles: List[Dict[str, Any]], ciphers: Dict[str, List[str]]) -> None:
        ciphers_list: List[Dict[str, Any]] = []
        for cipher_names in ciphers.values():
            for nom in cipher_names[1]:
                nom_upper = nom[1].upper()
                if 'ECDHE' in nom_upper:
                    key_exchange, forward_secrecy = 'ECDHE', True
                elif 'DHE' in nom_upper or 'EDH' in nom_upper:
                    key_exchange, forward_secrecy = 'DHE', True
                elif 'ECDH' in nom_upper:
                    key_exchange, forward_secrecy = 'ECDH', False
                elif 'DH' in nom_upper:
                    key_exchange, forward_secrecy = 'DH', False
                else:
                    key_exchange, forward_secrecy = 'RSA', False
                ciphers_list.append({'nom': nom[1], 'key_exchange': key_exchange, 'forward_secrecy': forward_secrecy})

        try:
            hsts: Dict[str, Any] = self.test_hsts.lancer()
            vuln_config: Dict[str, Any] = self.test_vuln_config.lancer(protocoles, ciphers_list)
            heartbleed: Dict[str, Any] = self.test_heartbleed.lancer()

            self.resultat = {
                'erreur': False,
                'heartbleed': heartbleed,
                'hsts': hsts,
                'config': vuln_config,
                'resume': self._generer_resume(hsts, vuln_config, heartbleed)
            }

        except Exception as e:
            self.resultat = {
                'erreur': True,
                'message': f'Erreur lors des tests: {str(e)}'
            }

    def _generer_resume(self, hsts: Dict[str, Any], vuln_config: Dict[str, Any], heartbleed: Dict[str, Any]) -> Dict[str, Any]:
        resume: Dict[str, Any] = {
            'nombre_vulnerabilites': 0,
            'vulnerabilites_critiques': [],
            'vulnerabilites_hautes': [],
            'vulnerabilites_moyennes': [],
            'vulnerabilites_faibles': [],
            'avertissements': [],
            'severite_globale': 'OK'
        }

        # HSTS
        if not hsts.get('erreur'):
            if not hsts.get('present'):
                resume['avertissements'].append({
                    'nom': 'HSTS Absent',
                    'description': 'En-tête HSTS non configuré',
                    'recommandation': hsts.get('recommandation')
                })
            elif hsts.get('severite') in ['FAIBLE', 'INSUFFISANT']:
                resume['avertissements'].append({
                    'nom': 'HSTS Faible',
                    'description': 'Configuration HSTS non optimale',
                    'recommandations': hsts.get('recommandations')
                })

        # Heartbleed (toujours affiché)
        heartbleed_info: Dict[str, Any] = {
            'nom': heartbleed.get('nom'),
            'cve': heartbleed.get('cve'),
            'vulnerable': heartbleed.get('vulnerable'),
            'description': heartbleed.get('description'),
            'recommandation': heartbleed.get('recommandation')
        }
        if heartbleed.get('vulnerable'):
            resume['nombre_vulnerabilites'] += 1
            resume['vulnerabilites_critiques'].append(heartbleed_info)

        # Vulnérabilités de configuration (seulement les vulnérables dans les buckets)
        if not vuln_config.get('erreur'):
            for vuln in vuln_config.get('vulnerabilites', []):
                if not vuln.get('vulnerable'):
                    continue

                resume['nombre_vulnerabilites'] += 1
                vuln_info: Dict[str, Any] = {
                    'nom': vuln.get('nom'),
                    'cve': vuln.get('cve'),
                    'vulnerable': vuln.get('vulnerable'),
                    'description': vuln.get('description'),
                    'recommandation': vuln.get('recommandation')
                }

                severite: str = vuln.get('severite', 'OK')

                if severite == 'CRITIQUE':
                    resume['vulnerabilites_critiques'].append(vuln_info)
                elif severite == 'HAUTE':
                    resume['vulnerabilites_hautes'].append(vuln_info)
                elif severite == 'MOYENNE':
                    resume['vulnerabilites_moyennes'].append(vuln_info)
                else:
                    resume['vulnerabilites_faibles'].append(vuln_info)

        # Sévérité globale (basée uniquement sur les vulnérabilités réelles)
        vulns_critiques = [v for v in resume['vulnerabilites_critiques'] if v.get('vulnerable')]
        vulns_hautes = [v for v in resume['vulnerabilites_hautes'] if v.get('vulnerable')]
        vulns_moyennes = [v for v in resume['vulnerabilites_moyennes'] if v.get('vulnerable')]
        vulns_faibles = [v for v in resume['vulnerabilites_faibles'] if v.get('vulnerable')]

        if vulns_critiques:
            resume['severite_globale'] = 'CRITIQUE'
        elif vulns_hautes:
            resume['severite_globale'] = 'HAUTE'
        elif vulns_moyennes:
            resume['severite_globale'] = 'MOYENNE'
        elif vulns_faibles or resume['avertissements']:
            resume['severite_globale'] = 'FAIBLE'
        else:
            resume['severite_globale'] = 'OK'

        return resume
