from __future__ import annotations


import gzip
import json
import os
import re
from typing import Dict, Any
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cache global de la Chromium HSTS Preload List (chargé une seule fois)
_chromium_preload_cache = None
_chromium_cache_loaded = False


class TestHSTS:

    def __init__(self, fqdn: str, port: int, ip: str):
        self.fqdn = fqdn
        self.port = port
        self.ip = ip
        self.timeout = 10

    def lancer(self) -> Dict[str, Any]:
        try:
            hsts_header = self._get_hsts_header()
            preloaded = self._check_hsts_preload()

            if not hsts_header and not preloaded:
                return {
                    'erreur': False,
                    'present': False,
                    'severite': 'ATTENTION',
                    'recommandation': 'Activer HSTS pour forcer HTTPS et prévenir les attaques downgrade'
                }

            # Cas où le domaine est preloadé mais sans header
            if not hsts_header and preloaded:
                return {
                    'erreur': False,
                    'present': True,
                    'header': None,
                    'max_age': None,
                    'include_subdomains': True,
                    'preload': True,
                    'severite': 'EXCELLENT',
                    'recommandations': [
                        'Domaine présent dans la HSTS Preload List des navigateurs.',
                        'HTTPS est forcé par les navigateurs sans avoir besoin du header HTTP.'
                    ]
                }

            # Analyse de l'en-tête HSTS
            analyse = self._analyser_hsts_header(hsts_header)

            resultats = {
                'erreur': False,
                'present': True,
                'header': hsts_header,
                'max_age': analyse.get('max_age'),
                'include_subdomains': analyse.get('include_subdomains', False),
                'preload': analyse.get('preload', False),
                'severite': self._determiner_severite(analyse),
                'recommandations': self._generer_recommandations(analyse)
            }

            return resultats

        except Exception as e:
            return {
                'erreur': True,
                'message': f'Erreur lors du test HSTS: {str(e)}'
            }

    def _get_hsts_header(self) -> str:
        if self.port == 443:
            url = f"https://{self.fqdn}/"
        else:
            url = f"https://{self.fqdn}:{self.port}/"

        try:
            # Première tentative sans suivre les redirections
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )

            hsts = response.headers.get('Strict-Transport-Security', '')
            if hsts:
                return hsts

            # Si pas trouvé, essayer en suivant les redirections
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            return response.headers.get('Strict-Transport-Security', '')

        except Exception:
            return ""

    def _check_hsts_preload(self) -> bool:
        """
        Vérifie si le domaine est dans la HSTS Preload List.
        Étape 1 : API hstspreload.org
        Étape 2 : Fichier local Chromium preload list
        """
        domains_to_check = [self.fqdn]
        if self.fqdn.startswith('www.'):
            domains_to_check.append(self.fqdn[4:])

        # Étape 1 : API hstspreload.org
        for domain in domains_to_check:
            try:
                response = requests.get(
                    f"https://hstspreload.org/api/v2/status?domain={domain}",
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') in ('preloaded', 'pending'):
                        return True
            except Exception:
                continue

        # Étape 2 : Chromium preload list (fichier local)
        return self._check_chromium_preload()

    def _check_chromium_preload(self) -> bool:
        """
        Vérifie le domaine dans la Chromium preload list locale.
        """
        global _chromium_preload_cache, _chromium_cache_loaded

        if not _chromium_cache_loaded:
            _chromium_cache_loaded = True
            try:
                data_file = os.path.join(
                    os.path.dirname(__file__),
                    'chromium_hsts_preload.json.gz'
                )
                with gzip.open(data_file, 'rt', encoding='utf-8') as f:
                    _chromium_preload_cache = json.load(f)
            except Exception:
                _chromium_preload_cache = {}

        if not _chromium_preload_cache:
            return False

        # Vérifier le domaine et tous ses parents
        domain = self.fqdn.lower()
        parts = domain.split('.')

        for i in range(len(parts)):
            check = '.'.join(parts[i:])
            if check in _chromium_preload_cache:
                if i == 0 or _chromium_preload_cache[check]:
                    return True

        # Vérifier sans TLD (ex: "google" pour google.com)
        if len(parts) >= 2:
            base_name = '.'.join(parts[:-1])
            if base_name.startswith('www.'):
                base_name = base_name[4:]
            if base_name in _chromium_preload_cache:
                if _chromium_preload_cache[base_name]:
                    return True

        return False

    def _analyser_hsts_header(self, hsts_header: str) -> Dict[str, Any]:
        analyse = {
            'max_age': None,
            'include_subdomains': False,
            'preload': False
        }

        # Extraction du max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts_header, re.IGNORECASE)
        if max_age_match:
            analyse['max_age'] = int(max_age_match.group(1))

        # Vérification de includeSubDomains
        if re.search(r'includeSubDomains', hsts_header, re.IGNORECASE):
            analyse['include_subdomains'] = True

        # Vérification de preload
        if re.search(r'preload', hsts_header, re.IGNORECASE):
            analyse['preload'] = True

        return analyse

    def _determiner_severite(self, analyse: Dict[str, Any]) -> str:
        """
        Détermine la sévérité de la configuration HSTS

        Args:
            analyse: Analyse HSTS

        Returns:
            str: Niveau de sévérité
        """
        max_age = analyse.get('max_age', 0)

        # Recommandation: max-age >= 31536000 (1 an)
        if max_age >= 31536000:
            if analyse.get('include_subdomains') and analyse.get('preload'):
                return 'EXCELLENT'
            elif analyse.get('include_subdomains'):
                return 'BON'
            else:
                return 'ACCEPTABLE'
        elif max_age >= 86400:  # 1 jour
            return 'FAIBLE'
        else:
            return 'INSUFFISANT'

    def _generer_recommandations(self, analyse: Dict[str, Any]) -> list:
        """
        Génère des recommandations basées sur l'analyse HSTS

        Args:
            analyse: Analyse HSTS

        Returns:
            list: Liste de recommandations
        """
        recommandations = []
        max_age = analyse.get('max_age', 0)

        # Recommandations sur max-age
        if max_age < 86400:  # < 1 jour
            recommandations.append('CRITIQUE: max-age trop faible (< 1 jour). Augmenter à 31536000 (1 an).')
        elif max_age < 31536000:  # < 1 an
            recommandations.append('Augmenter max-age à 31536000 (1 an) pour conformité recommandée.')
        else:
            recommandations.append(f'Bon max-age: {max_age} secondes ({max_age // 86400} jours).')

        # Recommandation includeSubDomains
        if not analyse.get('include_subdomains'):
            recommandations.append('Ajouter "includeSubDomains" pour protéger tous les sous-domaines.')
        else:
            recommandations.append('includeSubDomains activé: tous les sous-domaines sont protégés.')

        # Recommandation preload
        if not analyse.get('preload'):
            recommandations.append('Considérer l\'ajout de "preload" et soumettre à hstspreload.org.')
        else:
            recommandations.append('Preload activé: domaine éligible pour la liste HSTS preload.')

        return recommandations
