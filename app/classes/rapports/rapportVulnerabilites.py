from __future__ import annotations
from typing import Any
from classes.rapports.rapportBase import RapportBase


class RapportVulnerabilites(RapportBase):
    """"""

    def __init__(self):
        # ca marche comme ca l'heritage en python
        super().__init__()

    def genererRapport(self, listeDesResultats: Any | None = None):
        if listeDesResultats is None or listeDesResultats.get('erreur'):
            self.rapport = {'erreur': True}
            return

        resume = listeDesResultats.get('resume', {})
        hsts_data = listeDesResultats.get('hsts', {})

        self.rapport = {
            'erreur': False,
            'nombre': resume.get('nombre_vulnerabilites', 0),
            'severite_globale': resume.get('severite_globale', 'OK'),
            'critiques': resume.get('vulnerabilites_critiques', []),
            'hautes': resume.get('vulnerabilites_hautes', []),
            'moyennes': resume.get('vulnerabilites_moyennes', []),
            'faibles': resume.get('vulnerabilites_faibles', []),
            'avertissements': resume.get('avertissements', []),
            # Champs HSTS
            'hsts_present': hsts_data.get('present', False),
            'hsts_preloaded': hsts_data.get('preloaded', False),
            'hsts_max_age': hsts_data.get('max_age'),
            'hsts_include_subdomains': hsts_data.get('include_subdomains', False),
            'hsts_preload': hsts_data.get('preload', False),
            'hsts_severite': hsts_data.get('severite'),
            'hsts_recommandations': hsts_data.get('recommandations', []),
            # Données détaillées
            'hsts': hsts_data,
            'heartbleed': listeDesResultats.get('heartbleed', {}),
            'config': listeDesResultats.get('config', {}),
            'resume': resume
        }