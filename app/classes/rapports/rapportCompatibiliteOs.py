from __future__ import annotations
from typing import Any, List, Dict
from classes.rapports.rapportBase import RapportBase


class RapportCompatibiliteOs(RapportBase):
    """
    Génère un rapport de compatibilité OS/clients SSL.
    Chaque entrée contient :
        - nom       : nom du client (ex: "Android 9.0")
        - compatible: True/False
    """

    def genererRapport(self, listeDesResultats: List[Dict[str, Any]] | None = None):
        """
        Transforme la liste de résultats du test en rapport structuré.
        """
        if not listeDesResultats:
            self.rapport = []
            return

        self.rapport = [
            {"nom": r["nom"], "compatible": r.get("compatible", False)}
            for r in listeDesResultats
        ]
