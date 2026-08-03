from __future__ import annotations
from typing import Any, List, Dict
from classes.rapports.rapportBase import RapportBase


class RapportProtocole(RapportBase):
    """
    Génère un rapport des protocoles SSL/TLS testés avec TestProtocole.
    Chaque entrée contient:
        - nom: nom du protocole
        - supporte: True/False
        - obsolete: True si le protocole est obsolète
    """

    # Protocoles considérés comme obsolètes
    OBSOLETES = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}

    def __init__(self):
        super().__init__()

    def genererRapport(self, listeDesResultats: List[Dict[str, Any]] | None = None):
        """
        Transforme la liste de résultats du test en rapport structuré
        avec le champ 'obsolete'
        """
        if listeDesResultats is None:
            listeDesResultats = []

        rapport: List[Dict[str, Any]] = []

        protocoles_vus = {r["nom"] for r in listeDesResultats}
        if "SSL 2.0" not in protocoles_vus:
            listeDesResultats.insert(0, {"nom": "SSL 2.0", "supporte": False})

        for proto in listeDesResultats:
            nom = proto["nom"]
            supporte = proto.get("supporte", False)
            obsolete = nom in self.OBSOLETES
            rapport.append({"nom": nom, "supporte": supporte, "obsolete": obsolete})

        self.rapport = rapport
