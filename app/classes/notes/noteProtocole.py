from __future__ import annotations
from typing import Any, List, Dict
from classes.notes.noteBase import NoteBase


class NoteProtocole(NoteBase):
    """
    Classe pour calculer la note des protocoles SSL/TLS.
    
    Méthode de calcul :
        1. Identifier le meilleur protocole supporté
        2. Prendre sa note de base
        3. Appliquer les pénalités pour les autres protocoles supportés
    
    Table des notes et pénalités :
        TLS 1.3 (meilleur) : 100 / pénalité -0
        TLS 1.2 (meilleur) : 80 / pénalité -5
        TLS 1.1 (meilleur) : 50 / pénalité -10
        TLS 1.0 (meilleur) : 30 / pénalité -20
        SSL 2.0/3.0 : 0 (bloquant)
    """

    # Protocoles dangereux (bloquants)
    PROTOCOLES_DANGEREUX = {"SSL 2.0", "SSL 3.0"}

    # Mapping protocole → (note_base, penalite)
    PROTOCOLES = {
        "TLS 1.3": (100.0, 0.0),
        "TLS 1.2": (80.0, 5.0),
        "TLS 1.1": (50.0, 10.0),
        "TLS 1.0": (30.0, 20.0),
    }

    def __init__(self):
        super().__init__()

    def calculerNote(self, listeDesResultats: List[Dict[str, Any]] | None = None):
        """
        Calcule la note de sécurité des protocoles selon la méthode définie.
        """
        if not listeDesResultats:
            self.note = 0.0
            return

        # État de support des protocoles
        support_ssl2_ssl3 = False
        protocoles_supportes = set()

        for proto in listeDesResultats:
            nom = proto.get("nom", "")
            supporte = proto.get("supporte", False)

            if not supporte:
                continue

            # Règle SSL 2.0/3.0 : bloquant
            if nom in self.PROTOCOLES_DANGEREUX:
                support_ssl2_ssl3 = True

            if nom in self.PROTOCOLES:
                protocoles_supportes.add(nom)

        # Règle 1 : SSL 2.0 ou SSL 3.0 → 0
        if support_ssl2_ssl3:
            self.note = 0.0
            return

        # Règle 2 : Aucun protocole supporté → 0
        if not protocoles_supportes:
            self.note = 0.0
            return

        # Trouver le meilleur protocole (ordre: TLS 1.3 > 1.2 > 1.1 > 1.0)
        ordre_priorite = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"]
        meilleur = None
        for proto in ordre_priorite:
            if proto in protocoles_supportes:
                meilleur = proto
                break

        if meilleur is None:
            self.note = 0.0
            return

        # Note de base du meilleur protocole
        note_base, _ = self.PROTOCOLES[meilleur]
        note = note_base

        # Appliquer les pénalités pour les autres protocoles
        for proto in protocoles_supportes:
            if proto == meilleur:
                continue
            _, penalite = self.PROTOCOLES[proto]
            note -= penalite

        # Note minimale 0
        if note < 0:
            note = 0.0

        self.note = note