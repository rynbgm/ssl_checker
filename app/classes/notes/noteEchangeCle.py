from __future__ import annotations
from typing import Any
from classes.notes.noteBase import NoteBase

class NoteEchangeCle(NoteBase):

    def __init__(self):
        super().__init__()

    def calculerNote(self, listeDesResultats: Any | None = None) -> None:
        if not isinstance(listeDesResultats, dict):
            self.note = 0
            return
            
        # Clause de garde pour les protocoles très faibles
        mots_faibles = ['anon', 'EXPORT', 'NULL']
        if any(mot in k for k in listeDesResultats for mot in mots_faibles):
            self.note = 0
            return

        notes_individuelles = []
        courbes_vues = set()

    
        cles_courbes = ["TLS_1_3_ECDHE", "TLS!_3_ECDHE", "ECDHE"]
        self._extraire_notes_courbes(listeDesResultats, cles_courbes, courbes_vues, notes_individuelles)

        cles_entiers = ["DHE", "RSA", "DH"]
        self._extraire_notes_entiers(listeDesResultats, cles_entiers, notes_individuelles)

        ecdh = listeDesResultats.get("ECDH")
        if isinstance(ecdh, dict) and "taille" in ecdh:
            notes_individuelles.append(self._noter_taille(ecdh["taille"]))

        # Calcul de la moyenne finale
        if notes_individuelles:
            self.note = sum(notes_individuelles) / len(notes_individuelles)
        else:
            self.note = 0

    def _extraire_notes_courbes(self, resultats: dict, cles: list[str], courbes_vues: set, notes: list[float]) -> None:
        """Parcourt les résultats pour extraire les notes des courbes (ECDHE)."""
        for cle in cles:
            curves = resultats.get(cle)
            
            if not isinstance(curves, list):
                continue

            for curve in curves:
                if not isinstance(curve, dict) or "taille" not in curve:
                    continue

                nom = curve.get("nom", "")
                taille = curve.get("taille", 0)
                cle_unique = f"{nom}_{taille}"

                # On ignore les doublons
                if cle_unique in courbes_vues:
                    continue

                courbes_vues.add(cle_unique)
                notes.append(self._noter_taille(taille))

    def _extraire_notes_entiers(self, resultats: dict, cles: list[str], notes: list[float]) -> None:
        """Parcourt les résultats pour extraire les notes des clés entières (RSA, DHE, DH)."""
        for cle in cles:
            taille = resultats.get(cle)
            if isinstance(taille, int):
                notes.append(self._noter_taille(taille))

    def _noter_taille(self, taille: int) -> float:
        """Évalue la taille de la clé et retourne une note sur 100."""

        if taille >= 7680: return 100.0
        if taille >= 4096: return 90.0
        if taille >= 3072: return 80.0
        if taille >= 2048: return 70.0
        if taille >= 1536: return 40.0
        if taille >= 1024: return 20.0
        return 0.0