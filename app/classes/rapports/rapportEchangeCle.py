from __future__ import annotations
from typing import Any
from classes.rapports.rapportBase import RapportBase


class RapportEchangeCle(RapportBase):

    def __init__(self):
        super().__init__()
        self.nom = "echangeCle"

    def genererRapport(self, resultats: Any | None = None) -> None:
        if not isinstance(resultats, dict):
            self.rapport = {}
            return

        rapport_final = {}

        self._traiter_courbes_ecdhe(resultats, rapport_final)
        self._traiter_cles_entieres(resultats, rapport_final)
        self._traiter_cles_zero(resultats, rapport_final)
        self._traiter_ecdh(resultats, rapport_final)

        self.rapport = rapport_final

    def _traiter_courbes_ecdhe(self, resultats: dict, rapport_final: dict) -> None:
        courbes_vues = set()
        courbes_ecdhe = []
        cles_a_traiter = ["TLS_1_3_ECDHE", "ECDHE"]

        for cle in cles_a_traiter:
            curves = resultats.get(cle)
            
            if not isinstance(curves, list):
                continue
            for curve in curves:
                if not isinstance(curve, dict):
                    continue
                    
                nom = curve.get("nom", "")
                taille = curve.get("taille", 0)
                cle_unique = f"{nom}_{taille}"

                if cle_unique in courbes_vues:
                    continue
                    
                courbes_vues.add(cle_unique)
                courbes_ecdhe.append({
                    "nom": nom,
                    "taille": taille,
                    "force": self._evaluer_force(taille),
                })

        if courbes_ecdhe:
            rapport_final["ecdhe"] = {"courbes": courbes_ecdhe}

    def _traiter_cles_entieres(self, resultats: dict, rapport_final: dict) -> None:
        mapping_cles = {"DHE": "dhe", "RSA": "rsa", "DH": "dh"}
        
        for cle_in, cle_out in mapping_cles.items():
            valeur = resultats.get(cle_in)
            
            if not isinstance(valeur, int):
                continue
                
            rapport_final[cle_out] = {
                "taille": valeur,
                "force": self._evaluer_force(valeur),
            }

    def _traiter_cles_zero(self, resultats: dict, rapport_final: dict) -> None:
        mapping_cles = {
            "DH_anon": "dh_anon",
            "ECDH_anon": "ecdh_anon",
            "RSA_EXPORT": "rsa_export",
            "NULL": "null"
        }
        force_zero = self._evaluer_force(0)
        
        for cle_in, cle_out in mapping_cles.items():
            if cle_in not in resultats:
                continue
                
            rapport_final[cle_out] = {
                "taille": 0,
                "force": force_zero
            }

    def _traiter_ecdh(self, resultats: dict, rapport_final: dict) -> None:
        ecdh = resultats.get("ECDH")
        
        if isinstance(ecdh, dict):
            taille = ecdh.get("taille", 0)
            rapport_final["ecdh"] = {
                "nom": ecdh.get("nom", ""),
                "taille": taille,
                "force": self._evaluer_force(taille),
            }

    def _evaluer_force(self, taille: int) -> str:
        if taille >= 3072:
            return "Fort"
        if taille >= 2048: 
            return "Moyen"
        return "Faible"