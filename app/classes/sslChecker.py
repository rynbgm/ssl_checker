from __future__ import annotations
from typing import Any,Generator
from classes.factory import Factory
import traceback


class SslChecker:
    def __init__(self, fqdn: str, port: str,scan_type : str):
        self.fqdn = fqdn 
        self.port = port
        self.scan_type = scan_type
        self.resulat = None
        
        self.factory = Factory(fqdn,port,scan_type)

        self.testGlobal, self.noteGlobale, self.rapportGlobal = None, None, None

    def lancer(self) -> Generator[str | dict[str, Any], None, None]:

        try:
            self.testGlobal, self.noteGlobale, self.rapportGlobal = self.factory.getInstances()
            
            yield "Initialisation des tests..."
            yield from self.testGlobal.lancer()
            listeDesResultats = self.testGlobal.getResulat()
            
            yield "Calcul des notes..."
            self.noteGlobale.calculerNote(listeDesResultats)
            note = self.noteGlobale.getNotes()

            yield "Génération du rapport..."
            self.rapportGlobal.genererRapport(listeDesResultats)
            rapport_data = self.rapportGlobal.getRapport()

            bloc : dict[str, Any] = {
                "fqdn": self.fqdn,
                "port": self.port,
                "note": note,
                "rapport": rapport_data 
            }

            res : dict[str, Any]=  {
                "success": True,
                "finished": True,
                "data": bloc
            } 
            self.resulat = res
            yield res

        except Exception as _:
            print(f"[ERREUR INTERNE] SslChecker a planté sur {self.fqdn}:{self.port}")
            print(traceback.format_exc())
            res_erreur : dict[str, Any] = {
                "success": False,
                "finished": True,
                "message": "Une erreur inattendue est survenue lors de l'analyse du serveur."
            }
            yield res_erreur
    
    def getResulat(self) -> dict[str, Any] | None:
        return self.resulat