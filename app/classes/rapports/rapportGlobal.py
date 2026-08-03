from __future__ import annotations
from typing import Any
from classes.rapports.rapportCertificat import RapportCertificat
from classes.rapports.rapportCipher import RapportCipher
from classes.rapports.rapportCompatibiliteOs import RapportCompatibiliteOs
from classes.rapports.rapportEchangeCle import RapportEchangeCle
from classes.rapports.rapportPorts import RapportPorts
from classes.rapports.rapportProtocole import RapportProtocole
from classes.rapports.rapportVulnerabilites import RapportVulnerabilites

class RapportGlobal():
    def __init__(self,fqdn:str):
        self.fqdn : str = fqdn
        self.certificat = RapportCertificat()
        self.cipher = RapportCipher()
        self.compatibiliteOs = RapportCompatibiliteOs()
        self.cle = RapportEchangeCle()
        self.ports = RapportPorts(self.fqdn)
        self.protocole = RapportProtocole()
        self.vulns = RapportVulnerabilites()
        self.rapport : dict[str, Any] = {}

    def genererRapport(self, listDesResultats: dict[str, Any]):

        if listDesResultats.get('certificat', {}).get('verdict', {}).get('valide', False):
            self.protocole.genererRapport(listDesResultats.get('protocole', []))
            self.cle.genererRapport(listDesResultats.get('cle', {}))
            self.cipher.genererRapport(listDesResultats.get('cipher', {}))
            self.compatibiliteOs.genererRapport(listDesResultats.get('compatibiliteOs', {}))
            self.ports.genererRapport(listDesResultats.get('ports', {}))

            self.rapport['protocole'] = self.protocole.rapport
            self.rapport['echangeCle'] = self.cle.rapport
            self.rapport['ciphers'] = self.cipher.rapport
            self.rapport['compatibiliteOs'] = self.compatibiliteOs.rapport
            self.rapport['ports'] = self.ports.rapport

            self.vulns.genererRapport(listDesResultats.get('vulnerabilites', {}))
            self.rapport['vuln'] = self.vulns.rapport

        self.certificat.genererRapport(listDesResultats.get('certificat', {}))
        self.rapport['certificat'] = self.certificat.rapport
            


    def getRapport(self) -> dict[str, Any]:
        return self.rapport