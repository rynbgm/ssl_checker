from __future__ import annotations
from typing import Any,Generator
from classes.tests.testProtocole import TestProtocole
from classes.tests.testCertificat import TestCertificat
from classes.tests.testCipher import TestCipher
from classes.tests.testEchangeCle import TestEchangeCle
from classes.tests.testVulnerabilites import TestVulnerabilites
from classes.tests.testPorts import TestPorts
from classes.tests.testCompatibiliteOs import TestCompatibiliteOs


class TestGlobal:
    def __init__(self,fqdn:str,port:str,scan_type:str):

        self.port = port
        self.fqdn = fqdn
        self.scan_type = scan_type

        self.protocole = TestProtocole(fqdn,port)
        self.certificat = TestCertificat(fqdn,port)
        self.cipher = TestCipher(fqdn,port)
        self.cle = TestEchangeCle(fqdn,port)
        self.vulns = TestVulnerabilites(fqdn,port)
        self.ports = TestPorts(fqdn,port,scan_type)
        self.compatibiliteOs = TestCompatibiliteOs(fqdn, port)

        self.tests : list[tuple[str, Any]] = [
            ('protocole', self.protocole),
            ('certificat', self.certificat),
            ('cipher', self.cipher),
            ('cle', self.cle),
            ('vulnerabilites', self.vulns),
            ('ports', self.ports),
            ('compatibiliteOs', self.compatibiliteOs)
        ]

    def lancer(self) -> Generator[str, None, None]:
        yield "Démarrage des tests..."

        yield "Analyse du certificat en cours..."
        self.certificat.lancer()

        protocoles = []
        ciphers = {}

        cert_result = self.certificat.getResultat()
        cert_valide = cert_result.get('verdict', {}).get('valide', False)

        if cert_valide:

            yield "Analyse du protocole en cours..."
            self.protocole.lancer()
            protocoles = self.protocole.getResultat()

            yield "Analyse des ciphers en cours..."
            self.cipher.lancer(protocoles)
            ciphers = self.cipher.getResultat()

            yield "Analyse de l'échange de clés en cours..."
            self.cle.lancer(self.certificat.getResultat(),self.cipher.getResultat())

            yield "Analyse des ports en cours..."
            self.ports.lancer()

            yield "Analyse de la compatibilité OS en cours..."
            self.compatibiliteOs.lancer(
                self.protocole.getResultat(),
                self.cipher.getResultat()
            )

            yield "Recherche de vulnérabilités en cours..."
            self.vulns.lancer(protocoles, ciphers)

    def getResulat(self) -> dict[str, Any] | None:
        resultats : dict[str, Any]= {} 
    
        for cle, instance in self.tests:
            resultats[cle] = instance.getResultat()
            
        return resultats