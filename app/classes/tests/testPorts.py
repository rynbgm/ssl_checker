from __future__ import annotations
from classes.tests.testBase import TestBase
from typing import Any
import nmap


class TestPorts(TestBase):
    def __init__(self,fqdn:str, port:str, scan_type : str):
        super().__init__(fqdn,port)
        self.scan_type = scan_type


    def lancer(self,*args:Any, **kwargs:Any) -> None:
        
        nm = nmap.PortScanner()
        try :
            if self.scan_type == 'rapide':
                nm.scan(self.fqdn, arguments='-F -Pn --host-timeout 2m')
            else:
                # scan full
                nm.scan(self.fqdn, arguments='-p- -sV -Pn --host-timeout 5m')
        except nmap.PortScannerError as _:
            self.resultat = None
        
        res : dict[str, Any] | None= {}

        if nm.all_hosts():
            host = nm.all_hosts()[0]
            if 'tcp' in nm[host].all_protocols():
                for port in nm[host]['tcp'].keys():
                    etat = nm[host]['tcp'][port]['state']
                    service = nm[host]['tcp'][port]['name']

                    produit = nm[host]['tcp'][port].get('product','')
                    version = nm[host]['tcp'][port].get('version','')
                    details = f"{produit} {version}".strip()

                    res[str(port)] = {"etat":etat, "service" : service, "details": details if details else "Inconnu"}
            
        if not res:
            self.resultat = None
        else:
            self.resultat = res
