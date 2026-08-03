from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class TestBase(ABC):
    """"""

    def __init__(self,fqdn:str,port:str):
        self.resultat : Any = {}
        self.nom = type(self).__name__
        self.port = port
        self.fqdn = fqdn 

    @abstractmethod
    def lancer(self,*args:Any, **kwargs:Any) -> None:
        pass

    def getResultat(self) -> Any:
        return self.resultat

    def getNom(self) -> str:
        return self.nom