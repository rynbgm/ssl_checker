from __future__ import annotations


from typing import Any

from classes.notes.noteGlobale import NoteGlobale
from classes.tests.testGlobal import TestGlobal
from classes.rapports.rapportGlobal import RapportGlobal



class Factory():

    def __init__(self,fqdn:str,port:str,scan_type : str):
        self.noteGlobale = NoteGlobale()
        self.testGlobal = TestGlobal(fqdn,port,scan_type)
        self.rapportGlobal = RapportGlobal(fqdn)


    def getInstances(self) -> list[Any]:
        return [ self.testGlobal,self.noteGlobale, self.rapportGlobal]