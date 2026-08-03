from __future__ import annotations
# le but de cette classe est de factoriser et imposer les fonctions utiles au classes qui vont herite d'elle
# en gros c'est une class abstraite quoi    
# monsieur andary toi etre fier de nous la 


from abc import ABC, abstractmethod
from typing import Any


class NoteBase(ABC):
    """Class qui sert a factoriser le code source des sous classes de la notation et imposer deux fonctions"""

    def __init__(self) :
        self.note = 0.0
        # on a besoin du nom pour faire les champ de la reponse
        self.nom = type(self).__name__
    

    @abstractmethod
    def calculerNote(self, listeDesResultats: Any | None = None):
        pass

    def getNote(self) -> float:
        return self.note
    
    def getNom(self) -> str:
        return self.nom

