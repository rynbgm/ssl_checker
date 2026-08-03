from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod


class RapportBase(ABC):
    """Classe abstraite pour définir la structure des rapports
    elle va servir a rajouter les parties de chaque sous classes dans le rapport, elle fait ca en les appelant un par un 
    et en leur demandant des sous rapports qu'il va mettre dans un seul res"""

    def __init__(self):
        self.rapport : Any = {}
        self.nom = type(self).__name__
        

    @abstractmethod
    def genererRapport(self, listeDesResultats: Any | None = None):
        # a perso pour chaque class
        pass


    def getRapport(self) -> dict[str, Any]:
        return {self.nom:self.rapport}


    def getNom(self) -> str:
        return self.nom