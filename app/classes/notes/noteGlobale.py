from __future__ import annotations
from typing import Any
from classes.notes.noteProtocole import NoteProtocole
from classes.notes.noteEchangeCle import NoteEchangeCle
from classes.notes.noteCipher import NoteCipher
from classes.notes.noteCertificat import NoteCertificat

class NoteGlobale():
    ''''cettre classe va servir a calculer la note globale du scan
    conctraitement elle prend en entree une liste issue des resultat des tests (TestGlobal)
    puis se focus sur 3 axes : protocole, cle, chiper , la note est calculer comme suit
    note globale = 0.3 * noteProtocle + 0.3 * noteCle + 0.4 * noteChiper'''

    def __init__(self):
        # on cree tt les classes pro dans leur domaine et c'est tt...
        self.protocole = NoteProtocole()
        self.cle = NoteEchangeCle()
        self.cipher = NoteCipher()
        self.certificat = NoteCertificat()
        self.note_globale : float = 0.0
        self.evaluation :str = ""
        self.listDesObjets : list[Any] = [self.protocole,self.cle,self.cipher,self.certificat]



    def calculerNote(self,liste_des_resultats:dict[str, Any]):

        if liste_des_resultats.get('certificat', {}).get('verdict', {}).get('valide', False):
            self.certificat.calculerNote(liste_des_resultats['certificat'])
            self.protocole.calculerNote(liste_des_resultats['protocole'])
            self.cle.calculerNote(liste_des_resultats['cle'])
            self.cipher.calculerNote(liste_des_resultats['cipher'])
            self.note_globale= 0.3 * self.protocole.getNote() + 0.3 * self.cle.getNote() + 0.4 * self.cipher.getNote()
            if self.note_globale < 50.0:
                self.evaluation = 'F'
            elif self.note_globale < 75:
                self.evaluation = 'B'
            else :
                self.evaluation = 'A'
        else:
            self.evaluation = 'T'
            self.note_globale = 0.0


    def getNotes(self) -> dict[str,float | str]:
        resulat : dict[str,float | str] = {}
        for i in range (len(self.listDesObjets)):
            resulat[self.listDesObjets[i].getNom()] = self.listDesObjets[i].getNote()
        resulat['noteGlobale'] = self.note_globale
        resulat['evaluation'] = self.evaluation
        
        return resulat
        
