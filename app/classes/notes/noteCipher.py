from __future__ import annotations
from typing import Any
from classes.notes.noteBase import NoteBase


class NoteCipher(NoteBase):
    """Classe pour calculer la note des suites de chiffrement"""

    def __init__(self):
        super().__init__()

    def get_size(self, cipher: str) -> int:
        """Détermine la taille de la clé à partir du nom de la suite."""
        if '40_' in cipher: return 40
        if any(x in cipher for x in ['128_', 'SEED', 'IDEA', 'SM4']): return 128
        if any(x in cipher for x in ['256_', 'CHACHA']): return 256
        if '3DES' in cipher: return 112
        if 'DES' in cipher: return 56
        return 0

    def _note_base_cipher(self, cipher_name: str) -> int:
        """Calcule la note de base selon le type de cipher."""
        if any(bad in cipher_name for bad in ['NULL', 'ANON', 'EXPORT', 'MD5', 'DES']):
            return 0
        if 'RC4' in cipher_name:
            return 20
        if '3DES' in cipher_name:
            return 40
        if 'CBC' in cipher_name:
            return 60
        return 100

    def _adjust_note_by_keysize(self, note: int, size: int) -> int:
        """Ajuste la note selon la taille de clé."""
        if size > 0 and size < 128:
            return min(note, 40)
        if size >= 256:
            return min(note + 10, 100)
        return note

    def _get_cipher_name(self, item: Any) -> str:
        """Extrait le nom du cipher depuis un tuple ou une chaîne."""
        if isinstance(item, tuple):
            return str(item[1]).upper()
        return str(item).upper()

    def _noter_cipher(self, item: Any) -> int:
        """Retourne la note pour un cipher donné."""
        name = self._get_cipher_name(item)
        note = self._note_base_cipher(name)
        size = self.get_size(name)
        return self._adjust_note_by_keysize(note, size)

    def calculerNote(self, liste_des_resultats: Any | None = None):  
        if not liste_des_resultats:
            self.note = 0
            return

        toutes_les_notes = [
            self._noter_cipher(item)
            for ciphers in liste_des_resultats.values()  
            for item in ciphers[1]
        ]

        self.note = sum(toutes_les_notes) / len(toutes_les_notes) if toutes_les_notes else 0