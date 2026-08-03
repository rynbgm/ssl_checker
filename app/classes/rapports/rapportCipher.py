import os
import pandas as pd
from typing import Any
from classes.rapports.rapportBase import RapportBase


class RapportCipher(RapportBase):
    def __init__(self):
        super().__init__()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.csv_path = os.path.join(base_dir, '../tls-parameters-4.csv')
        try:
            self.df_ciphers = pd.read_csv(self.csv_path)
            self.df_ciphers["Description"] = self.df_ciphers["Description"].str.strip()
            self.df_indexed = self.df_ciphers.set_index("Description")
        except Exception as e:
            print(f"[!] Erreur de lecture du CSV dans {self.csv_path}: {e}")
            self.df_ciphers = None
            self.df_indexed = None

    def get_size(self, cipher: str) -> int:
        """Détermine la taille de la clé à partir du nom de la suite."""
        c = cipher.upper()
        if '40_' in c: return 40
        if any(x in c for x in ['128_', 'SEED', 'IDEA', 'SM4']): return 128
        if any(x in c for x in ['256_', 'CHACHA']): return 256
        if '3DES' in c: return 112
        if 'DES' in c: return 56
        return 0

    def getevaluation(self, cipher_name: str) -> str:
        """Évalue la sécurité d'une suite en consultant le DataFrame."""
        if self.df_indexed is None:
            return "Unknown"
        try:
            if cipher_name in self.df_indexed.index:
                tag = str(self.df_indexed.loc[cipher_name, "Recommended"])
                if 'Y' in tag:
                    return 'Secure'
                elif 'N' in tag:
                    return 'Weak'
        except Exception:
            pass
        return 'Unsecure'

    def _get_order_label(self, order: bool) -> str:
        """Retourne le label d'ordre de préférence du serveur."""
        if order:
            return "Selon l'ordre du serveur"
        return "Pas d'ordre de préférence"

    def genererRapport(self, liste_resultats: dict):
        """Génère le dictionnaire final pour l'affichage."""
        self.rapport = {}
        for protocole, suites in liste_resultats.items():
            details_suites = []
            for s in suites[1]:
                details_suites.append({
                    "nom": s[1],
                    "force": self.getevaluation(s[1]),
                    "taille": self.get_size(s[1])
                })
            # Clé = "TLS 1.2 #Selon l'ordre du serveur"
            #        ou "TLS 1.2 #Pas d'ordre de préférence"
            order_label = self._get_order_label(suites[0])
            self.rapport[f'{protocole} #{order_label}'] = details_suites