from __future__ import annotations
import json
import os
from typing import Any, List, Dict, Set, Optional
from collections import defaultdict
from classes.tests.testBase import TestBase


# Mapping protocole hex → nom
PROTOCOLE_HEX_VERS_NOM = {
    768:  "SSL 3.0",
    769:  "TLS 1.0",
    770:  "TLS 1.1",
    771:  "TLS 1.2",
    772:  "TLS 1.3",
}


# Mapping des cipher IDs vers leurs noms courts personnalisés
CIPHER_SHORT_NAMES = {
    # TLS 1.3
    4865: "TLS13-AES128",
    4866: "TLS13-AES256",
    4867: "TLS13-CHACHA20",
    
    # CHACHA20
    52393: "CHACHA20",
    52392: "CHACHA20",
    52244: "CHACHA20",
    52243: "CHACHA20",
    52245: "CHACHA20",
    52394: "CHACHA20",
    
    # AES-GCM
    49199: "AES128-GCM",
    49195: "AES128-GCM",
    49196: "AES256-GCM",
    49200: "AES256-GCM",
    159: "DHE-AES256-GCM",
    158: "DHE-AES128-GCM",
    157: "RSA-AES256-GCM",
    156: "RSA-AES128-GCM",
    
    # CBC
    49162: "AES256-CBC",
    49172: "AES256-CBC",
    49161: "AES128-CBC",
    49171: "AES128-CBC",
    49159: "RC4",
    49169: "RC4",
    47: "AES128-CBC",
    53: "AES256-CBC",
    51: "DHE-AES128-CBC",
    50: "DHE-AES128-CBC",
    57: "DHE-AES256-CBC",
    56: "DHE-AES256-CBC",
    
    # RC4
    5: "RC4",
    4: "RC4",
    
    # 3DES
    10: "3DES",
    
    # SCSV
    255: "SCSV",
    
    # GREASE (ignorés)
    19018: None,
    64250: None,
    47802: None,
    43690: None,
    51914: None,
    39578: None,
    14906: None,
    31354: None,
    2570: None,
    6682: None,
    27242: None,
    56026: None,
}


class TestCompatibiliteOs(TestBase):
    """
    Vérifie la compatibilité des clients SSL/TLS (OS, navigateurs)
    avec le serveur testé.
    """

    def __init__(self, fqdn: str, port: str):
        super().__init__(fqdn, port)
        self._clients = self._charger_clients()

    def _charger_clients(self) -> List[Dict[str, Any]]:
        """Charge la liste des clients SSL depuis clients.json"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(base_dir, "../clients.json")
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _protocoles_serveur(self, protocoles: List[Dict[str, Any]]) -> set:
        """Retourne l'ensemble des protocoles supportés par le serveur"""
        return {p["nom"] for p in protocoles if p.get("supporte")}

    def _ciphers_serveur(self, ciphers: Dict[str, Any]) -> set:
        """Retourne l'ensemble des cipher IDs supportés par le serveur"""
        ids = set()
        for suites in ciphers.values():
            for suite in suites[1]:
                if isinstance(suite, (list, tuple)) and len(suite) >= 1:
                    ids.add(suite[0])
        return ids

    def _est_compatible(
        self,
        client: Dict[str, Any],
        protocoles_serveur: set,
        ciphers_serveur: set,
    ) -> bool:
        """Vérifie si un client est compatible avec le serveur"""
        lowest = client.get("lowestProtocol", 0)
        highest = client.get("highestProtocol", 0)

        protocoles_client = {
            nom
            for hex_val, nom in PROTOCOLE_HEX_VERS_NOM.items()
            if lowest <= hex_val <= highest
        }

        if not protocoles_client & protocoles_serveur:
            return False

        suites_client = set(client.get("suiteIds", []))
        if not suites_client & ciphers_serveur:
            return False

        return True

    def _get_cipher_short_name(self, cipher_id: int) -> Optional[str]:
        """Retourne le nom court du cipher pour l'affichage, ou None pour ignoré"""
        return CIPHER_SHORT_NAMES.get(cipher_id)

    def _get_cipher_signature(self, suiteIds: List[int]) -> Set[str]:
        """Retourne l'ensemble des noms courts des ciphers supportés par le client"""
        signature = set()
        for cipher_id in suiteIds:
            short_name = self._get_cipher_short_name(cipher_id)
            if short_name:
                signature.add(short_name)
        return signature

    def _get_signature_key(self, signature: Set[str]) -> str:
        """Retourne une clé unique pour une signature (triée pour cohérence)"""
        return ",".join(sorted(signature))

    def _get_base_name(self, client: Dict[str, Any]) -> str:
        """Retourne le nom de base du client (sans distinction)"""
        name = client.get('name', '')
        version = client.get('version', '')
        platform = client.get('platform', '')
        if version:
            name += f" {version}"
        if platform:
            name += f" / {platform}"
        return name.strip()

    def _get_cipher_priority(self, cipher_name: str) -> int:
        """Retourne un score de priorité pour un cipher (plus haut = plus significatif)"""
        if cipher_name.startswith("TLS13"):
            return 100
        if "CHACHA20" in cipher_name:
            return 90
        if "GCM" in cipher_name:
            return 80
        if "SCSV" in cipher_name:
            return 70
        if "CBC" in cipher_name:
            return 30
        if cipher_name == "RC4":
            return 10
        if cipher_name == "3DES":
            return 5
        return 0

    def _find_distinctive_info(
        self,
        group_clients: List[Dict[str, Any]],
        signatures: Dict[int, Set[str]]
    ) -> Dict[int, Optional[str]]:
        """
        Trouve pour chaque variante d'un groupe une information distinctive.
        Retourne {client_id: info} où info est soit un cipher court, soit le nombre de ciphers.
        """
        if len(group_clients) <= 1:
            return {}
        
        # Vérifier d'abord si toutes les signatures sont identiques
        sig_keys = [self._get_signature_key(signatures[client['id']]) for client in group_clients]
        
        if len(set(sig_keys)) == 1:
            # Toutes identiques : fusion (pas de distinction)
            return {}
        
        # Signatures différentes : trouver les distinctions
        distinctive = {}
        
        for client in group_clients:
            client_id = client['id']
            my_sig = signatures.get(client_id, set())
            
            # Ciphers des autres variantes
            other_sig = set()
            for other in group_clients:
                if other['id'] != client_id:
                    other_sig.update(signatures.get(other['id'], set()))
            
            # Ciphers uniques à cette variante
            unique = my_sig - other_sig
            
            if unique:
                # Prendre le cipher le plus significatif
                best_cipher = max(unique, key=self._get_cipher_priority)
                distinctive[client_id] = best_cipher
            else:
                # Pas de cipher unique : utiliser le nombre de ciphers
                nb_ciphers = len(client.get("suiteIds", []))
                distinctive[client_id] = f"{nb_ciphers} ciphers"
        
        return distinctive

    def lancer(self, protocoles: List[Dict[str, Any]], ciphers: Dict[str, Any]) -> None:
        """Teste la compatibilité de chaque client avec le serveur"""
        protocoles_serveur = self._protocoles_serveur(protocoles)
        ciphers_serveur = self._ciphers_serveur(ciphers)

        # Calculer les signatures pour tous les clients
        signatures: Dict[int, Set[str]] = {}
        for client in self._clients:
            signatures[client['id']] = self._get_cipher_signature(client.get("suiteIds", []))

        # Grouper les clients par (name, version, platform)
        # Exemple: "Android|7.0|" ou "Chrome|49|Win 7"
        groupes_par_nom: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for client in self._clients:
            name = client.get('name', '')
            version = client.get('version', '')
            platform = client.get('platform', '')
            key = f"{name}|{version}|{platform}"
            groupes_par_nom[key].append(client)

        # Calculer les informations distinctives pour chaque groupe nominal
        distinctive_par_client: Dict[int, Optional[str]] = {}
        for group_clients in groupes_par_nom.values():
            group_distinctive = self._find_distinctive_info(group_clients, signatures)
            distinctive_par_client.update(group_distinctive)

        # Construire le résultat : fusion au sein du même (name, version, platform) uniquement
        resultat: List[Dict[str, Any]] = []

        for key, group_clients in groupes_par_nom.items():
            # Au sein de ce groupe, regrouper par signature identique
            sous_groupes: Dict[str, Dict[str, Any]] = {}
            
            for client in group_clients:
                client_id = client['id']
                sig = signatures[client_id]
                sig_key = self._get_signature_key(sig)
                nom_base = self._get_base_name(client)
                distinctive = distinctive_par_client.get(client_id)
                
                if distinctive:
                    nom_final = f"{nom_base} (+{distinctive})"
                else:
                    nom_final = nom_base
                
                # Fusion des clients avec la même signature au sein du même groupe
                if sig_key not in sous_groupes:
                    sous_groupes[sig_key] = {
                        "nom": nom_final,
                        "compatible": self._est_compatible(client, protocoles_serveur, ciphers_serveur)
                    }
            
            resultat.extend(sous_groupes.values())

        self.resultat = resultat