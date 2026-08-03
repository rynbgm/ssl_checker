from __future__ import annotations
from typing import Any
from classes.rapports.rapportBase import RapportBase
import requests


ANALYSE_PORTS : dict[str, Any] = {
    "80": {"alerte": False, "msg": "Le port 80 (HTTP) est ouvert. Assurez-vous qu'il redirige systématiquement vers le 443 (HTTPS)."},
    "443": {"alerte": False, "msg": "Le port 443 (HTTPS) est ouvert. Comportement normal pour un serveur web."},
    "8080": {"alerte": False, "msg": "INFO : Le port 8080 héberge souvent des interfaces d'administration ou des proxys web."},
    "8443": {"alerte": False, "msg": "INFO : Le port 8443 est souvent utilisé pour des consoles d'administration web chiffrées."},
    "10000": {"alerte": True, "msg": "ALERTE : Port Webmin (10000) exposé. Vérifiez l'absence de CVE et forcez l'authentification 2FA."},
    "22": {"alerte": False, "msg": "INFO : Le port 22 (SSH) est ouvert. Vérifiez que l'authentification par clé est forcée (désactiver les mots de passe) et fail2ban activé."},
    "3389": {"alerte": True, "msg": "CRITIQUE : Accès bureau à distance RDP (3389) exposé. Cible massive de ransomwares. À placer derrière un VPN !"},
    "5900": {"alerte": True, "msg": "ALERTE : Port VNC (5900) exposé. L'accès à distance doit être filtré par IP ou VPN."},
    "20": {"alerte": True, "msg": "CRITIQUE : Port FTP-Data (20) ouvert. Protocole non chiffré."},
    "21": {"alerte": True, "msg": "CRITIQUE : Port FTP (21) ouvert. Les identifiants transitent en clair. Remplacez par SFTP."},
    "23": {"alerte": True, "msg": "CRITIQUE : Port Telnet (23) ouvert. Protocole obsolète et en clair. À fermer immédiatement !"},
    "69": {"alerte": True, "msg": "CRITIQUE : Port TFTP (69) ouvert. Aucun chiffrement ni authentification."},
    "389": {"alerte": True, "msg": "ALERTE : Port LDAP (389) ouvert en clair. Risque de fuite d'annuaire interne. Privilégiez LDAPS (636)."},
    "139": {"alerte": True, "msg": "CRITIQUE : Port NetBIOS (139) exposé. Vulnérabilité majeure, à fermer en périmètre externe."},
    "445": {"alerte": True, "msg": "CRITIQUE : Port SMB (445) exposé. Vecteur historique du ransomware WannaCry. À bloquer d'urgence !"},
    "2049": {"alerte": True, "msg": "ALERTE : Port NFS (2049) exposé. Risque d'accès non autorisé aux fichiers de configuration."},
    "1433": {"alerte": True, "msg": "ALERTE : Port MSSQL (1433) exposé sur Internet. À placer dans un sous-réseau privé."},
    "3306": {"alerte": True, "msg": "ALERTE : Port MySQL/MariaDB (3306) exposé sur Internet. Risque de vol de base de données."},
    "5432": {"alerte": True, "msg": "ALERTE : Port PostgreSQL (5432) exposé sur Internet. Restreindre l'accès à localhost."},
    "6379": {"alerte": True, "msg": "CRITIQUE : Port Redis (6379) exposé. Souvent sans mot de passe par défaut, compromission totale possible."},
    "9200": {"alerte": True, "msg": "CRITIQUE : Port Elasticsearch (9200) exposé. Risque de vol ou d'effacement de toutes les données (Ransomware)."},
    "11211": {"alerte": True, "msg": "CRITIQUE : Port Memcached (11211) exposé. Utilisable par des hackers pour des attaques DDoS (Amplification)."},
    "27017": {"alerte": True, "msg": "CRITIQUE : Port MongoDB (27017) exposé. Historiquement vulnérable aux vols de données massifs."}
}


class RapportPorts(RapportBase):
    """"""

    def __init__(self,fqdn:str):
        # ca marche comme ca l'heritage en python
        super().__init__()
        self.fqdn = fqdn

    def genererRapport(self, listeDesResultats: Any | None = None):
        if listeDesResultats is None:
            self.rapport = {
                "erreur" : True,
                "status" : "inconnu",
                "commentaires" : ["Impossible de faire le scan"],
                "donnees" : {}
            }
        else:
            
            commentaires : list[str] = []
            portsOuverts : list[str] = []
            alertes = False

            for port,info in listeDesResultats.items():
                etat = info.get('etat','inconnu')
                service = info.get('service','inconnu')

                if etat == "open":
                    portsOuverts.append(port)

                    if port == "80":
                            redirige_bien, detail = self.verifier_redirection_https(self.fqdn)
                            
                            if redirige_bien:
                                commentaires.append("INFO : Le port 80 (HTTP) est ouvert et redirige correctement vers HTTPS.")
                            else:
                                commentaires.append(f"ALERTE : Le port 80 est ouvert mais ne redirige pas correctement : {detail}")
                                alertes = True

                    elif port in ANALYSE_PORTS:
                        regle = ANALYSE_PORTS[port]
                        commentaires.append(regle["msg"])

                        if regle["alerte"]:
                            alertes = True
                            
                    else:
                        commentaires.append(f"INFO : Le port {port} ({service}) est ouvert. Vérifiez s'il est légitime d'exposer ce service public.")
            self.rapport = {
                "titre": "Analyse d'exposition des ports",
                "statut": "Vulnérable" if alertes else "Sécurisé",
                "commentaires": commentaires,
                "donnees": listeDesResultats
            }



    def verifier_redirection_https(self,fqdn: str) -> tuple[bool, str]:

        url_http = f"http://{fqdn}"
        
        # car ca marche pas a cause du user agent de la lib requests 
        faux_navigateur = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        try:
            reponse = requests.get(url_http, headers=faux_navigateur, allow_redirects=False, timeout=5)
            
            if reponse.status_code in [301, 302, 307, 308]:
                destination = reponse.headers.get('Location', '')
                if destination.startswith('https://'):
                    return True, "Redirection valide vers HTTPS."
                else:
                    return False, f"Il redirige vers cette destination: {destination}"
            else:
                debut_page = reponse.text[:50].replace('\n', ' ').strip()
                return False, f"Le serveur a répondu HTTP {reponse.status_code}. Debut du contenu: '{debut_page}...'"
                
        except requests.exceptions.RequestException as _:
            return False, "Erreur de connexion au port 80 (Timeout ou connexion coupée par le serveur)."