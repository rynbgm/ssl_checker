from __future__ import annotations

from typing import Any, Dict
from classes.notes.noteBase import NoteBase


class NoteCertificat(NoteBase):
    """Classe pour calculer la note du certificat"""

    def __init__(self):
        super().__init__()
        self.details = {}
    
    def calculerNote(self,listeDesResultats: Any| None = None):
        """
        Calcule la note du certificat (0-100)

        Critères de notation:
        - Validité temporelle: 25 points
        - Chaîne de certification: 25 points
        - Force de la clé publique: 20 points
        - Algorithme de signature: 10 points
        - Extensions de sécurité: 10 points
        - Statut de révocation: 10 points

        Args:
            listeDesResultats: Résultats du TestCertificat

        Returns:
            int: Note sur 100
        """
        
        resultats_test = listeDesResultats if listeDesResultats is not None else {}

        if resultats_test.get('erreur'):
            self.note = 0
            self.details = {'erreur': resultats_test.get('message')}
            return 0

        note_totale = 0
        details = {}

        # 1. Validité temporelle (25 points)
        note_validite, detail_validite = self._noter_validite(resultats_test.get('validite', {}))
        note_totale += note_validite
        details['validite'] = detail_validite

        # 2. Chaîne de certification (25 points)
        note_chaine, detail_chaine = self._noter_chaine(resultats_test.get('chaine_certification', {}))
        note_totale += note_chaine
        details['chaine'] = detail_chaine

        # 3. Force de la clé publique (20 points)
        note_cle, detail_cle = self._noter_cle_publique(resultats_test.get('cle_publique', {}))
        note_totale += note_cle
        details['cle_publique'] = detail_cle

        # 4. Algorithme de signature (10 points)
        note_signature, detail_signature = self._noter_signature(resultats_test.get('signature', {}))
        note_totale += note_signature
        details['signature'] = detail_signature

        # 5. Extensions de sécurité (10 points)
        note_extensions, detail_extensions = self._noter_extensions(resultats_test.get('extensions', {}))
        note_totale += note_extensions
        details['extensions'] = detail_extensions

        # 6. Statut de révocation (10 points)
        note_revocation, detail_revocation = self._noter_revocation(resultats_test.get('revocation', {}))
        note_totale += note_revocation
        details['revocation'] = detail_revocation

        # Vérifications d'autorité
        note_autorite, detail_autorite = self._noter_autorite(resultats_test.get('autorite', {}))
        if note_autorite < 0:  
            note_totale += note_autorite
            details['autorite'] = detail_autorite

        self.note = max(0, min(100, int(note_totale)))
        self.details = details


    def _noter_validite(self, validite: Dict[str, Any]) -> tuple:
        """
        Note la validité temporelle du certificat

        Args:
            validite: Données de validité

        Returns:
            tuple: (note, détails)
        """
        if not validite:
            return (0, {'score': 0, 'raison': 'Pas de données de validité'})

        note = 25 
        details = {'score': 25}

        # Vérification que le certificat est valide
        if not validite.get('valide', False):
            if validite.get('expire', False):
                note = 0
                details = {'score': 0, 'raison': 'Certificat expiré'}
            elif validite.get('pas_encore_valide', False):
                note = 0
                details = {'score': 0, 'raison': 'Certificat pas encore valide'}
        else:
            # Pénalité si expire bientôt (< 30 jours)
            if validite.get('expire_bientot', False):
                jours = validite.get('jours_restants', 0)
                note = 15
                details = {'score': 15, 'raison': f'Expire dans {jours} jours'}
            else:
                jours = validite.get('jours_restants', 0)
                details = {'score': 25, 'jours_restants': jours}

        return (note, details)

    def _noter_chaine(self, chaine: Dict[str, Any]) -> tuple:
        """
        Note la chaîne de certification

        Args:
            chaine: Données de la chaîne

        Returns:
            tuple: (note, détails)
        """
        if not chaine or chaine.get('erreur'):
            return (0, {'score': 0, 'raison': 'Chaîne non vérifiable'})

        note = 25
        details = {'score': 25}
        raisons = [] 
        if not chaine.get('complete', False):
            note -= 10
            raisons.append('Chaîne incomplète (racine non atteinte)')

        if chaine.get('reconstruite_via_aia', False):
            note -= 10 
            raisons.append('Intermédiaires manquants (reconstruite via AIA)')

        longueur = chaine.get('longueur', 0)
        details['longueur_chaine'] = longueur

        
        if longueur > 5:
            note -= 5
            raisons.append('Chaîne très longue (> 5 certificats)')

       
        note = max(0, note)
        details['score'] = note
        
        if raisons:
            details['raison'] = " | ".join(raisons)
        else:
            details['raison'] = "Chaîne correcte et complète"

        return (note, details)

  
    def _noter_cle_publique(self, cle: Dict[str, Any]) -> tuple:
        key_type = str(cle.get('type', '')).upper() 
        taille = cle.get('taille', 0)

        
        ec_names = {'EC', 'ECDSA', 'ELLIPTICCURVE', 'ED25519', 'ED448', 'X25519', 'X448'}

        if 'RSA' in key_type:
            note = 20 if taille >= 2048 else 0
        elif any(name in key_type for name in ec_names):
            note = 20 if taille >= 256 else 10
        else:
            note = 15 if cle.get('securise') else 5

        return (note, {'score': note, 'type': key_type, 'taille': taille})

    def _noter_signature(self, signature: Dict[str, Any]) -> tuple:
        """
        Note l'algorithme de signature

        Args:
            signature: Données de signature

        Returns:
            tuple: (note, détails)
        """
        if not signature:
            return (0, {'score': 0, 'raison': 'Pas de données de signature'})

        securise = signature.get('securise', False)
        hash_algo = signature.get('hash', 'unknown')

        if not securise:
            return (0, {'score': 0, 'raison': f'Algorithme de hash faible: {hash_algo}'})

        # Notation selon l'algorithme de hash
        if hash_algo.lower() in ['sha256', 'sha384', 'sha512']:
            note = 10
        else:
            note = 0
        

        details = {
            'score': note,
            'algorithme': signature.get('algorithme'),
            'hash': hash_algo
        }

        return (note, details)

    def _noter_extensions(self, extensions: Dict[str, Any]) -> tuple:
        """
        Note les extensions de sécurité

        Args:
            extensions: Données des extensions

        Returns:
            tuple: (note, détails)
        """
        if not extensions:
            return (5, {'score': 5, 'raison': 'Extensions basiques'})

        note = 10
        details = {'score': 10}
        points = []

        # Vérification SAN (Subject Alternative Name)
        san = extensions.get('san', [])
        if len(san) > 0:
            points.append('SAN présent')
        else:
            note -= 2

        # Key Usage
        key_usage = extensions.get('key_usage', [])
        if len(key_usage) > 0:
            points.append('Key Usage défini')
        else:
            note -= 2

        # Extended Key Usage
        ext_key_usage = extensions.get('extended_key_usage', [])
        if len(ext_key_usage) > 0:
            points.append('Extended Key Usage défini')

        # OCSP 
        aia = extensions.get('authority_info_access', {})

        points_aia = []
        if 'ocsp' in aia:
            points.append('OCSP présent dans AIA')
        else:
            note -= 5
            points_aia.append("Lien OCSP manquant")

        if 'ca_issuers' in aia:
            points.append('Lien caIssuers présent dans AIA')
        else:
            note -= 2
            points_aia.append("Lien caIssuers manquant")
            
        if points_aia:
            details['raison_aia'] = " | ".join(points_aia)

        
        crl = extensions.get('crl_distribution_points', [])
        if len(crl) > 0:
            points.append('CRL disponible')

        details['points'] = points
        details['score'] = max(0, note)

        return (max(0, note), details)

    def _noter_revocation(self, revocation: Dict[str, Any]) -> tuple:
        """
        Note le statut de révocation

        Args:
            revocation: Données de révocation

        Returns:
            tuple: (note, détails)
        """
        if not revocation:
            return (0, {'score': 0, 'raison': 'Pas de mécanisme de révocation'})

        note = 10
        details = {'score': 10}

        ocsp = revocation.get('ocsp', {})
        crl = revocation.get('crl', {})

        if not ocsp.get('disponible') and not crl.get('disponible'):
            note = 0
            details = {'score': 0, 'raison': 'Aucun mécanisme de révocation'}
        elif ocsp.get('disponible') and crl.get('disponible'):
            details['raison'] = 'OCSP et CRL disponibles'
        elif ocsp.get('disponible'):
            note = 8
            details['raison'] = 'OCSP disponible'
        elif crl.get('disponible'):
            note = 5
            details['raison'] = 'CRL disponible'

        return (note, details)

    def _noter_autorite(self, autorite: Dict[str, Any]) -> tuple:
        """
        Vérifie l'autorité de certification (pénalités si problème)

        Args:
            autorite: Données d'autorité

        Returns:
            tuple: (note (peut être négative), détails)
        """
        if not autorite:
            return (0, {})

        # Pénalité pour certificat auto-signé
        if autorite.get('auto_signe', False):
            return (-50, {'score': -50, 'raison': 'Certificat auto-signé'})

        # Vérification que le CN correspond
        if not autorite.get('cn_correspond', False):
            return (-30, {'score': -30, 'raison': 'CN ne correspond pas au FQDN'})

        return (0, {'score': 0, 'raison': 'OK'})

    #peut être utile pour recuperer les details
    def get_details(self) -> Dict[str, Any]:
        """
        Retourne les détails de notation

        Returns:
            dict: Détails
        """
        return self.details