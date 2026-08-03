from __future__ import annotations
from typing import Dict, Any, List
from classes.rapports.rapportBase import RapportBase


class RapportCertificat(RapportBase):
    """"""

    def __init__(self):
        super().__init__()

    def genererRapport(self, resultats: Any):
        if not resultats or resultats.get('erreur'):
            return {
                'erreur': True,
                'message': resultats.get('message') if resultats else 'Données manquantes'
            }

        validite      = resultats.get('validite') or {}
        autorite      = resultats.get('autorite') or {}
        cle_pub       = resultats.get('cle_publique') or {}
        signature     = resultats.get('signature') or {}
        extensions_data = resultats.get('extensions') or {}
        chaine_cert   = resultats.get('chaine_certification') or {}
        revocation    = resultats.get('revocation') or {}
        verdict       = resultats.get('verdict') or {}


        self.rapport = {
            'erreur': False,

            # ── Verdict global ─────────────────────────────────────────────
            'verdict': verdict,

            # ── Validité temporelle ────────────────────────────────────────
            'validite': {
                'debut': validite.get('debut'),
                'fin': validite.get('fin'),
                'jours_restants': validite.get('jours_restants', 0),
                'valide': validite.get('valide', False),
                'expire': validite.get('expire', False),
                'expire_bientot': validite.get('expire_bientot', False),
                'pas_encore_valide': validite.get('pas_encore_valide', False)
            },

            # ── Identité ───────────────────────────────────────────────────
            'sujet': autorite.get('subject', {}),
            'emetteur': autorite.get('issuer', {}),
            'auto_signe': autorite.get('auto_signe', False),
            'cn_correspond': autorite.get('cn_correspond', False),

            # ── Clé publique ───────────────────────────────────────────────
            'cle_publique': {
                'type': cle_pub.get('type', 'Inconnu'),
                'taille': cle_pub.get('taille', 0),
                'courbe': cle_pub.get('courbe'),
                'details': cle_pub.get('details', ''),
                'securise': cle_pub.get('securise', False),
                'force': self._evaluer_force_cle(
                    cle_pub.get('type'), cle_pub.get('taille', 0)
                )
            },

            # ── Signature ──────────────────────────────────────────────────
            'signature': {
                'algorithme': signature.get('algorithme', 'Inconnu'),
                'hash': signature.get('hash', 'Inconnu'),
                'securise': signature.get('securise', False),
                'details': signature.get('details', '')
            },

            # ── Extensions ─────────────────────────────────────────────────
            'extensions': {
                'san': extensions_data.get('san', []),
                'key_usage': extensions_data.get('key_usage', []),
                'extended_key_usage': extensions_data.get('extended_key_usage', []),
                'basic_constraints': extensions_data.get('basic_constraints', {})
            },

            # ── Chaîne de certification ────────────────────────────────────
            'chaine': {
                'longueur': chaine_cert.get('longueur', 0),
                'complete': chaine_cert.get('complete', False),
                'reconstruite_via_aia': chaine_cert.get('reconstruite_via_aia', False),
                'certificats': chaine_cert.get('certificats', [])
            },

            # ── Révocation ─────────────────────────────────────────────────
            'revocation': {
                'ocsp': self._formater_revocation(revocation.get('ocsp', {})),
                'crl': self._formater_revocation(revocation.get('crl', {}))
            }
        }
    def _formater_revocation(self, rev: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formate les données de révocation (OCSP ou CRL) pour le frontend.
        """
        if not rev:
            return {'disponible': False, 'revoque': None, 'statut': 'non vérifié'}

        statut_label = 'non vérifié'
        if rev.get('revoque') is True:
            statut_label = 'révoqué'
        elif rev.get('revoque') is False:
            statut_label = 'valide'
        elif not rev.get('disponible'):
            statut_label = 'non disponible'

        return {**rev, 'statut_label': statut_label}

    def _evaluer_force_cle(self, key_type: str, key_size: int) -> str:
        key_type = str(key_type or '')

        if key_type == 'RSA':
            if key_size >= 4096:
                return 'Très forte (4096+ bits)'
            elif key_size >= 2048:
                return 'Forte (2048 bits)'
            elif key_size >= 1024:
                return 'Faible (1024 bits) - À éviter'
            else:
                return 'Très faible - Non sécurisé'
        elif key_type == 'EC':
            if key_size >= 384:
                return 'Très forte (P-384+)'
            elif key_size >= 256:
                return 'Forte (P-256)'
            else:
                return 'Faible'
        elif key_type in ('Ed25519', 'X25519'):
            return 'Forte (256 bits)'
        elif key_type in ('Ed448', 'X448'):
            return 'Très forte (448 bits)'
        elif key_type == 'DSA':
            if key_size >= 2048:
                return 'Acceptable (DSA déprécié)'
            else:
                return 'Faible (DSA < 2048 bits)'

        return 'Inconnue'