from __future__ import annotations
from classes.tests.testBase import TestBase
from typing import Any,Generator

import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448, x25519, x448, dh
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, NameOID
from OpenSSL import SSL, crypto
import requests

class TestCertificat(TestBase):
    def __init__(self,fqdn:str,port:str):
        super().__init__(fqdn,port)
        self.issuer_cert = None
        self.timeout = 10
        self.chaine_certificats_objets = []

    def lancer(self):
        try:
            # Récupération du certificat
            cert = self.recuperer_certificat()
            
            if not cert:
                self.resultat = {
                    'erreur': True,
                    'message': 'Impossible de récupérer le certificat'
                }
                return # 

            chaine = self.analyser_chaine_certification(cert)

            
            certs_pour_signature = self.chaine_certificats_objets if self.chaine_certificats_objets else [cert]

            self.resultat = {
                'erreur': False,
                'validite': self.analyser_validite(cert),
                'autorite': self.analyser_autorite(cert),
                'cle_publique': self.analyser_cle_publique(cert),
                'signature': self.analyser_signature(certs_pour_signature),
                'extensions': self.analyser_extensions(cert),
                'chaine_certification': chaine,
                'revocation': self.analyser_revocation(cert)
            }
            self.resultat['verdict'] = self.generer_verdict(self.resultat)

        except Exception as e:
            self.resultat = {
                'erreur': True,
                'message': f'Erreur lors de l\'analyse du certificat: {str(e)}'
            }
        
    def recuperer_certificat(self) -> Optional[x509.Certificate]:
        """
        Récupère le certificat SSL/TLS du serveur.
        """
        try:
            context = ssl.create_default_context() # NOSONAR
            context.check_hostname = False  # NOSONAR
            context.verify_mode = ssl.CERT_NONE  # NOSONAR


            with socket.create_connection((self.fqdn, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.fqdn) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    return x509.load_der_x509_certificate(cert_der, default_backend())

        except Exception as e:
            print(f"Erreur récupération certificat: {e}")
            return None

    def analyser_validite(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        Analyse la validité temporelle du certificat
        """
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        jours_restants = (not_after - now).days

        return {
            'debut': not_before.isoformat(),
            'fin': not_after.isoformat(),
            'jours_restants': jours_restants,
            'valide': not_before <= now <= not_after,
            'expire_bientot': 0 < jours_restants <= 30,
            'expire': now > not_after,
            'pas_encore_valide': now < not_before
        }

    def generer_verdict(self, resultats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calcule le verdict global en fusionnant les tests techniques et 
        l'explication des malus de notation (0-100).
        """
        problemes: List[str] = []
        avertissements: List[str] = []

        
        validite = resultats.get('validite', {})
        if validite.get('expire'):
            problemes.append('Certificat expiré (Note: 0/25)')
        elif validite.get('pas_encore_valide'):
            problemes.append('Certificat pas encore valide (Note: 0/25)')
        
        if validite.get('expire_bientot'):
            jours = validite.get('jours_restants', 0)
            avertissements.append(f'Validité : expire dans {jours} jours (Malus : note 15/25)')

       
        autorite = resultats.get('autorite', {})
        if autorite.get('auto_signe'):
            problemes.append('Identité : Certificat auto-signé - Aucune autorité de confiance (-50 pts)')
        if not autorite.get('cn_correspond'):
            problemes.append('Identité : Le nom (CN/SAN) ne correspond pas au domaine cible (-30 pts)')

       
        cle = resultats.get('cle_publique', {})
        key_type = str(cle.get('type', '')).upper()
        taille = cle.get('taille', 0)

        if not cle.get('securise'):
           
            problemes.append(f'Clé publique non sécurisée : {cle.get("details", "inconnu")} (Note: 0/20)')
        else:
            is_rsa_ok = 'RSA' in key_type and taille >= 2048
            is_ec_ok  = any(x in key_type for x in ['EC', 'ECDSA', 'ELLIPTIC']) and taille >= 256
            is_modern = any(x in key_type for x in ['ED25519', 'ED448', 'X25519', 'X448'])

            if not (is_rsa_ok or is_ec_ok or is_modern):
                avertissements.append(
                    f"Clé publique : Le type '{key_type}' ({taille} bits) n'est pas "
                    f"explicitement reconnu par le barème. Note par défaut : 10/20 (-10 pts)"
                )

        
        sig = resultats.get('signature', {})
        if not sig.get('securise'):
            problemes.append(f'Algorithme de signature faible : {sig.get("hash", "inconnu")} (Note: 0/10)')

        
        chaine = resultats.get('chaine_certification', {})
        if chaine.get('erreur'):
            avertissements.append('Chaîne : Impossible de vérifier la structure (Note: 0/25)')
        elif not chaine.get('complete'):
            avertissements.append('Chaîne incomplète : certificat racine non atteint (-10 pts)')
        
        if chaine.get('reconstruite_via_aia'):
            avertissements.append(
                "Chaîne : Le serveur n'envoie pas les certificats intermédiaires. "
                "Le client doit les télécharger via l'AIA, ce qui ralentit la connexion (-10 pts)"
            )
        
        if chaine.get('longueur', 0) > 5:
            avertissements.append(f"Chaîne très longue : {chaine.get('longueur')} certificats détectés (-5 pts)")

        
        ext = resultats.get('extensions', {})
        if not ext.get('san'):
            avertissements.append('Extension : Subject Alternative Name (SAN) manquant (-2 pts)')
        if not ext.get('key_usage'):
            avertissements.append('Extension : Key Usage non défini (-2 pts)')
        
        aia_info = ext.get('authority_info_access', {})
        if 'ca_issuers' not in aia_info:
            avertissements.append("Extension : Lien caIssuers (certificat parent) absent dans l'AIA (-2 pts)")

        if 'ocsp' not in aia_info:
            avertissements.append("Extension : Information OCSP (vérification de révocation) absente dans l'AIA (-5 pts)")

      
        rev = resultats.get('revocation', {})
        ocsp_res = rev.get('ocsp', {})
        crl_res = rev.get('crl', {})
        
        if ocsp_res.get('revoque') is True or crl_res.get('revoque') is True:
            problemes.append('CRITIQUE : Certificat révoqué (Note globale: 0)')
        
       
        elif not ocsp_res.get('disponible') and not crl_res.get('disponible'):
            avertissements.append('Révocation : aucun mécanisme OCSP ou CRL disponible (Note: 0/10)')
        
       
        elif not ocsp_res.get('disponible'):
            avertissements.append('Révocation : Seule la CRL est disponible. L\'absence d\'OCSP est pénalisée (-5 pts)')
        
        elif not crl_res.get('disponible'):
            avertissements.append('Révocation : Seul l\'OCSP est disponible. L\'absence de CRL est pénalisée (-2 pts)')

        
        valide = len(problemes) == 0
        if not valide:
            statut = 'INVALIDE'
        elif avertissements:
            statut = 'ATTENTION'
        else:
            statut = 'VALIDE'

        return {
            'valide': valide,
            'statut': statut,
            'problemes': problemes,
            'avertissements': avertissements
        }

    def analyser_autorite(self, cert: x509.Certificate) -> Dict[str, Any]:
        subject = {}
        for attr in cert.subject:
            oid = attr.oid
            value = attr.value
            if oid == NameOID.COMMON_NAME:
                subject['CN'] = value
            elif oid == NameOID.ORGANIZATION_NAME:
                subject['O'] = value
            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                subject['OU'] = value
            elif oid == NameOID.COUNTRY_NAME:
                subject['C'] = value
            elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                subject['ST'] = value
            elif oid == NameOID.LOCALITY_NAME:
                subject['L'] = value

        issuer = {}
        for attr in cert.issuer:
            oid = attr.oid
            value = attr.value
            if oid == NameOID.COMMON_NAME:
                issuer['CN'] = value
            elif oid == NameOID.ORGANIZATION_NAME:
                issuer['O'] = value
            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                issuer['OU'] = value
            elif oid == NameOID.COUNTRY_NAME:
                issuer['C'] = value

        auto_signe = subject.get('CN') == issuer.get('CN')

        fqdn_cible = self.fqdn.lower()
        cn_cert = subject.get('CN', '').lower()
        
        sans = []
        try:
            san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            noms_dns = san_extension.value.get_values_for_type(x509.DNSName)
            sans = [nom.lower() for nom in noms_dns]
        except x509.ExtensionNotFound:
            pass
    
        cn_correspond = False
        if cn_cert == fqdn_cible or self._verifier_wildcard(cn_cert):
            cn_correspond = True
        else:
            for san in sans:
                if san == fqdn_cible or self._verifier_wildcard(san):
                    cn_correspond = True
                    break

        return {
            'subject': subject,
            'issuer': issuer,
            'auto_signe': auto_signe,
            'sans': sans, 
            'cn_correspond': cn_correspond
        }

    def _verifier_wildcard(self, nom_domaine: str) -> bool:
        if not nom_domaine.startswith('*.'):
            return False
            
        wildcard_domain = nom_domaine[2:].lower()
        fqdn_parts = self.fqdn.lower().split('.')
        
        if len(fqdn_parts) < 2:
            return False
            
        fqdn_domain = '.'.join(fqdn_parts[1:])
        return wildcard_domain == fqdn_domain

    def analyser_cle_publique(self, cert: x509.Certificate) -> Dict[str, Any]:
        public_key = cert.public_key()
        resultats = {}

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            resultats['type'] = 'RSA'
            resultats['taille'] = key_size
            resultats['securise'] = key_size >= 2048
            resultats['details'] = f"RSA {key_size} bits"

        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_size = public_key.key_size
            curve_name = public_key.curve.name
            resultats['type'] = 'EC'
            resultats['taille'] = key_size
            resultats['courbe'] = curve_name
            resultats['securise'] = key_size >= 256
            resultats['details'] = f"ECDSA {curve_name} ({key_size} bits)"

        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            resultats['type'] = 'Ed25519'
            resultats['taille'] = 256
            resultats['securise'] = True
            resultats['details'] = "Ed25519 (256 bits)"

        elif isinstance(public_key, ed448.Ed448PublicKey):
            resultats['type'] = 'Ed448'
            resultats['taille'] = 448
            resultats['securise'] = True
            resultats['details'] = "Ed448 (448 bits)"

        elif isinstance(public_key, dsa.DSAPublicKey):
            key_size = public_key.key_size
            resultats['type'] = 'DSA'
            resultats['taille'] = key_size
            resultats['securise'] = key_size >= 2048
            resultats['details'] = f"DSA {key_size} bits"

        elif isinstance(public_key, dh.DHPublicKey):
            key_size = public_key.key_size
            resultats['type'] = 'DH'
            resultats['taille'] = key_size
            resultats['securise'] = key_size >= 2048
            resultats['details'] = f"DH {key_size} bits"

        elif isinstance(public_key, x25519.X25519PublicKey):
            resultats['type'] = 'X25519'
            resultats['taille'] = 256
            resultats['securise'] = True
            resultats['details'] = "X25519 (256 bits)"

        elif isinstance(public_key, x448.X448PublicKey):
            resultats['type'] = 'X448'
            resultats['taille'] = 448
            resultats['securise'] = True
            resultats['details'] = "X448 (448 bits)"

        else:
            key_type = type(public_key).__name__
            resultats['type'] = key_type
            resultats['taille'] = getattr(public_key, 'key_size', 0)
            resultats['securise'] = False
            resultats['details'] = f"Type non reconnu: {key_type}"

        return resultats

    def analyser_signature(self, certificats_de_la_chaine: List[x509.Certificate]) -> Dict[str, Any]:
        """
        Analyse l'algorithme de signature de TOUTE la chaîne.
        """
        algorithmes_faibles = ['md5', 'sha1'] 
        global_securise = True
        maillon_faible = None

        for cert in certificats_de_la_chaine:
            sig_hash = cert.signature_hash_algorithm
            hash_name = sig_hash.name.lower() if sig_hash else 'unknown' 
            
            if hash_name in algorithmes_faibles:
                global_securise = False
                maillon_faible = hash_name
                break 

       
        leaf_cert = certificats_de_la_chaine[0]
        sig_algo_leaf = leaf_cert.signature_algorithm_oid._name
        hash_leaf = leaf_cert.signature_hash_algorithm.name.lower() if leaf_cert.signature_hash_algorithm else 'unknown'

        if global_securise:
            details_str = f"{sig_algo_leaf} (Chaîne sécurisée)"
        else:
            details_str = f"{sig_algo_leaf} (Vulnérable: un intermédiaire utilise {maillon_faible.upper()})"

        return {
            'algorithme': sig_algo_leaf,
            'hash': hash_leaf,
            'securise': global_securise,
            'details': details_str
        }

    def analyser_extensions(self, cert: x509.Certificate) -> Dict[str, Any]:
        extensions = {
            'san': [],
            'key_usage': [],
            'extended_key_usage': [],
            'basic_constraints': {},
            'authority_info_access': {},
            'crl_distribution_points': []
        }

        try:
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if hasattr(name, 'value'):
                        extensions['san'].append(str(name.value))
            except x509.ExtensionNotFound:
                pass

            try:
                ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                ku = ku_ext.value
                if ku.digital_signature:
                    extensions['key_usage'].append('Digital Signature')
                if ku.key_encipherment:
                    extensions['key_usage'].append('Key Encipherment')
                if ku.key_agreement:
                    extensions['key_usage'].append('Key Agreement')
            except x509.ExtensionNotFound:
                pass

            try:
                eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                for eku in eku_ext.value:
                    extensions['extended_key_usage'].append(eku._name)
            except x509.ExtensionNotFound:
                pass

            try:
                bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                bc = bc_ext.value
                extensions['basic_constraints'] = {
                    'ca': bc.ca,
                    'path_length': bc.path_length
                }
            except x509.ExtensionNotFound:
                extensions['basic_constraints'] = {'ca': False, 'path_length': None}

            try:
                aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                for access in aia_ext.value:
                    if access.access_method._name == 'OCSP':
                        extensions['authority_info_access']['ocsp'] = access.access_location.value
                    elif access.access_method._name == 'caIssuers':
                        extensions['authority_info_access']['ca_issuers'] = access.access_location.value
            except x509.ExtensionNotFound:
                pass

            try:
                crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
                for dp in crl_ext.value:
                    for name in dp.full_name:
                        if hasattr(name, 'value'):
                            extensions['crl_distribution_points'].append(name.value)
            except x509.ExtensionNotFound:
                pass

        except Exception as e:
            extensions['erreur'] = str(e)

        return extensions

    def analyser_chaine_certification(
        self, cert: Optional[x509.Certificate] = None
    ) -> Dict[str, Any]:
        """
        Analyse la chaîne de certification complète.
        Essai 1 : connexion TLS via pyOpenSSL (chaîne envoyée par le serveur).
        Essai 2 : reconstruction en suivant les AIA caIssuers (fallback universel).
        """
        # ── Essai 1 : pyOpenSSL ───────────────────────────────────────────
        try:
            context = SSL.Context(SSL.TLS_METHOD)
            context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
            context.set_cipher_list(b"ALL:@SECLEVEL=0")

            with socket.create_connection(
                (self.fqdn, self.port), timeout=self.timeout
            ) as raw_sock:
                raw_sock.setblocking(True)
                conn = SSL.Connection(context, raw_sock)
                conn.set_tlsext_host_name(self.fqdn.encode('utf-8'))
                conn.set_connect_state()
                while True:
                    try:
                        conn.do_handshake()
                        break # Succès, on sort de la boucle
                    except SSL.WantReadError:
                        # Le système n'est pas prêt, on attend un peu
                        import select
                        select.select([raw_sock], [], [], self.timeout)
                        continue
                    except SSL.WantWriteError:
                        import select
                        select.select([], [raw_sock], [], self.timeout)
                        continue

                chain = conn.get_peer_cert_chain()
                if chain:
                    dernier_openssl = chain[-1]
                    racine_presente = (dernier_openssl.get_subject().CN == dernier_openssl.get_issuer().CN)
                    
                    
                    if len(chain) > 1 or racine_presente:
                        self.chaine_certificats_objets = []
                        for c in chain:
                            cert_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, c)
                            self.chaine_certificats_objets.append(
                                x509.load_der_x509_certificate(cert_der, default_backend())
                            )
                        
                        if len(self.chaine_certificats_objets) >= 2:
                            self.issuer_cert = self.chaine_certificats_objets[1]

                        return {
                            'longueur': len(chain),
                            'complete': True,
                            'reconstruite_via_aia': False,
                            'certificats': [{'niveau': i, 'subject': c.get_subject().CN, 'issuer': c.get_issuer().CN} for i, c in enumerate(chain)]
                        }
        except Exception as e:
            pass  

        # ── Essai 2 : reconstruction via AIA caIssuers ────────────────────
        if cert:
            return self._construire_chaine_via_aia(cert)

        return {
            'erreur': True,
            'message': 'Impossible de récupérer la chaîne de certification'
        }

    def _construire_chaine_via_aia(
        self, leaf_cert: x509.Certificate
    ) -> Dict[str, Any]:
        """
        Reconstruit la chaîne en téléchargeant chaque certificat émetteur
        depuis l'URL caIssuers de l'extension AIA.
        Fonctionne sur tout serveur, même ceux qui n'envoient pas leur chaîne.
        """
        chain = [leaf_cert]
        current = leaf_cert

        for _ in range(5):  
            try:
                aia = current.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
                ca_url = None
                for access in aia.value:
                    if access.access_method._name == 'caIssuers':
                        ca_url = access.access_location.value
                        break

                if not ca_url:
                    break

                resp = requests.get(ca_url, timeout=10)
                if resp.status_code != 200:
                    break

                try:
                    issuer = x509.load_der_x509_certificate(
                        resp.content, default_backend()
                    )
                except Exception:
                    issuer = x509.load_pem_x509_certificate(
                        resp.content, default_backend()
                    )

                chain.append(issuer)

                if self.issuer_cert is None and len(chain) == 2:
                    self.issuer_cert = issuer

                if issuer.subject == issuer.issuer:
                    break

                current = issuer

            except Exception:
                break

        def _cn(c: x509.Certificate) -> Optional[str]:
            attrs = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None

        def _cn_issuer(c: x509.Certificate) -> Optional[str]:
            attrs = c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None

        self.chaine_certificats_objets = chain
        dernier = chain[-1]
        
        return {
            'longueur': len(chain),
            'complete': dernier.subject == dernier.issuer,
            'reconstruite_via_aia': True,
            'certificats': [
                {'niveau': i, 'subject': _cn(c), 'issuer': _cn_issuer(c)}
                for i, c in enumerate(chain)
            ]
        }

    def analyser_revocation(self, cert: x509.Certificate) -> Dict[str, Any]:
        """
        Vérifie le statut de révocation via OCSP et CRL
        """
        resultats = {
            'ocsp': {'disponible': False, 'revoque': None},
            'crl': {'disponible': False, 'revoque': None}
        }

        extensions = self.analyser_extensions(cert)

        # ── Test OCSP ──
        if 'ocsp' in extensions.get('authority_info_access', {}):
            ocsp_url = extensions['authority_info_access']['ocsp']
            resultats['ocsp']['disponible'] = True
            resultats['ocsp']['url'] = ocsp_url

            if self.issuer_cert:
                try:
                    builder = ocsp.OCSPRequestBuilder()
                    builder = builder.add_certificate(cert, self.issuer_cert, hashes.SHA256())
                    ocsp_request = builder.build()

                    response = requests.post(
                        ocsp_url,
                        data=ocsp_request.public_bytes(Encoding.DER),
                        headers={'Content-Type': 'application/ocsp-request'},
                        timeout=10
                    )

                    if response.status_code == 200:
                        ocsp_response = ocsp.load_der_ocsp_response(response.content)
                        status = ocsp_response.response_status
                        resultats['ocsp']['teste'] = True

                        if status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                            cert_status = ocsp_response.certificate_status
                            if cert_status == ocsp.OCSPCertStatus.GOOD:
                                resultats['ocsp']['revoque'] = False
                                resultats['ocsp']['statut'] = 'good'
                            elif cert_status == ocsp.OCSPCertStatus.REVOKED:
                                resultats['ocsp']['revoque'] = True
                                resultats['ocsp']['statut'] = 'revoked'
                                resultats['ocsp']['date_revocation'] = (
                                    ocsp_response.revocation_time.isoformat() 
                                    if ocsp_response.revocation_time else None
                                )
                                resultats['ocsp']['raison'] = (
                                    ocsp_response.revocation_reason.value
                                    if ocsp_response.revocation_reason else None
                                )
                            elif cert_status == ocsp.OCSPCertStatus.UNKNOWN:
                                resultats['ocsp']['revoque'] = None
                                resultats['ocsp']['statut'] = 'unknown'

                            if ocsp_response.this_update:
                                resultats['ocsp']['derniere_mise_a_jour'] = (
                                    ocsp_response.this_update.replace(tzinfo=timezone.utc).isoformat()
                                )
                            if ocsp_response.next_update:
                                resultats['ocsp']['prochaine_mise_a_jour'] = (
                                    ocsp_response.next_update.replace(tzinfo=timezone.utc).isoformat()
                                )
                        else:
                            resultats['ocsp']['statut'] = f'response_status_{status.value}'
                            resultats['ocsp']['message'] = f'Réponse OCSP non réussie: {status.name}'
                    else:
                        resultats['ocsp']['teste'] = False
                        resultats['ocsp']['message'] = (
                            f'Erreur HTTP {response.status_code} du répondeur OCSP'
                        )
                except Exception as e:
                    resultats['ocsp']['teste'] = False
                    resultats['ocsp']['erreur'] = str(e)
            else:
                resultats['ocsp']['teste'] = False
                resultats['ocsp']['message'] = (
                    'Certificat émetteur non disponible pour la requête OCSP'
                )

        # ── Test CRL ──
        if extensions.get('crl_distribution_points'):
            crl_urls = extensions['crl_distribution_points']
            resultats['crl']['disponible'] = True
            resultats['crl']['urls'] = crl_urls

            try:
                crl_url = crl_urls[0]
                response = requests.get(crl_url, timeout=10)

                if response.status_code == 200:
                    crl_data = response.content
                    resultats['crl']['taille'] = len(crl_data)

                    crl_obj = None
                    try:
                        crl_obj = x509.load_der_x509_crl(crl_data, default_backend())
                    except Exception:
                        try:
                            crl_obj = x509.load_pem_x509_crl(crl_data, default_backend())
                        except Exception:
                            pass

                    if crl_obj:
                        resultats['crl']['teste'] = True

                        revoked_entry = crl_obj.get_revoked_certificate_by_serial_number(
                            cert.serial_number
                        )
                        if revoked_entry is not None:
                            resultats['crl']['revoque'] = True
                            resultats['crl']['date_revocation'] = (
                                revoked_entry.revocation_date.isoformat() 
                        )
                        else:
                            resultats['crl']['revoque'] = False

                        resultats['crl']['emetteur'] = (
                            crl_obj.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                            if crl_obj.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                            else None
                        )
                        resultats['crl']['derniere_mise_a_jour'] = crl_obj.last_update.replace(tzinfo=timezone.utc).isoformat()
                        resultats['crl']['prochaine_mise_a_jour'] = (
                            crl_obj.next_update.replace(tzinfo=timezone.utc).isoformat() if crl_obj.next_update else None
                        )
                        resultats['crl']['nombre_certificats_revoques'] = len(list(crl_obj))

                        if self.issuer_cert:
                            try:
                                issuer_public_key = self.issuer_cert.public_key()
                                if isinstance(issuer_public_key, rsa.RSAPublicKey):
                                    from cryptography.hazmat.primitives.asymmetric import padding
                                    issuer_public_key.verify(
                                        crl_obj.signature,
                                        crl_obj.tbs_certlist_bytes,
                                        padding.PKCS1v15(),
                                        crl_obj.signature_hash_algorithm
                                    )
                                elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                                    issuer_public_key.verify(
                                        crl_obj.signature,
                                        crl_obj.tbs_certlist_bytes,
                                        ec.ECDSA(crl_obj.signature_hash_algorithm)
                                    )
                                resultats['crl']['signature_valide'] = True
                            except Exception:
                                resultats['crl']['signature_valide'] = False
                    else:
                        resultats['crl']['teste'] = False
                        resultats['crl']['message'] = 'Impossible de parser la CRL (format non reconnu)'
                else:
                    resultats['crl']['teste'] = False
                    resultats['crl']['message'] = (
                        f'Erreur HTTP {response.status_code} lors du téléchargement de la CRL'
                    )

            except Exception as e:
                resultats['crl']['teste'] = False
                resultats['crl']['erreur'] = str(e)

        return resultats