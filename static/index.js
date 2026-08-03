const DOM = {
    input: document.getElementById('domain-input'),
    portInput: document.getElementById('port-input'),
    btnScan: document.getElementById('scan-button'),
    btnNew: document.getElementById('new-scan-button'),
    examples: document.querySelectorAll('.example-domain'),

    hero: document.getElementById('hero-section'),
    dashboard: document.getElementById('dashboard-section'),
    statusBar: document.getElementById('status-bar'),
    statusSpinner: document.getElementById('status-spinner'),
    statusText: document.getElementById('status-text'),
    progressFill: document.getElementById('progress-fill'),
    domainName: document.getElementById('domain-name'),
    portDisplay: document.getElementById('port-display'),
    portWarning: document.getElementById('port-warning'),
    warningPortNum: document.getElementById('warning-port-num'),
    btnTop: document.getElementById('back-to-top'),
    scanCheckbox: document.getElementById('scan-checkbox'),
    scanTypeBadge: document.getElementById('scan-type-badge'),

    scores: {
        cert: { card: document.getElementById('cert-score-card'), val: document.getElementById('cert-score') },
        proto: { card: document.getElementById('protocol-score-card'), val: document.getElementById('protocol-score') },
        cipher: { card: document.getElementById('cipher-score-card'), val: document.getElementById('cipher-score') },
        key: { card: document.getElementById('key-score-card'), val: document.getElementById('key-score') },
        global: { card: document.getElementById('global-score-card'), val: document.getElementById('global-score'), eval: document.getElementById('global-evaluation') }
    },

    content: {
        validite: document.getElementById('cert-validite-content'),
        autorite: document.getElementById('cert-autorite-content'),
        cle: document.getElementById('cert-cle-content'),
        signature: document.getElementById('cert-signature-content'),
        extensions: document.getElementById('cert-extensions-content'),
        chaine: document.getElementById('cert-chaine-content'),
        revocation: document.getElementById('cert-revocation-content'),
        problemes: document.getElementById('cert-problemes-content'),
        proto: document.getElementById('protocol-content'),
        cipher: document.getElementById('cipher-content'),
        keyEcdhe: document.getElementById('key-ecdhe-content'),
        keyOther: document.getElementById('key-other-content'),
        keyEcdh: document.getElementById('key-ecdh-content'),
        compat: document.getElementById('compat-content'),
        ports: document.getElementById('ports-content'),
        portsStatus: document.getElementById('ports-status-content'),
        vuln: document.getElementById('vuln-content'),
        vulnResume: document.getElementById('vuln-resume-content')
    }
};

// ─── Helpers ────────────────────────────────────────────────────

function badge(text, cls) {
    return `<span class="badge ${cls}">${text}</span>`;
}

function isGood(val) {
    return val ? badge('Oui', 'safe') : badge('Non', 'unsafe');
}

function isBad(val) {
    return val ? badge('Oui', 'unsafe') : badge('Non', 'safe');
}

function infoRow(label, value) {
    return `<div class="data-row"><span>${label}</span><span>${value ?? '-'}</span></div>`;
}

// ─── UI ─────────────────────────────────────────────────────────

const UI = {

    resetDashboard(domain, port, scanType) {
        DOM.hero.classList.add('hidden');
        DOM.dashboard.classList.remove('hidden');
        DOM.domainName.textContent = domain;
        DOM.portDisplay.textContent = 'Port : ' + port;

        if (DOM.scanTypeBadge) {
            const isComplet = scanType === 'complet';
            DOM.scanTypeBadge.textContent = isComplet ? 'Analyse complète' : 'Analyse rapide';
            DOM.scanTypeBadge.className = 'scan-type-badge ' + (isComplet ? 'scan-type-complet' : 'scan-type-rapide');
        }

        DOM.portWarning.classList.add('hidden');

        Object.values(DOM.scores).forEach(s => {
            if (!s.card) return;
            s.card.className = 'summary-card';
            if (s.card.id === 'global-score-card') s.card.classList.add('summary-card-global');
            if (s.val) {
                s.val.classList.add('hidden');
                const skel = s.val.previousElementSibling;
                if (skel) skel.style.display = 'block';
            }
            if (s.eval) s.eval.classList.add('hidden');
        });

        const loader = '<div class="loading-state"><div class="spinner-ring"></div></div>';
        Object.values(DOM.content).forEach(z => { if (z) z.innerHTML = loader; });

        document.querySelectorAll('.data-sections .section').forEach(s => {
            s.style.display = '';
        });

        DOM.statusBar.classList.remove('complete');
        DOM.statusSpinner.style.display = 'block';
        DOM.progressFill.style.width = '10%';
        DOM.statusText.textContent = 'Communication avec le serveur...';
        DOM.statusText.style.color = '';

        const bar = document.getElementById('back-to-top-bar');
        if (bar) bar.classList.add('hidden');
    },

    setProgress(pct, text) {
        DOM.progressFill.style.width = pct + '%';
        DOM.statusText.textContent = text;
    },

    setComplete() {
        DOM.progressFill.style.width = '100%';
        DOM.statusText.textContent = 'Scan terminé ✓';
        DOM.statusBar.classList.add('complete');
        DOM.statusSpinner.style.display = 'none';
        const bar = document.getElementById('back-to-top-bar');
        if (bar) bar.classList.remove('hidden');
    },

    setError(msg) {
        DOM.statusText.textContent = '❌ Erreur : ' + msg;
        DOM.statusText.style.color = 'var(--color-danger)';
        DOM.statusSpinner.style.display = 'none';
    },

    updateScore(target, value) {
        if (!target || !target.card || !target.val) return;
        const skel = target.val.previousElementSibling;
        if (skel) skel.style.display = 'none';
        target.val.textContent = value;
        target.val.classList.remove('hidden');
        target.card.classList.remove('excellent', 'good', 'warning', 'poor');
        if (value >= 90) target.card.classList.add('excellent');
        else if (value >= 70) target.card.classList.add('good');
        else if (value >= 50) target.card.classList.add('warning');
        else target.card.classList.add('poor');
    },

    setScoreDash(target) {
        if (!target || !target.card || !target.val) return;
        const skel = target.val.previousElementSibling;
        if (skel) skel.style.display = 'none';
        target.val.textContent = '—';
        target.val.classList.remove('hidden');
        target.card.classList.remove('excellent', 'good', 'warning', 'poor');
    },

    renderAll(rapport, notes) {
        const cert = rapport.certificat;

        const isExpired = cert?.validite?.expire === true;
        const isNotYetValid = cert?.validite?.pas_encore_valide === true;
        const isAutoSigned = cert?.auto_signe === true;
        const isCnMismatch = cert?.cn_correspond === false; 
        const isInsecureKey = cert?.cle_publique?.securise === false; 
        const isInsecureSig = cert?.signature?.securise === false; 
        const isRevoked = cert?.revocation?.ocsp?.revoque === true || cert?.revocation?.crl?.revoque === true;

        const isFatalError = isExpired || isNotYetValid || isAutoSigned || isCnMismatch || isInsecureKey || isInsecureSig || isRevoked;

        if (isFatalError) {
            const sections = document.querySelectorAll('.data-sections .section');
            sections.forEach(section => {
                const title = section.querySelector('.section-title');
                if (title && title.textContent.trim() === 'Certificat SSL/TLS') {
                    return; 
                }
                section.style.display = 'none';
            });

            if (cert) this.renderCert(cert);

            let raison = "invalide";
            if (isRevoked) raison = "révoqué";
            else if (isExpired) raison = "expiré";
            else if (isNotYetValid) raison = "pas encore valide";
            else if (isAutoSigned) raison = "auto-signé";
            else if (isCnMismatch) raison = "invalide (le nom de domaine ne correspond pas)";
            else if (isInsecureKey) raison = "vulnérable (clé publique non sécurisée)";
            else if (isInsecureSig) raison = "vulnérable (algorithme de signature faible)";

            DOM.statusText.textContent = `Certificat ${raison} — analyse des autres composants interrompue.`;
            DOM.statusText.style.color = 'var(--color-danger)';
            DOM.progressFill.style.width = '100%';
            DOM.statusSpinner.style.display = 'none';
            DOM.statusBar.classList.add('complete');

            this.updateScore(DOM.scores.cert, 0);
            this.setScoreDash(DOM.scores.proto);
            this.setScoreDash(DOM.scores.cipher);
            this.setScoreDash(DOM.scores.key);
            this.setScoreDash(DOM.scores.global);
            if (DOM.scores.global.eval) {
                DOM.scores.global.eval.classList.add('hidden');
            }

            return; 
        }

        if (rapport.certificat) this.renderCert(rapport.certificat);
        if (rapport.protocole) this.renderProto(rapport.protocole);
        if (rapport.ciphers) this.renderCipher(rapport.ciphers);
        if (rapport.echangeCle) this.renderKeyExchange(rapport.echangeCle);
        if (rapport.compatibiliteOs) this.renderCompat(rapport.compatibiliteOs);
        if (rapport.ports) this.renderPorts(rapport.ports);
        if (rapport.vuln) this.renderVuln(rapport.vuln);
        if (notes) this.renderScores(notes, rapport);

        this.setComplete();
    },

    renderScores(notes, rapport) {
        if (notes.NoteCertificat !== undefined) {
            this.updateScore(DOM.scores.cert, Math.round(notes.NoteCertificat));
        }
        if (notes.NoteProtocole !== undefined) {
            this.updateScore(DOM.scores.proto, Math.round(notes.NoteProtocole));
        }
        if (notes.NoteCipher !== undefined) {
            this.updateScore(DOM.scores.cipher, Math.round(notes.NoteCipher));
        }
        if (notes.NoteEchangeCle !== undefined) {
            this.updateScore(DOM.scores.key, Math.round(notes.NoteEchangeCle));
        }

        if (notes.noteGlobale !== undefined && DOM.scores.global) {
            const globalScore = Math.round(notes.noteGlobale);
            this.updateScore(DOM.scores.global, globalScore);

            if (notes.evaluation && DOM.scores.global.eval) {
                const evalEl = DOM.scores.global.eval;
                evalEl.textContent = notes.evaluation;
                evalEl.classList.remove('hidden', 'A', 'B', 'F', 'T');
                evalEl.classList.add(notes.evaluation);
            }
        }
    },

    // ─── CERTIFICAT ──────────────────────────────────────────────
    renderCert(cert) {
        if (!cert) return;

        // ═══════════════════════════════════════════════════════════════════
        // VALIDITÉ
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.validite) {
            const v = cert.validite || {};
            DOM.content.validite.innerHTML =
                infoRow('Validité temporelle', v.valide ? badge('OUI', 'safe') : badge('NON', 'unsafe')) +
                infoRow('Début', v.debut || '-') +
                infoRow('Fin', v.fin || '-') +
                infoRow('Jours restants', v.jours_restants ?? '-') +
                infoRow('Expire bientôt', isBad(v.expire_bientot)) +
                infoRow('Expiré', isBad(v.expire)) +
                infoRow('Pas encore valide', isBad(v.pas_encore_valide));
        }

        // ═══════════════════════════════════════════════════════════════════
        // AUTORITÉ/IDENTITÉ
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.autorite) {
            const sub = cert.sujet || {};
            const iss = cert.emetteur || {};

            DOM.content.autorite.innerHTML =
                `<div class="subsection-title">Sujet</div>` +
                infoRow('CN', sub.CN || '-') +
                infoRow('Organisation', sub.O || '-') +
                infoRow('OU', sub.OU || '-') +
                infoRow('Pays', sub.C || '-') +
                infoRow('État', sub.ST || '-') +
                infoRow('Ville', sub.L || '-') +
                `<div class="subsection-title" style="margin-top:1rem">Émetteur</div>` +
                infoRow('CN', iss.CN || '-') +
                infoRow('Organisation', iss.O || '-') +
                infoRow('OU', iss.OU || '-') +
                infoRow('Pays', iss.C || '-') +
                `<div class="subsection-title" style="margin-top:1rem">Validation</div>` +
                infoRow('Auto-signé', isBad(cert.auto_signe)) +
                infoRow('CN correspond', isGood(cert.cn_correspond));
        }

        // ═══════════════════════════════════════════════════════════════════
        // CLÉ PUBLIQUE
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.cle) {
            const k = cert.cle_publique || {};
            DOM.content.cle.innerHTML =
                infoRow('Type', k.type || '-') +
                infoRow('Taille', k.taille ? k.taille + ' bits' : '-') +
                infoRow('Courbe', k.courbe || '-') +
                infoRow('Force', k.force || '-') +
                infoRow('Sécurisé', isGood(k.securise)) +
                infoRow('Détails', k.details || '-');
        }

        // ═══════════════════════════════════════════════════════════════════
        // SIGNATURE
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.signature) {
            const s = cert.signature || {};
            DOM.content.signature.innerHTML =
                infoRow('Algorithme', s.algorithme || '-') +
                infoRow('Hash', s.hash || '-') +
                infoRow('Sécurisé', isGood(s.securise)) +
                infoRow('Détails', s.details || '-');
        }

        // ═══════════════════════════════════════════════════════════════════
        // EXTENSIONS
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.extensions) {
            const e = cert.extensions || {};
            const bc = e.basic_constraints || {};

            DOM.content.extensions.innerHTML =
                infoRow('Noms domaines protégés (SAN)', (e.san || []).join(', ') || '-') +
                infoRow('Usage de la clé (Key Usage)', (e.key_usage || []).join(', ') || '-') +
                infoRow('Type d\'authentification (extended key usage)', (e.extended_key_usage || []).join(', ') || '-') +
                infoRow('Est une Autorité (CA)', isBad(bc.ca)) +
                infoRow('longueur de chemin (Path Length)', bc.path_length !== null && bc.path_length !== undefined ? bc.path_length : '-');
        }

        // ═══════════════════════════════════════════════════════════════════
        // CHAÎNE DE CERTIFICATION
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.chaine) {
            const c = cert.chaine || {};
            const certs = c.certificats || [];

            let chainHtml =
                infoRow('Longueur', c.longueur ?? '-') +
                infoRow('Complète', isGood(c.complete));

            if (certs.length > 0) {
                chainHtml += `<div class="cipher-group" style="margin-top:0.75rem">
                <div class="cipher-group-title">Certificats dans la chaîne</div>
                <div class="cipher-list">`;

                certs.forEach(ct => {
                    chainHtml += `<div class="cipher-item secure">
                    <span class="cipher-name">Niveau ${ct.niveau} — ${ct.subject || 'N/A'}</span>
                    <span style="font-size:0.8rem;color:var(--color-text-muted)">Émis par: ${ct.issuer || 'N/A'}</span>
                </div>`;
                });

                chainHtml += `</div></div>`;
            }

            DOM.content.chaine.innerHTML = chainHtml;
        }

        // ═══════════════════════════════════════════════════════════════════
        // RÉVOCATION
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.revocation) {
            const r = cert.revocation || {};
            const ocsp = r.ocsp || {};
            const crl = r.crl || {};

            let revocHtml = `<div class="subsection-title" style="margin-top:0; margin-bottom: 1rem; color: var(--color-primary); font-size: 0.9rem;">Vérification de révocation</div>`;

            revocHtml += `<div class="subsection-title">OCSP</div>`;

            if (ocsp.disponible) {
                revocHtml +=
                    infoRow('Disponible', badge('OUI', 'safe')) +
                    infoRow('URL', ocsp.url || '-');

                if (ocsp.statut_label) {
                    revocHtml += infoRow('Statut', ocsp.statut_label);
                } else if (ocsp.statut) {
                    revocHtml += infoRow('Statut', ocsp.statut);
                }

                revocHtml += infoRow('Révoqué', isBad(ocsp.revoque));

                if (ocsp.teste !== undefined) {
                    revocHtml += infoRow('Testé', isGood(ocsp.teste));
                }

                if (ocsp.derniere_mise_a_jour) {
                    try {
                        const date = new Date(ocsp.derniere_mise_a_jour);
                        revocHtml += infoRow('Dernière MAJ',
                            date.toLocaleString('fr-FR', {
                                year: 'numeric',
                                month: '2-digit',
                                day: '2-digit',
                                hour: '2-digit',
                                minute: '2-digit'
                            }));
                    } catch (e) {
                        revocHtml += infoRow('Dernière MAJ', ocsp.derniere_mise_a_jour);
                    }
                }

                if (ocsp.prochaine_mise_a_jour) {
                    try {
                        const date = new Date(ocsp.prochaine_mise_a_jour);
                        revocHtml += infoRow('Prochaine MAJ',
                            date.toLocaleString('fr-FR', {
                                year: 'numeric',
                                month: '2-digit',
                                day: '2-digit',
                                hour: '2-digit',
                                minute: '2-digit'
                            }));
                    } catch (e) {
                        revocHtml += infoRow('Prochaine MAJ', ocsp.prochaine_mise_a_jour);
                    }
                }

                if (ocsp.message) {
                    revocHtml += infoRow('Message', ocsp.message);
                }
            } else {
                revocHtml += infoRow('Disponible', badge('NON', 'unsafe'));
            }

            revocHtml += `<div class="subsection-title" style="margin-top:1rem">CRL</div>`;

            if (crl.disponible) {
                revocHtml += infoRow('Disponible', badge('OUI', 'safe'));

                if (crl.urls && Array.isArray(crl.urls) && crl.urls.length > 0) {
                    revocHtml += infoRow('URL', crl.urls[0]);
                    if (crl.urls.length > 1) {
                        revocHtml += infoRow('URLs supplémentaires', `${crl.urls.length - 1} autre(s)`);
                    }
                } else if (crl.url) {
                    revocHtml += infoRow('URL', crl.url);
                }

                if (crl.statut_label) {
                    revocHtml += infoRow('Statut', crl.statut_label);
                }

                revocHtml += infoRow('Révoqué', isBad(crl.revoque));

                if (crl.teste !== undefined) {
                    revocHtml += infoRow('Testé', isGood(crl.teste));
                }

                if (crl.telecharge !== undefined) {
                    revocHtml += infoRow('Téléchargé', isGood(crl.telecharge));
                }

                if (crl.taille) {
                    revocHtml += infoRow('Taille', (crl.taille / 1024).toFixed(2) + ' KB');
                }

                if (crl.emetteur) {
                    revocHtml += infoRow('Émetteur', crl.emetteur);
                }

                if (crl.nombre_certificats_revoques !== undefined && crl.nombre_certificats_revoques !== null) {
                    revocHtml += infoRow('Certificats révoqués', crl.nombre_certificats_revoques);
                }

                if (crl.signature_valide !== undefined) {
                    revocHtml += infoRow('Signature CRL valide', isGood(crl.signature_valide));
                }

                if (crl.derniere_mise_a_jour) {
                    try {
                        const date = new Date(crl.derniere_mise_a_jour);
                        revocHtml += infoRow('Dernière MAJ',
                            date.toLocaleString('fr-FR', {
                                year: 'numeric',
                                month: '2-digit',
                                day: '2-digit',
                                hour: '2-digit',
                                minute: '2-digit'
                            }));
                    } catch (e) {
                        revocHtml += infoRow('Dernière MAJ', crl.derniere_mise_a_jour);
                    }
                }

                if (crl.prochaine_mise_a_jour) {
                    try {
                        const date = new Date(crl.prochaine_mise_a_jour);
                        revocHtml += infoRow('Prochaine MAJ',
                            date.toLocaleString('fr-FR', {
                                year: 'numeric',
                                month: '2-digit',
                                day: '2-digit',
                                hour: '2-digit',
                                minute: '2-digit'
                            }));
                    } catch (e) {
                        revocHtml += infoRow('Prochaine MAJ', crl.prochaine_mise_a_jour);
                    }
                }

                if (crl.message) {
                    revocHtml += infoRow('Message', crl.message);
                }

                if (crl.erreur) {
                    revocHtml += infoRow('Erreur', crl.erreur);
                }
            } else {
                revocHtml += infoRow('Disponible', badge('NON', 'unsafe'));
            }

            DOM.content.revocation.innerHTML = revocHtml;
        }

        // ═══════════════════════════════════════════════════════════════════
        // PROBLÈMES
        // ═══════════════════════════════════════════════════════════════════
        if (DOM.content.problemes) {
            let problemesHtml = '';

            const problemes = (cert.verdict && Array.isArray(cert.verdict.problemes))
                ? cert.verdict.problemes
                : (Array.isArray(cert.problemes) ? cert.problemes : []);

            const avertissementsBruts =
                (cert.verdict && Array.isArray(cert.verdict.avertissements) ? cert.verdict.avertissements : null) ||
                cert.avertissements ||
                cert.avertissement ||
                [];
            const avertissements = Array.isArray(avertissementsBruts) ? avertissementsBruts : [];

            if (problemes.length === 0 && avertissements.length === 0) {
                problemesHtml = infoRow('Statut', badge('Aucun problème détecté', 'safe'));
            } else {
                problemesHtml = '<div class="problemes-list">';

                problemes.forEach(prob => {
                    const texteProb = typeof prob === 'object' ? (prob.nom || prob.description || 'Problème détecté') : prob;
                    problemesHtml += `<div class="probleme-item danger">${texteProb}</div>`;
                });

                avertissements.forEach(avert => {
                    const texteAvert = typeof avert === 'object' ? (avert.nom || avert.description || 'Avertissement') : avert;
                    problemesHtml += `<div class="probleme-item warning">${texteAvert}</div>`;
                });

                problemesHtml += '</div>';
            }

            DOM.content.problemes.innerHTML = problemesHtml;
        }
    },

    // ─── PROTOCOLES ──────────────────────────────────────────────
    renderProto(list) {
        const items = Array.isArray(list) ? list : (list?.tests || []);

        const supportedItems = items.filter(p => p.supporte);

        if (supportedItems.length === 0) {
            DOM.content.proto.innerHTML = '<p style="color:var(--color-text-muted)">Aucun protocole supporté détecté</p>';
            return;
        }

        let html = '<div class="protocol-list">';

        supportedItems.forEach(p => {
            const nameLower = p.nom.toLowerCase();

            let statusClass = 'supported'; 
            let statusLabel = '✓ Sécurisé';

            if (nameLower.includes('ssl')) {
                statusClass = 'insecure'; 
                statusLabel = '❌ Dangereux';
            } else if (nameLower.includes('tls') && (nameLower.includes('1.0') || nameLower.includes('1.1'))) {
                statusClass = 'obsolete'; 
                statusLabel = '⚠️ Obsolète';
            } else if (nameLower.includes('tls') && (nameLower.includes('1.2') || nameLower.includes('1.3'))) {
                statusClass = 'supported'; 
                statusLabel = '✓ Sécurisé';
            }

            html += `
            <div class="protocol-item ${statusClass}">
                <span class="protocol-name">${p.nom}</span>
                <span class="protocol-status">
                    <span class="protocol-badge ${statusClass}">${statusLabel}</span>
                </span>
            </div>
            `;
        });

        DOM.content.proto.innerHTML = html + '</div>';
    },

    // ─── CIPHERS ─────────────────────────────────────────────────
    renderCipher(data) {
        const CIPHER_LIMIT = 5;
        let html = '';
        Object.keys(data).forEach(ver => {
            const list = data[ver];
            if (!Array.isArray(list)) return;

            const groupId = 'cg-' + ver.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9-]/g, '');
            const hasMore = list.length > CIPHER_LIMIT;

            html += `<div class="cipher-group">
                    <div class="cipher-group-title">${ver}</div>
                    <div class="cipher-list" id="${groupId}">`;

            list.forEach((c, i) => {
                const force = (c.force || '').toLowerCase();
                let cls = 'insecure';
                if (force === 'secure') cls = 'secure';
                else if (force === 'weak') cls = 'weak';
                else if (force === 'unsecure' || force === 'insecure') cls = 'insecure';

                const hidden = hasMore && i >= CIPHER_LIMIT ? ' cipher-hidden is-overflow' : ''; html += `<div class="cipher-item ${cls}${hidden}">
                        <span class="cipher-name">${c.nom}</span>
                        <span class="cipher-badge ${cls}">${c.taille} bits</span>
                     </div>`;
            });

            html += `</div>`;

            if (hasMore) {
                const remaining = list.length - CIPHER_LIMIT;
                html += `<button class="show-more-btn" data-target="${groupId}" data-remaining="${remaining}">
                    Voir ${remaining} suite${remaining > 1 ? 's' : ''} supplémentaire${remaining > 1 ? 's' : ''}
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 4l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>`;
            }

            html += `</div>`;
        });

        DOM.content.cipher.innerHTML =
            html || '<p style="color:var(--color-text-muted)">Aucune donnée</p>';

        DOM.content.cipher.querySelectorAll('.show-more-btn').forEach(btn => {
            btn.addEventListener('click', () => this._toggleShowMore(btn));
        });
    },

    // ─── ÉCHANGE DE CLÉS ─────────────────────────────────────────
    renderKeyExchange(data) {
        const getStrengthClass = (name, size) => {
            const n = (name || '').toLowerCase();
            if (n.includes('ec') || n.includes('ed') || n.includes('x25519') || n.includes('x448')) {
                if (size >= 256) return 'secure'; 
                if (size >= 224) return 'weak';   
                return 'insecure';                
            }
            if (size >= 3072) return 'secure';    
            if (size >= 2048) return 'weak';      
            return 'insecure';                    
        }

        const ecdheCard = DOM.content.keyEcdhe.closest('.data-card');
        const otherCard = DOM.content.keyOther.closest('.data-card');
        const ecdhCard = DOM.content.keyEcdh.closest('.data-card');

        const ecdheList = data.ecdhe && Array.isArray(data.ecdhe.courbes) ? data.ecdhe.courbes : [];
        if (ecdheList.length > 0) {
            let ecdheHtml = '<div class="key-list">';
            ecdheList.forEach(curve => {
                const strength = getStrengthClass(curve.nom, curve.taille);
                ecdheHtml += `
                    <div class="key-item ${strength}">
                        <span class="key-name">${curve.nom}</span>
                        <span class="key-size ${strength}">${curve.taille} bits</span>
                    </div>`;
            });
            ecdheHtml += '</div>';
            DOM.content.keyEcdhe.innerHTML = ecdheHtml;
            if (ecdheCard) ecdheCard.style.display = '';
        } else {
            if (ecdheCard) ecdheCard.style.display = 'none';
        }

        let otherHtml = '';
        const keysToProcess = [
            { id: 'dhe', label: 'DHE', data: data.dhe },
            { id: 'dh', label: 'DH', data: data.dh },
            { id: 'rsa', label: 'RSA', data: data.rsa }
        ];

        keysToProcess.forEach(item => {
            if (item.data && typeof item.data === 'object') {
                const size = item.data.taille;
                if (size !== undefined) {
                    const strength = getStrengthClass(item.label, size);
                    otherHtml += `
                        <div class="key-item ${strength}">
                            <span class="key-name">${item.label}</span>
                            <span class="key-size ${strength}">${size} bits</span>
                        </div>`;
                }
            }
        });

        ['dh_anon', 'ecdh_anon', 'rsa_export', 'null'].forEach(key => {
            if (data[key]) {
                otherHtml += `
                    <div class="key-item insecure">
                        <span class="key-name">${key.replace('_', ' ').toUpperCase()}</span>
                        <span class="key-size insecure">VULNÉRABLE</span>
                    </div>`;
            }
        });

        if (otherHtml !== '') {
            DOM.content.keyOther.innerHTML = '<div class="key-list">' + otherHtml + '</div>';
            if (otherCard) otherCard.style.display = '';
        } else {
            if (otherCard) otherCard.style.display = 'none';
        }

        if (data.ecdh && typeof data.ecdh === 'object' && data.ecdh.taille) {
            const ecdh = data.ecdh;
            const strength = getStrengthClass(ecdh.nom, ecdh.taille);
            DOM.content.keyEcdh.innerHTML = `
                <div class="key-list">
                    <div class="key-item ${strength}">
                        <span class="key-name">${ecdh.nom || 'ECDH'}</span>
                        <span class="key-size ${strength}">${ecdh.taille} bits</span>
                    </div>
                </div>`;
            if (ecdhCard) ecdhCard.style.display = '';
        } else {
            if (ecdhCard) ecdhCard.style.display = 'none';
        }

        const section = DOM.content.keyEcdhe.closest('.section');
        if (section) {
            const hasData = (ecdheList.length > 0 || otherHtml !== '' || (data.ecdh && data.ecdh.taille));
            section.style.display = hasData ? '' : 'none';
        }
    },

    // ─── COMPATIBILITÉ OS ────────────────────────────────────────
    renderCompat(data) {
        const COMPAT_LIMIT = 6;

        if (!Array.isArray(data) || data.length === 0) {
            DOM.content.compat.innerHTML = '<p style="color:var(--color-text-muted)">Aucune donnée</p>';
            return;
        }

        let compatibles = data.filter(item => item.compatible === true);
        let incompatibles = data.filter(item => item.compatible === false);

        let html = '';

        html += `<div class="compat-summary">
                    <div class="compat-stat">
                        <div class="compat-stat-value">${compatibles.length}</div>
                        <div class="compat-stat-label">Compatible</div>
                    </div>
                    <div class="compat-stat">
                        <div class="compat-stat-value">${incompatibles.length}</div>
                        <div class="compat-stat-label">Incompatible</div>
                    </div>
                    <div class="compat-stat">
                        <div class="compat-stat-value">${data.length}</div>
                        <div class="compat-stat-label">Total</div>
                    </div>
                 </div>`;

        const buildCompatGroup = (list, cls, icon, label, gridId) => {
            if (list.length === 0) return '';
            const hasMore = list.length > COMPAT_LIMIT;
            const remaining = list.length - COMPAT_LIMIT;
            let out = `<div class="subsection-title" style="margin-top:1.5rem">${label}</div>`;
            out += `<div class="compat-grid" id="${gridId}">`;
            list.forEach((client, i) => {
                const hidden = hasMore && i >= COMPAT_LIMIT ? ' compat-hidden is-overflow' : '';
                out += `<div class="compat-item ${cls}${hidden}">
                            <span class="compat-icon">${icon}</span>
                            <span class="compat-name">${client.nom}</span>
                        </div>`;
            });
            out += `</div>`;
            if (hasMore) {
                out += `<button class="show-more-btn" data-target="${gridId}" data-remaining="${remaining}">
                    Voir ${remaining} client${remaining > 1 ? 's' : ''} supplémentaire${remaining > 1 ? 's' : ''}
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 4l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </button>`;
            }
            return out;
        };

        html += buildCompatGroup(compatibles, 'compatible', '✓', 'Clients Compatibles', 'compat-ok');
        html += buildCompatGroup(incompatibles, 'incompatible', '✗', 'Clients Incompatibles', 'compat-ko');

        DOM.content.compat.innerHTML = html;

        DOM.content.compat.querySelectorAll('.show-more-btn').forEach(btn => {
            btn.addEventListener('click', () => this._toggleShowMore(btn));
        });
    },

    // ─── PORTS ───────────────────────────────────────────────────
    renderPorts(data) {
        let portsHtml = '';

        if (data.donnees && typeof data.donnees === 'object') {
            portsHtml = '<div class="ports-list">';

            Object.keys(data.donnees).forEach(port => {
                const portInfo = data.donnees[port];
                const etat = portInfo.etat || 'unknown';
                const service = portInfo.service || '-';

                let etatClass = 'unknown';
                let etatLabel = etat;
                let icon = '⚪';

                if (etat === 'open') {
                    etatClass = 'open';
                    etatLabel = 'Ouvert';
                    icon = '🔵'; 
                } else if (etat === 'closed') {
                    etatClass = 'closed';
                    etatLabel = 'Fermé';
                    icon = '⚫'; 
                } else if (etat === 'filtered') {
                    etatClass = 'filtered';
                    etatLabel = 'Filtré';
                    icon = '🟡';
                }

                portsHtml += `
                    <div class="port-item ${etatClass}">
                        <div class="port-info">
                            <span class="port-icon">${icon}</span>
                            <div>
                                <div class="port-number">Port ${port}</div>
                                <div class="port-service">${service}</div>
                            </div>
                        </div>
                        <span class="port-badge ${etatClass}">${etatLabel}</span>
                    </div>
                `;
            });

            portsHtml += '</div>';
        } else {
            portsHtml = '<p style="color:var(--color-text-muted)">Aucune donnée</p>';
        }

        DOM.content.ports.innerHTML = portsHtml;

        let statusHtml = '';

        const typeScan = data.type_scan || (DOM.scanTypeBadge.textContent.includes('complète') ? 'Complet (TCP/Syn)' : 'Standard (TCP Connect)');
        statusHtml += infoRow('Type de scan', badge(typeScan, 'info'));

        if (data.titre || data.statut) {
            const statut = data.statut || 'Unknown';
            let statutClass = 'unknown';

            if (statut.toLowerCase().includes('sécurisé') || statut.toLowerCase() === 'ok') {
                statutClass = 'safe';
            } else if (statut.toLowerCase().includes('vulnérable') || statut.toLowerCase().includes('danger')) {
                statutClass = 'unsafe';
            } else if (statut.toLowerCase().includes('attention') || statut.toLowerCase().includes('warning')) {
                statutClass = 'weak';
            } else {
                statutClass = 'info';
            }

            statusHtml += infoRow('Statut global', badge(statut, statutClass));
        }

        if (data.commentaires && Array.isArray(data.commentaires) && data.commentaires.length > 0) {
            statusHtml += '<div class="subsection-title" style="margin-top: 1rem;">Commentaires</div>';
            statusHtml += '<div class="ports-comments">';
            data.commentaires.forEach(comment => {
                let commentClass = 'info';
                if (comment.toLowerCase().includes('alerte') || comment.toLowerCase().includes('majeure')) {
                    commentClass = 'danger';
                } else if (comment.toLowerCase().includes('assurez-vous') || comment.toLowerCase().includes('attention')) {
                    commentClass = 'warning';
                }
                statusHtml += `<div class="port-comment ${commentClass}">${comment}</div>`;
            });
            statusHtml += '</div>';
        }

        if (!statusHtml) {
            statusHtml = '<p style="color:var(--color-text-muted)">Aucune donnée</p>';
        }

        DOM.content.portsStatus.innerHTML = statusHtml;
    },

    // ─── SHOW MORE / LESS toggle ─────────────────────────────────
    _toggleShowMore(btn) {
        const targetId = btn.dataset.target;
        const container = document.getElementById(targetId);
        if (!container) return;

        const hiddenClass = container.classList.contains('compat-grid') ? 'compat-hidden' : 'cipher-hidden';

        const overflowItems = container.querySelectorAll('.is-overflow');
        const isExpanded = btn.dataset.expanded === 'true';

        if (!isExpanded) {
            overflowItems.forEach(el => el.classList.remove(hiddenClass));
            btn.dataset.expanded = 'true';
            btn.innerHTML = `Réduire
                <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 8l4-4 4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
        } else {
            overflowItems.forEach(el => el.classList.add(hiddenClass));
            btn.dataset.expanded = 'false';
            const remaining = btn.dataset.remaining;
            const isCipher = hiddenClass === 'cipher-hidden';
            const word = isCipher ? 'suite' : 'client';
            btn.innerHTML = `Voir ${remaining} ${word}${remaining > 1 ? 's' : ''} supplémentaire${remaining > 1 ? 's' : ''}
                <svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2 4l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
        }
    },

    // ─── VULNÉRABILITÉS ──────────────────────────────────────────
    renderVuln(data) {
        let html = '<div class="vuln-grid">';

        if (data.heartbleed && Object.keys(data.heartbleed).length > 0) {
            const hb = data.heartbleed;
            const badgeClass = hb.vulnerable ? 'unsafe' : 'safe';
            const badgeText = hb.vulnerable ? 'Vulnérable' : 'Non vulnérable';

            html += `<div class="vuln-item ${badgeClass}">
                        <div class="vuln-info">
                            <div>
                                <div class="vuln-name">Heartbleed ${hb.cve ? `<small style="color:var(--color-text-muted)">${hb.cve}</small>` : ''}</div>
                                ${hb.description ? `<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.25rem">${hb.description}</div>` : ''}
                                ${hb.recommandation ? `<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.25rem"><strong>Recommandation:</strong> ${hb.recommandation}</div>` : ''}
                            </div>
                        </div>
                        <span class="badge ${badgeClass}">${badgeText}</span>
                     </div>`;
        }

        if (data.hsts && Object.keys(data.hsts).length > 0) {
            const hsts = data.hsts;
            const badgeClass = hsts.present ? 'safe' : 'unsafe';
            const badgeText = hsts.present ? 'Activé' : 'Manquant';

            let hstsDetails = '';
            if (hsts.present) {
                hstsDetails = '<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.25rem">';
                if (hsts.header) hstsDetails += `Header: ${hsts.header}<br>`;
                if (hsts.max_age !== undefined) hstsDetails += `Max-Age: ${hsts.max_age} | `;
                if (hsts.include_subdomains !== undefined) hstsDetails += `SubDomains: ${hsts.include_subdomains ? 'Oui' : 'Non'} | `;
                if (hsts.preload !== undefined) hstsDetails += `Preload: ${hsts.preload ? 'Oui' : 'Non'}`;
                hstsDetails += '</div>';
            }

            let hstsRecommandations = '';
            if (hsts.recommandations && Array.isArray(hsts.recommandations) && hsts.recommandations.length > 0) {
                hstsRecommandations = '<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.25rem"><strong>Recommandations:</strong><br>';
                hsts.recommandations.forEach(rec => {
                    hstsRecommandations += `• ${rec}<br>`;
                });
                hstsRecommandations += '</div>';
            }

            html += `<div class="vuln-item ${badgeClass}">
                        <div class="vuln-info">
                            <div>
                                <div class="vuln-name">HSTS</div>
                                ${hstsDetails}
                                ${hstsRecommandations}
                            </div>
                        </div>
                        <span class="badge ${badgeClass}">${badgeText}</span>
                     </div>`;
        }

        if (data.config && Array.isArray(data.config.vulnerabilites) && data.config.vulnerabilites.length > 0) {
            data.config.vulnerabilites.forEach(v => {
                const textBadge = v.severite || (v.vulnerable ? 'Vulnérable' : 'Non vulnérable');
                const textLower = textBadge.toLowerCase();

                let badgeClass = 'unsafe'; 

                if (v.vulnerable === false || textLower.includes('pas vulnérable') || textLower.includes('non vulnérable') || textLower === 'ok') {
                    badgeClass = 'safe';
                }
                else if (textLower.includes('moyenne') || textLower.includes('faible') || textLower.includes('attention')) {
                    badgeClass = 'weak';
                }

                let detailsHtml = '';
                if (v.description) detailsHtml += `<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.3rem">${v.description}</div>`;
                if (v.details) detailsHtml += `<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.25rem"><strong>Détails:</strong> ${v.details}</div>`;
                if (v.recommandation) detailsHtml += `<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.25rem"><strong>Recommandation:</strong> ${v.recommandation}</div>`;

                if (v.ciphers_affectes && Array.isArray(v.ciphers_affectes) && v.ciphers_affectes.length > 0) {
                    const uniqueCiphers = [...new Set(v.ciphers_affectes)]; 
                    detailsHtml += `<div style="font-size:0.8rem;color:var(--color-text-muted);margin-top:0.25rem"><strong>Ciphers affectés:</strong>
                        <ul style="margin: 0.2rem 0 0 1rem; padding: 0;">`;
                    uniqueCiphers.forEach(cipher => {
                        detailsHtml += `<li>${cipher}</li>`;
                    });
                    detailsHtml += `</ul></div>`;
                }

                html += `<div class="vuln-item ${badgeClass}">
                            <div class="vuln-info">
                                <div>
                                    <div class="vuln-name">${v.nom || 'Vulnérabilité'} ${v.cve && v.cve !== 'N/A' ? `<small style="color:var(--color-text-muted)">${v.cve}</small>` : ''}</div>
                                    ${detailsHtml}
                                </div>
                            </div>
                            <span class="badge ${badgeClass}">${textBadge}</span>
                         </div>`;
            });
        }

        html += '</div>';
        DOM.content.vuln.innerHTML = html;

        if (data.resume && DOM.content.vulnResume) {
            const r = data.resume;
            let resumeHtml = '';

            const sev = r.severite_globale || '-';
            let sevCls = 'safe';
            if (sev === 'OK' || sev === 'EXCELLENT' || sev === 'PAS VULNÉRABLE') {
                sevCls = 'safe';
            } else if (sev === 'CRITIQUE' || sev === 'HAUTE' || sev === 'ÉLEVÉE') {
                sevCls = 'unsafe';
            } else {
                sevCls = 'weak'; 
            }
            resumeHtml += infoRow('Sévérité globale', badge(sev, sevCls));

            resumeHtml += infoRow('Total vulnérabilités', r.nombre_vulnerabilites || 0);

            const critiques = r.vulnerabilites_critiques || [];
            resumeHtml += infoRow('Critiques', critiques.length);
            if (critiques.length > 0) {
                resumeHtml += '<div style="margin-left:1rem;margin-top:0.5rem;font-size:0.85rem">';
                critiques.forEach(c => {
                    resumeHtml += `<div style="color:var(--color-danger);margin-bottom:0.25rem">• ${typeof c === 'object' ? c.nom : c}</div>`;
                });
                resumeHtml += '</div>';
            }

            const hautes = r.vulnerabilites_hautes || [];
            resumeHtml += infoRow('Hautes', hautes.length);
            if (hautes.length > 0) {
                resumeHtml += '<div style="margin-left:1rem;margin-top:0.5rem;font-size:0.85rem">';
                hautes.forEach(h => {
                    resumeHtml += `<div style="color:var(--color-danger);margin-bottom:0.25rem">• ${typeof h === 'object' ? h.nom : h}</div>`;
                });
                resumeHtml += '</div>';
            }

            const moyennes = r.vulnerabilites_moyennes || [];
            resumeHtml += infoRow('Moyennes', moyennes.length);
            if (moyennes.length > 0) {
                resumeHtml += '<div style="margin-left:1rem;margin-top:0.5rem;font-size:0.85rem">';
                moyennes.forEach(m => {
                    resumeHtml += `<div style="color:var(--color-warning);margin-bottom:0.25rem">• ${typeof m === 'object' ? m.nom : m}</div>`;
                });
                resumeHtml += '</div>';
            }

            const faibles = r.vulnerabilites_faibles || [];
            resumeHtml += infoRow('Faibles', faibles.length);
            if (faibles.length > 0) {
                resumeHtml += '<div style="margin-left:1rem;margin-top:0.5rem;font-size:0.85rem">';
                faibles.forEach(f => {
                    resumeHtml += `<div style="color:var(--color-warning);margin-bottom:0.25rem">• ${typeof f === 'object' ? f.nom : f}</div>`;
                });
                resumeHtml += '</div>';
            }

            const avertissements = data.avertissements || r.avertissements || [];
            resumeHtml += infoRow('Avertissements', avertissements.length);

            if (avertissements.length > 0) {
                resumeHtml += '<div style="margin-left:1rem;margin-top:0.5rem;font-size:0.85rem">';
                avertissements.forEach(a => {
                    if (typeof a === 'object' && a !== null) {
                        resumeHtml += `<div style="color:var(--color-info);margin-bottom:0.4rem">
                            <strong>• ${a.nom || 'Avertissement'}</strong><br>
                            <span style="opacity: 0.8">${a.description || ''}</span>
                        </div>`;
                    }
                    else {
                        resumeHtml += `<div style="color:var(--color-info);margin-bottom:0.25rem">• ${a}</div>`;
                    }
                });
                resumeHtml += '</div>';
            }

            DOM.content.vulnResume.innerHTML = resumeHtml;
        }
    }
};

// ─── App / SSE ───────────────────────────────────────────────────

const App = {
    eventSource: null,

    runScan() {
        const domain = DOM.input.value.trim();
        const port = DOM.portInput?.value || 443;
        const scanType = this.selectedScanType || 'rapide';

        if (!domain) { alert("Veuillez entrer un domaine"); return; }

        if (domain.length > 253) {
            alert("Nom de domaine invalide (trop long).");
            return;
        }

        if (this.eventSource) this.eventSource.close();

        UI.resetDashboard(domain, port, scanType);

        setTimeout(() => {
            DOM.dashboard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);

        DOM.portWarning.classList.add('hidden');
        DOM.statusBar.style.display = '';
        const summaryGrid = document.querySelector('.summary-grid');
        const dataSections = document.querySelector('.data-sections');
        if (summaryGrid) summaryGrid.style.display = '';
        if (dataSections) dataSections.style.display = '';

        const url = `/analyse?fqdn=${encodeURIComponent(domain)}&port=${port}&scan=${scanType}`;
        this.eventSource = new EventSource(url);

        this.eventSource.onmessage = (event) => {
            let response;
            try {
                response = JSON.parse(event.data);
            }
            catch (e) {
                return;
            }

            if (response.success === false) {

                DOM.portWarning.classList.remove('hidden');

                const warningContent = DOM.portWarning.querySelector('.port-warning-content');
                if (warningContent) {
                    const errorText = response.data.toLowerCase();
                    let title = "Échec de l'analyse";

                    if (errorText.includes("invalide")) title = "Domaine ou Port invalide";
                    if (errorText.includes("https")) title = "Connexion HTTPS Impossible";

                    warningContent.innerHTML = `
                        <h3>${title}</h3>
                        <p>${response.data}</p>
                    `;
                }

                DOM.statusBar.style.display = 'none';
                if (summaryGrid) summaryGrid.style.display = 'none';
                if (dataSections) dataSections.style.display = 'none';

                this.eventSource.close();
                return;
            }

            if (response.finished === false) {
                const msg = response.data || '';
                if (msg.includes('Initialisation')) UI.setProgress(30, msg);
                else if (msg.includes('Lancement')) UI.setProgress(60, msg);
                else if (msg.includes('Recuperation')) UI.setProgress(85, msg);
                else UI.setProgress(50, msg);
                return;
            }

            this.eventSource.close();

            const data = response?.data;
            const rapport = data?.rapport;
            const notes = data?.note;

            if (!rapport) {
                UI.setError("Structure JSON inattendue");
                return;
            }

            UI.renderAll(rapport, notes);
        };

        this.eventSource.onerror = (err) => {
            UI.setError("Connexion au serveur perdue");
            this.eventSource.close();
        };
    },

    init() {
        this.selectedScanType = 'rapide';
        document.querySelectorAll('.scan-type-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.scan-type-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.selectedScanType = btn.dataset.type;
            });
        });

        DOM.btnScan.addEventListener('click', () => this.runScan());
        DOM.input.addEventListener('keypress', e => { if (e.key === 'Enter') this.runScan(); });

        DOM.btnNew.addEventListener('click', () => {
            if (this.eventSource) this.eventSource.close();
            DOM.dashboard.classList.add('hidden');
            DOM.hero.classList.remove('hidden');
            DOM.input.value = '';
        });

        DOM.examples.forEach(btn => {
            btn.addEventListener('click', () => {
                DOM.input.value = btn.dataset.domain;
                this.runScan();
            });
        });
        window.addEventListener('scroll', () => {
            if (window.scrollY > 400) {
                DOM.btnTop.classList.remove('hidden');
            } else {
                DOM.btnTop.classList.add('hidden');
            }
        });

        DOM.btnTop.addEventListener('click', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });

        const inlineTopBtn = document.getElementById('back-to-top-inline-btn');
        if (inlineTopBtn) {
            inlineTopBtn.addEventListener('click', () => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        }
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.summary-card[data-target]').forEach(card => {
        const handler = () => {
            const targetId = card.dataset.target;
            const target = document.getElementById(targetId);
            if (!target) return;
            const y = target.getBoundingClientRect().top + window.scrollY - 24;
            window.scrollTo({ top: y, behavior: 'smooth' });
        };
        card.addEventListener('click', handler);
        card.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handler(); }
        });
    });
});