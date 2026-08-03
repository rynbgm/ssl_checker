from __future__ import annotations
from flask import Flask, Response, stream_with_context
import json
from flask import request
from typing import Any,Generator
import traceback
import validators
from classes.sslChecker import SslChecker
import socket
import ssl

def supporte_https(fqdn: str, port: int = 443, timeout: int = 3) -> bool:
    try:
        context = ssl.create_default_context() # NOSONAR
        context.check_hostname = False # NOSONAR
        context.verify_mode = ssl.CERT_NONE # NOSONAR
        with socket.create_connection((fqdn, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=fqdn):
                return True
    except Exception:
        return False

app = Flask(__name__)

@app.route('/analyse', methods=['GET'])
def analyse() -> Response:
    
    fqdn_arg: str | None = request.args.get('fqdn')
    port_arg: str | None = request.args.get('port')
    scan_arg: str | None = request.args.get('scan')

    def send_sse_error(message: str) -> Response:
        def generate_error() -> Generator[str, None, None]:
            err_body: dict[str, Any] = {
                "success": False, 
                "finished": True, 
                "data": message
            }
            yield f"data: {json.dumps(err_body)}\n\n"
        return Response(stream_with_context(generate_error()), mimetype='text/event-stream')

    if fqdn_arg is None:
        return send_sse_error("Le paramètre 'fqdn' est obligatoire.")
    
    fqdn: str = fqdn_arg

    if not validators.domain(fqdn):
        return send_sse_error("Le nom de domaine est invalide !")
    
    port: str = port_arg if port_arg is not None else "443"

    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return send_sse_error("Le port est invalide. Il doit être un nombre compris entre 1 et 65535 !")
    
    port_int = int(port)
    if not supporte_https(fqdn, port_int):
        return send_sse_error(f"Impossible de se connecter en HTTPS à {fqdn}:{port}. Le serveur ne supporte pas le TLS ou est inaccessible.")
    # faut vraiment qu'on arrete avec les mot magiques
    types_of_scan = {'rapide','complet'}
    if scan_arg not in types_of_scan:
        return send_sse_error("Mauvais type de scan choisi.")



    def generate() -> Generator[str, None, None]:
        try:

            msg_init: dict[str, Any] = {
                "success": True,
                "finished": False,
                "data": f"Démarrage de l'analyse pour {fqdn}:{port}..."
            }
            yield f"data: {json.dumps(msg_init)}\n\n"

            sc = SslChecker(fqdn, port,scan_arg)

            retour: str | dict[str, Any]

            for retour in sc.lancer():
                
                # icic c'est la  progression juste un str
                if isinstance(retour, str):
                    msg_progression: dict[str, Any] = {
                        "success": True,
                        "finished": False,
                        "data": retour
                    }
                    yield f"data: {json.dumps(msg_progression)}\n\n"
                # donc c'est le vrai res dans se cas
                else:
                    yield f"data: {json.dumps(retour)}\n\n"

        except Exception as _:
            trace = traceback.format_exc()
            print(trace, flush=True) 
            message_error : dict[str, Any] = {
                "success": False,
                "finished": True,
                "data": "Une erreur inattendue s'est produite côté serveur lors de l'analyse."
            }
            yield f"data: {json.dumps(message_error)}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)