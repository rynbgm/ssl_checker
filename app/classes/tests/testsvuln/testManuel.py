from __future__ import annotations
import socket
# Pas de point ici non plus car on est dans le même dossier
from test_global import TestGlobal

def tester_google():
    print("🚀 Démarrage du test Sprint 1 (Dossier Plat)...")
    domain = "www.youtube.com"
    
    try:
        # On trouve l'IP
        ip = socket.gethostbyname(domain)
        print(f"📡 Cible : {domain} ({ip})")

        # On lance le test
        scanner = TestGlobal(domain, 443, ip)
        resultats = scanner.lancer_les_tests()

        # On affiche le résultat
        print("\n📊 RÉSULTATS :")
        
        # HSTS
        hsts = resultats['vulnerabilites']['hsts']
        if hsts['present']:
            print(f"✅ HSTS : PRÉSENT (Bravo !)")
            if hsts.get('header'):
                print(f"   Header : {hsts['header'][:50]}...")
            else:
                print(f"   Info : Domaine dans la HSTS Preload List (pas besoin de header)")
        else:
            print(f"❌ HSTS : ABSENT")

        # Heartbleed (Mock)
        hb = resultats['vulnerabilites']['heartbleed']
        print(f"✅ Heartbleed (Mock) : {hb['severite']}")

    except Exception as e:
        print(f"❌ ERREUR : {e}")

if __name__ == "__main__":
    tester_google()