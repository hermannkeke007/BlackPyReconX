# BlackPyReconX - Un framework d'attaque complet
# Copyright (C) 2025 Hermann KEKE
#
# Ce programme est un logiciel libre ; vous pouvez le redistribuer et/ou le
# modifier selon les termes de la Licence publique générale GNU telle que
# publiée par la Free Software Foundation ; soit la version 3 de la Licence,
# soit (à votre choix) toute version ultérieure.
#
# Ce programme est distribué dans l'espoir qu'il sera utile,
# mais SANS AUCUNE GARANTIE ; sans même la garantie implicite de
# QUALITÉ MARCHANDE ou d'ADÉQUATION À UN USAGE PARTICULIER. Voir la
# Licence publique générale GNU pour plus de détails.
#
# Vous devriez avoir reçu une copie de la Licence publique générale GNU
# avec ce programme. Si non, voir <https://www.gnu.org/licenses/>.

import subprocess
import time
import sys
import json

# --- CONFIGURATION ---
STATUS_FILE = 'status.json'

# Commandes à lancer
import os

commands = {
    "Interface Web (Flask)": [sys.executable, "-m", "flask", "--app", "app", "--debug", "run"],
    "Bot Telegram": [sys.executable, os.path.join("modules", "telegram_bot.py")]
}

processes = []

def set_bot_status(status: str):
    """Écrit le statut du bot dans le fichier d'état."""
    with open(STATUS_FILE, 'w') as f:
        json.dump({"bot_status": status}, f)

# --- SCRIPT PRINCIPAL ---
try:
    print("[*] Lancement de l'interface web et du bot Telegram...")
    
    # Indiquer que le bot est en cours de démarrage
    set_bot_status('active')

    # Lancer chaque commande dans un nouveau processus
    for name, cmd in commands.items():
        print(f"  -> Démarrage de : {name}")
        proc = subprocess.Popen(cmd)
        processes.append(proc)
        time.sleep(2)

    print("\n[+] Tous les services sont démarrés.")
    print("[*] L'interface web est disponible sur http://127.0.0.1:5000")
    print("[*] Le bot Telegram est en ligne.")
    print("\nAppuyez sur Ctrl+C pour tout arrêter.")

    while True:
        # Vérifier si un processus s'est terminé de manière inattendue
        for proc in processes:
            if proc.poll() is not None:
                print("\n[!] Un service s'est arrêté de manière inattendue. Arrêt de tous les services.")
                raise KeyboardInterrupt # Déclencher l'arrêt propre
        time.sleep(1)

except KeyboardInterrupt:
    print("\n\n[!] Interruption détectée. Arrêt de tous les services...")

finally:
    # Indiquer que le bot est arrêté, quoi qu'il arrive
    set_bot_status('inactive')
    
    for proc in processes:
        proc.terminate()
        proc.wait()
    
    print("[+] Tous les services ont été arrêtés. Au revoir !")
