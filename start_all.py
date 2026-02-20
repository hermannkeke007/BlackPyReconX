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
import os
from modules import utils # Import utils

# --- INSTRUCTIONS POUR L'ENVIRONNEMENT VIRTUEL (VENV) ---
# Il est FORTEMENT recommandé d'utiliser un environnement virtuel Python (venv)
# pour ce projet afin d'isoler ses dépendances et éviter les conflits.
# Si vous n'avez pas encore configuré votre venv, veuillez suivre ces étapes :
#
# 1.  Créez l'environnement virtuel (si ce n'est pas déjà fait) :
#     Sur Windows/macOS/Linux : python -m venv venv
#
# 2.  Activez l'environnement virtuel :
#     Sur Windows : venv\Scripts\activate
#     Sur macOS/Linux : source venv/bin/activate
#
# Une fois activé, l'installation des dépendances (gérée automatiquement)
# se fera dans cet environnement. Vous saurez que le venv est actif si
# "(venv)" apparaît au début de votre ligne de commande.
# --------------------------------------------------------

# --- CONFIGURATION ---
STATUS_FILE = 'status.json'
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json') # Path to config.json
INSTALL_MARKER_FILE = '.first_run_done'

# Déterminer le chemin vers les exécutables Python et Flask de l'environnement virtuel
VENV_PATH = os.path.join(os.path.dirname(__file__), 'venv')
PYTHON_EXECUTABLE = os.path.join(VENV_PATH, 'Scripts', 'python.exe') if sys.platform == 'win32' else os.path.join(VENV_PATH, 'bin', 'python')
FLASK_EXECUTABLE = os.path.join(VENV_PATH, 'Scripts', 'flask.exe') if sys.platform == 'win32' else os.path.join(VENV_PATH, 'bin', 'flask')

# Fallback si l'environnement virtuel n'est pas trouvé ou structuré différemment
if not os.path.exists(PYTHON_EXECUTABLE):
    PYTHON_EXECUTABLE = sys.executable # Utiliser l'interpréteur Python actuel
    print("[!] Avertissement: Environnement virtuel 'venv' non trouvé ou structure inattendue. Utilisation de l'interpréteur Python actuel. Assurez-vous que Flask est installé globalement ou que vous exécutez 'start_all.py' depuis un environnement virtuel activé.")
if not os.path.exists(FLASK_EXECUTABLE):
    # Si 'flask.exe' n'est pas directement présent, on utilise 'python -m flask'
    # mais en s'assurant que le bon interpréteur Python est utilisé.
    FLASK_COMMAND_PREFIX = [PYTHON_EXECUTABLE, "-m", "flask"]
else:
    FLASK_COMMAND_PREFIX = [FLASK_EXECUTABLE]

# --- Installation des dépendances si c'est la première exécution ---
if not os.path.exists(INSTALL_MARKER_FILE):
    print("[*] Première exécution détectée. Installation des dépendances...")
    try:
        subprocess.check_call([PYTHON_EXECUTABLE, "-m", "pip", "install", "-r", "requirements.txt"], stdout=sys.stdout, stderr=sys.stderr)
        with open(INSTALL_MARKER_FILE, 'w') as f:
            f.write("Dependencies installed on " + time.ctime())
        print("[+] Dépendances installées avec succès.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Erreur lors de l'installation des dépendances: {e}")
        print("[-] Veuillez installer manuellement les dépendances en exécutant : pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Une erreur inattendue est survenue lors de l'installation des dépendances: {e}")
        sys.exit(1)
else:
    print("[*] Dépendances déjà installées. Démarrage du framework...")


def set_bot_status(status: str):
    """Écrit le statut du bot dans le fichier d'état."""
    # Ensure STATUS_FILE exists before writing
    status_path = os.path.join(os.path.dirname(__file__), STATUS_FILE)
    with open(status_path, 'w') as f:
        json.dump({"bot_status": status}, f)

# --- SCRIPT PRINCIPAL ---
def main():
    processes = []
    
    config = utils.load_config()
    api_keys = config.get('api_keys', {})
    required_keys = ['shodan', 'abuseipdb', 'telegram_bot_token', 'telegram_chat_id']
    
    is_configured = True
    for key in required_keys:
        if not api_keys.get(key):
            is_configured = False
            break

    if not is_configured:
        print("[!] Clés API non configurées. Lancement de l'interface web pour la configuration initiale.")
        print("[*] Veuillez ouvrir votre navigateur et accéder à http://127.0.0.1:5000 pour configurer les clés API.")
        print("\n[!] Pour utiliser les fonctionnalités de Tor (anonymisation du trafic), assurez-vous d'avoir téléchargé, exécuté et connecté [Tor Browser](https://www.torproject.org/download/). Il doit être en cours d'exécution pour que le framework puisse utiliser le réseau Tor.")
        
        web_command = FLASK_COMMAND_PREFIX + ["--app", "app", "run"] # Removed debug flag here
        proc = subprocess.Popen(web_command)
        processes.append(proc)
        
        print("\n[!] L'application attend la configuration des clés API via l'interface web.")
        print("[*] Une fois configurées, le bot Telegram et le CLI seront également fonctionnels.")
        print("\nAppuyez sur Ctrl+C pour arrêter le serveur web.")

    else:
        print("[+] Clés API configurées. Lancement de l'interface web et du bot Telegram.")
        print("[*] Le bot Telegram et le CLI sont prêts à fonctionner avec les clés configurées.")
        
        commands = {
            "Interface Web (Flask)": FLASK_COMMAND_PREFIX + ["--app", "app", "run"], # Use simple run for production-like
            "Bot Telegram": [PYTHON_EXECUTABLE, os.path.join("modules", "telegram_bot.py")]
        }

        # Indiquer que le bot est en cours de démarrage
        set_bot_status('active')

        # Lancer chaque commande dans un nouveau processus
        for name, cmd in commands.items():
            print(f"  -> Démarrage de : {name}")
            if name == "Bot Telegram":
                bot_log_path = os.path.join(os.path.dirname(__file__), "telegram_bot.log")
                print(f"     (Les logs du bot Telegram seront écrits dans : {bot_log_path})")
                try:
                    with open(bot_log_path, "w") as bot_log_file:
                        proc = subprocess.Popen(cmd, stdout=bot_log_file, stderr=subprocess.STDOUT, text=True)
                    processes.append(proc)
                except OSError as e:
                    print(f"[-] Erreur lors du lancement du bot Telegram : {e}")
                    print("    Veuillez vous assurer que Python est correctement configuré et que l'environnement virtuel est activé.")
                    # Don't append to processes if it failed to launch
            else:
                proc = subprocess.Popen(cmd)
                processes.append(proc)
            time.sleep(2) # Give services a moment to start

        print("\n[+] Tous les services sont démarrés.")
        print("[*] L'interface web est disponible sur http://127.0.0.1:5000")
        print("[*] Le bot Telegram est en ligne.")
        print("\nAppuyez sur Ctrl+C pour tout arrêter.")

    try:
        while True:
            # Vérifier si un processus s'est terminé de manière inattendue
            for proc in processes:
                if proc.poll() is not None:
                    # If web server stops during unconfigured state, exit
                    if not is_configured and proc == processes[0]: # Assuming first process is web server
                        print("\n[!] Le serveur web s'est arrêté. Veuillez relancer 'start_all.py' si vous n'avez pas terminé la configuration.")
                        sys.exit(1)
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

if __name__ == '__main__':
    main()
