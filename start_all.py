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

# --- Détermination de l'exécutable Python ---
VENV_PATH = os.path.join(os.path.dirname(__file__), 'venv')
VENV_PYTHON_WIN = os.path.join(VENV_PATH, 'Scripts', 'python.exe')
VENV_PYTHON_UNIX = os.path.join(VENV_PATH, 'bin', 'python')

# Default to system python, will be updated if venv exists/is created
PYTHON_EXECUTABLE = sys.executable

# Ensure venv exists and use its python
if not (os.path.exists(VENV_PYTHON_WIN) or os.path.exists(VENV_PYTHON_UNIX)):
    print("[*] Création de l'environnement virtuel...")
    try:
        subprocess.check_call([sys.executable, "-m", "venv", VENV_PATH])
        print("[+] Environnement virtuel créé avec succès.")
        # Update PYTHON_EXECUTABLE to point to the newly created venv's python
        if sys.platform == 'win32':
            PYTHON_EXECUTABLE = VENV_PYTHON_WIN
        else:
            PYTHON_EXECUTABLE = VENV_PYTHON_UNIX
    except Exception as e:
        print(f"[-] Erreur lors de la création de l'environnement virtuel: {e}")
        print("[-] Le programme ne peut pas continuer. Assurez-vous que 'python -m venv' est disponible.")
        sys.exit(1)
else:
    # Venv already exists, set PYTHON_EXECUTABLE to it
    if sys.platform == 'win32':
        PYTHON_EXECUTABLE = VENV_PYTHON_WIN
    else:
        PYTHON_EXECUTABLE = VENV_PYTHON_UNIX

# If we are not running inside the venv, re-execute ourselves within the venv
if sys.executable != PYTHON_EXECUTABLE:
    print(f"[*] Redémarrage du script dans l'environnement virtuel: {PYTHON_EXECUTABLE} {sys.argv[0]}...")
    # Using 'call' here to wait for the new process to finish, then exit.
    # The new process will then handle the rest of the script.
    result = subprocess.run([PYTHON_EXECUTABLE, sys.argv[0]] + sys.argv[1:])
    sys.exit(result.returncode) # Exit the current process with the return code of the venv process

# --- Vérification et installation des dépendances ---
# Ce bloc est placé au début pour s'assurer que les modules sont disponibles avant leur importation.
print("[*] Installation/mise à jour des dépendances. Cela peut prendre un certain temps...")
try:
    # Utiliser --quiet pour une sortie moins verbeuse, sauf en cas d'erreur.
    # Rediriger la sortie standard vers DEVNULL pour ne pas polluer la console en cas de succès.
    subprocess.check_call([PYTHON_EXECUTABLE, "-m", "pip", "install", "-r", "requirements.txt"])
    print("[+] Les dépendances sont à jour.")
except subprocess.CalledProcessError as e:
    print(f"[-] Erreur lors de l'installation des dépendances. Pip a retourné le code {e.returncode}.")
    print("[-] Le programme ne peut pas continuer. Essayez d'exécuter 'pip install -r requirements.txt' manuellement.")
    sys.exit(1)
except Exception as e:
    print(f"[-] Une erreur inattendue est survenue lors de la vérification des dépendances: {e}")
    sys.exit(1)


# --- Importations des modules externes (APRÈS l'installation) ---
try:
    from dotenv import load_dotenv, set_key, find_dotenv
    from modules import utils
except ImportError as e:
    print(f"[-] Erreur d'importation après l'installation : {e}")
    print("[-] Un module requis est manquant même après la tentative d'installation.")
    print("[-] Assurez-vous que le module est listé dans 'requirements.txt' et qu'il n'y a pas eu d'erreur ci-dessus.")
    sys.exit(1)

# Charger les variables d'environnement depuis le fichier .env
load_dotenv(find_dotenv())

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
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')

# --- Détermination de la commande Flask ---
FLASK_EXECUTABLE = os.path.join(VENV_PATH, 'Scripts', 'flask.exe') if sys.platform == 'win32' else os.path.join(VENV_PATH, 'bin', 'flask')
if not os.path.exists(FLASK_EXECUTABLE):
    FLASK_COMMAND_PREFIX = [PYTHON_EXECUTABLE, "-m", "flask"]
    if not os.path.exists(os.path.join(VENV_PATH, 'Scripts')):
         print("[!] Avertissement: Environnement virtuel 'venv' non trouvé ou structure inattendue. Utilisation de l'interpréteur Python système. Assurez-vous que Flask est installé ou que vous exécutez 'start_all.py' depuis un environnement virtuel activé.")
else:
    FLASK_COMMAND_PREFIX = [FLASK_EXECUTABLE]


def set_bot_status(status: str):
    """Écrit le statut du bot dans le fichier d'état."""
    # Ensure STATUS_FILE exists before writing
    status_path = os.path.join(os.path.dirname(__file__), STATUS_FILE)
    with open(status_path, 'w') as f:
        json.dump({"bot_status": status}, f)

# --- SCRIPT PRINCIPAL ---
def main():
    processes = []
    
    # API keys are now read from .env directly
    required_keys = ['shodan', 'abuseipdb', 'telegram_bot_token', 'telegram_chat_id']
    
    # Check initial configuration status
    initial_is_configured = True
    for key in required_keys:
        if not utils.get_api_key(key):
            initial_is_configured = False
            break

    if not initial_is_configured:
        print("\n" + "#" * 70)
        print("[!] --- CONFIGURATION DES CLÉS API ---")
        print("[!] Des clés API essentielles sont manquantes ou vides dans votre fichier '.env'.")
        print("[!] Veuillez les saisir ci-dessous pour continuer.")
        print("[!] (Les valeurs seront sauvegardées dans votre fichier '.env' localement.)")
        print("#" * 70 + "\n")

        dotenv_path = find_dotenv()
        if not dotenv_path: 
            dotenv_path = '.env'
            with open(dotenv_path, 'w') as f:
                f.write("# Environment variables for BlackPyReconX\n")
        
        for key in required_keys:
            current_value = utils.get_api_key(key)
            if not current_value:
                value = input(f"Entrez la clé API pour {key.upper()}: ")
                if value:
                    set_key(dotenv_path, key.upper(), value)
                    print(f"[+] Clé {key.upper()} sauvegardée dans .env.")
                else:
                    print(f"[-] La clé {key.upper()} n'a pas été renseignée. Le programme pourrait ne pas fonctionner correctement.")
        
        load_dotenv(find_dotenv(), override=True)
        
        is_configured = True # Re-evaluate after prompts
        for key in required_keys:
            if not utils.get_api_key(key):
                is_configured = False
                break
        
        if not is_configured: # Still not configured after prompt
            print("\n[!] Toutes les clés API requises n'ont pas été configurées. Le programme pourrait rencontrer des erreurs.")
            print("[!] Veuillez relancer le script après avoir complété le fichier .env si nécessaire.")
            sys.exit(1)
        else: # Now configured, proceed to launch
            print("\n[+] Toutes les clés API ont été configurées. Le programme va démarrer.")
        
        print("\n[!] Pour utiliser les fonctionnalités de Tor (anonymisation du trafic), assurez-vous d'avoir téléchargé, exécuté et connecté [Tor Browser](https://www.torproject.org/download/). Il doit être en cours d'exécution pour que le framework puisse utiliser le réseau Tor.")
        print("#" * 70 + "\n")
        
    else: # Initial check determined it was configured
        is_configured = True # Use this variable for the rest of the main function if needed
        print("[+] Clés API configurées. Lancement de l'interface web et du bot Telegram.")
        print("[*] Le bot Telegram et le CLI sont prêts à fonctionner avec les clés configurées.")
        
    # --- Service Launch Logic (moved outside the if/else for initial_is_configured) ---
    commands = {
        "Interface Web (Flask)": FLASK_COMMAND_PREFIX + ["--app", "app", "run"],
        "Bot Telegram": [PYTHON_EXECUTABLE, os.path.join("modules", "telegram_bot.py")]
    }

    set_bot_status('active')

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
        else:
            proc = subprocess.Popen(cmd)
            processes.append(proc)
        time.sleep(2)

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
