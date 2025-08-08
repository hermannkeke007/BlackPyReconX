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
import zipfile
from datetime import datetime
from cryptography.fernet import Fernet

# Importer les outils de chiffrement du module crypto_tools
from . import crypto_tools

OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'outputs')

def zip_outputs() -> str:
    """Compresse le contenu du dossier outputs dans une archive ZIP."""
    # S'assurer que le dossier outputs existe
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"exfiltrated_data_{timestamp}.zip"
    zip_path = os.path.join(OUTPUTS_DIR, zip_filename)

    print(f"[*] Compression des données dans {zip_path}...")
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(OUTPUTS_DIR):
            for file in files:
                # Ne pas inclure les archives zip précédentes dans la nouvelle archive
                if file.endswith('.zip') or file.endswith('.enc'):
                    continue
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, OUTPUTS_DIR)
                zipf.write(file_path, arcname)
    
    print("[+] Compression terminée.")
    return zip_path

def encrypt_file(file_path: str) -> (str, bytes):
    """Chiffre un fichier en utilisant Fernet et retourne le chemin du fichier chiffré et la clé."""
    print(f"[*] Chiffrement de {file_path}...")
    
    # Générer une nouvelle clé pour chaque exfiltration
    key = Fernet.generate_key()
    fernet = Fernet(key)
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = fernet.encrypt(data)
        
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"[+] Fichier chiffré enregistré sous {encrypted_file_path}")
        # Sauvegarder la clé pour le rapport ou l'envoi
        key_file = os.path.join(OUTPUTS_DIR, 'encryption_key.key')
        with open(key_file, 'wb') as f:
            f.write(key)
        print(f"[+] Clé de chiffrement sauvegardée dans {key_file}")

        return encrypted_file_path, key

    except Exception as e:
        print(f"[-] Erreur lors du chiffrement : {e}")
        return None, None

# --- Fonctions d'envoi (à implémenter) ---
def send_via_telegram(file_path, key):
    print("[!] TODO: Implémenter l'envoi via Telegram.")
    # Utiliser le module telegram_bot.py pour envoyer le fichier et la clé
    pass

def send_via_webhook(file_path, key):
    print("[!] TODO: Implémenter l'envoi via Webhook.")
    # Envoyer le fichier et la clé à une URL de webhook
    pass

# --- FONCTION PRINCIPALE DU MODULE ---
def run(send_method='none'):
    """Fonction principale pour l'exfiltration."""
    print("[+] Lancement du module d'exfiltration...")
    
    # 1. Compresser les données
    zip_file_path = zip_outputs()
    if not zip_file_path or not os.path.exists(zip_file_path):
        print("[-] Échec de la compression. Arrêt de l'exfiltration.")
        return

    # 2. Chiffrer l'archive
    encrypted_path, encryption_key = encrypt_file(zip_file_path)
    
    # 3. Nettoyer l'archive non chiffrée
    os.remove(zip_file_path)
    print(f"[*] Archive non chiffrée {zip_file_path} supprimée.")

    if encrypted_path and encryption_key:
        # 4. Envoyer les données selon la méthode choisie
        if send_method == 'telegram':
            send_via_telegram(encrypted_path, encryption_key)
        elif send_method == 'webhook':
            send_via_webhook(encrypted_path, encryption_key)
        else:
            print("[*] Exfiltration terminée. Le fichier chiffré est prêt.")
    else:
        print("[-] Échec de l'exfiltration.")

if __name__ == '__main__':
    run()
