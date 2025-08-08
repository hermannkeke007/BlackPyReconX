import datetime
import json
import os
import requests
import socket
import socks
from rich.console import Console

console = Console()

CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'config.json')
OUTPUTS_BASE_DIR = os.path.join(os.path.dirname(__file__), '..', 'outputs')

# Variable globale pour stocker le répertoire de session actuel
current_session_dir = None

def log_message(level: str, message: str):
    """
    Affiche un message de log formaté avec rich.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    level_map = {
        '+': ("[bold green][+][/bold green]", "green"),
        '-': ("[bold red][-][/bold red]", "red"),
        '*': ("[bold blue][*][/bold blue]", "blue"),
        '!': ("[bold yellow][!][/bold yellow]", "yellow")
    }
    icon, color = level_map.get(level, ("", ""))
    console.print(f"{icon} {now} - {message}")

def load_config():
    """Charge la configuration depuis config.json."""
    if not os.path.exists(CONFIG_FILE):
        return {"use_tor": False}
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"use_tor": False}

def save_config(config_data):
    """Sauvegarde la configuration dans config.json."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)

def get_requests_session(force_tor=None):
    """
    Crée et retourne une session `requests` configurée pour utiliser TOR.
    """
    config = load_config()
    use_tor = force_tor if force_tor is not None else config.get('use_tor', False)

    session = requests.session()
    if use_tor:
        log_message('*', "Utilisation de TOR activée. Tentative de connexion via le proxy...")
        proxies = {
            'http': 'socks5h://127.0.0.1:9150', # Port par défaut du Tor Browser
            'https': 'socks5h://127.0.0.1:9150'
        }
        session.proxies = proxies
        try:
            response = session.get("https://httpbin.org/ip", timeout=20)
            response.raise_for_status() # Lève une exception pour les codes d'erreur HTTP
            test_ip = response.json().get('origin')
            if test_ip:
                log_message('+', f"Connexion via TOR réussie. Adresse IP publique de Tor : [bold yellow]{test_ip}[/bold yellow]")
                # Sauvegarder l'IP dans le statut
                try:
                    with open(os.path.join(os.path.dirname(__file__), '..', 'status.json'), 'r+') as f:
                        status_data = json.load(f)
                        status_data['tor_ip'] = test_ip
                        f.seek(0)
                        json.dump(status_data, f, indent=4)
                        f.truncate()
                except (FileNotFoundError, json.JSONDecodeError):
                    with open(os.path.join(os.path.dirname(__file__), '..', 'status.json'), 'w') as f:
                        json.dump({'tor_ip': test_ip}, f, indent=4)
            else:
                log_message('!', "Impossible de vérifier l'IP publique de Tor, mais le proxy est actif.")
        except requests.exceptions.HTTPError as e:
            log_message('!', f"Le service de vérification d'IP a retourné une erreur (ce qui est courant avec Tor). Le proxy est probablement fonctionnel. Erreur: {e}")
        except requests.exceptions.RequestException as e:
            log_message('-', f"La connexion au proxy TOR sur le port 9150 a échoué. Assurez-vous que le Navigateur Tor est lancé. Erreur: {e}")
            raise
    return session

def create_socket(use_tor):
    if use_tor:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9150)
        return s
    else:
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_current_session_dir():
    """
    Retourne le chemin du répertoire de la session actuelle.
    Crée un nouveau répertoire si aucune session n'est active.
    """
    global current_session_dir
    if current_session_dir is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_name = f"session_{timestamp}"
        current_session_dir = os.path.join(OUTPUTS_BASE_DIR, session_name)
        os.makedirs(current_session_dir, exist_ok=True)
        log_message('*', f"Nouvelle session de scan démarrée : {current_session_dir}")
    return current_session_dir

def reset_session_dir():
    """
    Réinitialise le répertoire de session, forçant la création d'un nouveau pour le prochain scan.
    """
    global current_session_dir
    current_session_dir = None
