import datetime
import json
import os
import requests
import socket
import socks
from rich.console import Console

console = Console()
from rich.console import Console

console = Console()

CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'config.json')

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
            test_ip = session.get("http://httpbin.org/ip", timeout=20).json()['origin']
            log_message('+', f"Connexion via TOR réussie. IP externe : {test_ip}")
        except Exception as e:
            log_message('-', "La connexion au proxy TOR sur le port 9150 a échoué.")
            raise Exception(f"Assurez-vous que le Navigateur Tor est lancé et que votre pare-feu ne bloque pas la connexion. Erreur: {e}") from e
    return session

def create_socket(use_tor):
    if use_tor:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9150)
        return s
    else:
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)