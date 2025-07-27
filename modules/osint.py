import requests
import json
import os
import threading
from dotenv import load_dotenv

load_dotenv()

# La session sera injectée par main.py
session = None

def get_api_keys():
    return os.getenv('SHODAN_API_KEY'), os.getenv('ABUSEIPDB_API_KEY')

# --- Fonctions pour chaque API (pour le parallélisme) ---

def fetch_ipinfo(target, results_dict):
    try:
        response = session.get(f"https://ipinfo.io/{target}/json", timeout=10)
        response.raise_for_status()
        results_dict['ipinfo'] = f"--- IPINFO.IO ---\n{json.dumps(response.json(), indent=2)}\n"
    except requests.exceptions.RequestException as e:
        results_dict['ipinfo'] = f"--- IPINFO.IO ---\nErreur: {e}\n"

def fetch_ipapi(target, results_dict):
    try:
        response = session.get(f"http://ip-api.com/json/{target}", timeout=10)
        response.raise_for_status()
        results_dict['ipapi'] = f"--- IP-API.COM ---\n{json.dumps(response.json(), indent=2)}\n"
    except requests.exceptions.RequestException as e:
        results_dict['ipapi'] = f"--- IP-API.COM ---\nErreur: {e}\n"

def fetch_abuseipdb(target, api_key, results_dict):
    if not api_key or api_key == "VOTRE_CLE_API_ABUSEIPDB":
        results_dict['abuseipdb'] = "--- ABUSEIPDB.COM ---\nClé API non configurée.\n"
        return
    try:
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': target, 'maxAgeInDays': '90'}
        response = session.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
        response.raise_for_status()
        results_dict['abuseipdb'] = f"--- ABUSEIPDB.COM ---\n{json.dumps(response.json(), indent=2)}\n"
    except requests.exceptions.RequestException as e:
        results_dict['abuseipdb'] = f"--- ABUSEIPDB.COM ---\nErreur: {e}\n"

def fetch_shodan(target, api_key, results_dict):
    if not api_key or api_key == "VOTRE_CLE_API_SHODAN":
        results_dict['shodan'] = "--- SHODAN.IO ---\nClé API non configurée.\n"
        return
    try:
        response = session.get(f"https://api.shodan.io/shodan/host/{target}?key={api_key}", timeout=10)
        response.raise_for_status()
        results_dict['shodan'] = f"--- SHODAN.IO ---\n{json.dumps(response.json(), indent=2)}\n"
    except requests.exceptions.RequestException as e:
        results_dict['shodan'] = f"--- SHODAN.IO ---\nErreur: {e}\n"

def run(target):
    if session is None:
        raise Exception("La session de requêtes n'a pas été initialisée.")

    shodan_api_key, abuseipdb_api_key = get_api_keys()
    
    results = {}
    threads = []

    # Créer et lancer les threads pour chaque appel API
    tasks = [
        (fetch_ipinfo, (target, results)),
        (fetch_ipapi, (target, results)),
        (fetch_abuseipdb, (target, abuseipdb_api_key, results)),
        (fetch_shodan, (target, shodan_api_key, results))
    ]

    for func, args in tasks:
        thread = threading.Thread(target=func, args=args, daemon=True)
        threads.append(thread)
        thread.start()

    # Attendre que tous les threads soient terminés
    for thread in threads:
        thread.join()

    # Assembler les résultats dans l'ordre souhaité
    final_results = (
        results.get('ipinfo', '') +
        results.get('ipapi', '') +
        results.get('abuseipdb', '') +
        results.get('shodan', '')
    )

    output_path = os.path.join(os.path.dirname(__file__), '..', 'outputs', 'osint.txt')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(final_results)

    print(f"[+] Résultats OSINT enregistrés dans {output_path}")
