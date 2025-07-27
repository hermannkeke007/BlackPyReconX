import socket
import subprocess
import os
import re
import threading
from queue import Queue
from . import utils

# Liste étendue de ports courants à scanner
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080]

# Files d'attente et stockage des résultats
port_queue = Queue()
banner_queue = Queue()
open_ports_list = []
banner_results = {}



def port_scan_worker(target_ip, use_tor):
    while not port_queue.empty():
        port = port_queue.get()
        try:
            with utils.create_socket(use_tor) as s:
                timeout = 10 if use_tor else 1
                s.settimeout(timeout)
                if s.connect_ex((target_ip, port)) == 0:
                    open_ports_list.append(port)
        except (socket.error, socks.ProxyConnectionError, socks.GeneralProxyError):
            pass
        finally:
            port_queue.task_done()

def get_banner(ip, port, use_tor):
    # ... (le contenu de la fonction get_banner reste identique)
    pass # Placeholder - la fonction est longue et ne change pas

def banner_grab_worker(target_ip, use_tor):
    while not banner_queue.empty():
        port = banner_queue.get()
        banner = get_banner(target_ip, port, use_tor)
        banner_results[port] = banner
        banner_queue.task_done()

def get_os_from_ttl(ip):
    # ... (le contenu de la fonction get_os_from_ttl reste identique)
    pass # Placeholder

def run(target, use_tor=False):
    global open_ports_list, banner_results
    open_ports_list = []
    banner_results = {}

    print(f"[+] Lancement du scan sur {target}...")
    try:
        target_ip = socket.gethostbyname(target)
        print(f"[*] IP de la cible : {target_ip}")
    except socket.gaierror:
        print(f"[-] Erreur : Impossible de résoudre le nom d'hôte {target}")
        return

    results = f"--- RÉSULTATS DU SCAN POUR {target} ({target_ip}) ---\n\n"
    os_info = get_os_from_ttl(target_ip)
    results += f"[+] Détection de l'OS (via TTL) : {os_info}\n"
    try:
        rev_dns = socket.gethostbyaddr(target_ip)
        results += f"[+] Reverse DNS : {rev_dns[0]}\n"
    except socket.herror:
        results += "[+] Reverse DNS : Aucune entrée trouvée\n"
    
    results += "\n--- SCAN DE PORTS TCP ---\n"
    print("[*] Scan des ports en cours...")
    for port in COMMON_PORTS:
        port_queue.put(port)

    threads = []
    for _ in range(50): # Augmentation des threads pour le scan de ports
        thread = threading.Thread(target=port_scan_worker, args=(target_ip, use_tor,), daemon=True)
        thread.start()
        threads.append(thread)
    port_queue.join()

    open_ports_list.sort()
    if open_ports_list:
        results += "Ports ouverts :\n"
        print("[*] Récupération des bannières pour les ports ouverts...")
        for port in open_ports_list:
            banner_queue.put(port)
        
        banner_threads = []
        for _ in range(20): # Threads pour la récupération des bannières
            thread = threading.Thread(target=banner_grab_worker, args=(target_ip, use_tor,), daemon=True)
            thread.start()
            banner_threads.append(thread)
        banner_queue.join()

        for port in open_ports_list:
            banner = banner_results.get(port, "Erreur inconnue lors de la récupération.")
            results += f"  [>] Port {port}/tcp : OUVERT | Bannière : {banner}\n"
    else:
        results += "Aucun port ouvert trouvé parmi les ports courants.\n"

    output_path = os.path.join(os.path.dirname(__file__), '..', 'outputs', 'scan_results.txt')
    with open(output_path, 'w') as f:
        f.write(results)

    print(f"[+] Résultats du scan enregistrés dans {output_path}")
    print(results)
