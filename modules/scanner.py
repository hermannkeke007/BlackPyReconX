import socket
import subprocess
import os
import re
import threading
import time
from queue import Queue
from . import utils

# Liste étendue de ports courants à scanner
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080]

# État global du module de scan
scan_state = {
    "running": False,
    "target": None,
    "target_ip": None,
    "use_tor": False,
    "threads": [],
    "open_ports": [],
    "banners": {},
    "lock": threading.Lock(),
    "port_queue": Queue(),
    "banner_queue": Queue()
}

def port_scan_worker():
    while scan_state["running"] and not scan_state["port_queue"].empty():
        port = scan_state["port_queue"].get()
        try:
            with utils.create_socket(scan_state["use_tor"]) as s:
                timeout = 10 if scan_state["use_tor"] else 1
                s.settimeout(timeout)
                if s.connect_ex((scan_state["target_ip"], port)) == 0:
                    with scan_state["lock"]:
                        scan_state["open_ports"].append(port)
        except (socket.error, utils.socks.ProxyConnectionError, utils.socks.GeneralProxyError):
            pass
        finally:
            scan_state["port_queue"].task_done()

def get_banner(ip, port, use_tor):
    # ... (le contenu de la fonction get_banner reste identique)
    pass # Placeholder - la fonction est longue et ne change pas

def banner_grab_worker():
    while scan_state["running"] and not scan_state["banner_queue"].empty():
        port = scan_state["banner_queue"].get()
        banner = get_banner(scan_state["target_ip"], port, scan_state["use_tor"])
        with scan_state["lock"]:
            scan_state["banners"][port] = banner
        scan_state["banner_queue"].task_done()

def get_os_from_ttl(ip):
    # ... (le contenu de la fonction get_os_from_ttl reste identique)
    pass # Placeholder

def start_scan(target, use_tor=False):
    global scan_state
    with scan_state["lock"]:
        if scan_state["running"]:
            utils.log_message('!', "Un scan est déjà en cours.")
            return

        utils.log_message('*', f"Démarrage du scan sur {target}")
        scan_state["running"] = True
        scan_state["target"] = target
        scan_state["use_tor"] = use_tor
        scan_state["open_ports"] = []
        scan_state["banners"] = {}
        scan_state["threads"] = []
        scan_state["port_queue"] = Queue()
        scan_state["banner_queue"] = Queue()

    try:
        scan_state["target_ip"] = socket.gethostbyname(target)
    except socket.gaierror:
        utils.log_message('-', f"Erreur : Impossible de résoudre le nom d'hôte {target}")
        scan_state["running"] = False
        return

    for port in COMMON_PORTS:
        scan_state["port_queue"].put(port)

    for _ in range(50):
        thread = threading.Thread(target=port_scan_worker, daemon=True)
        thread.start()
        scan_state["threads"].append(thread)

    # Attendre la fin du scan de ports pour lancer le banner grabbing
    scan_state["port_queue"].join()

    if scan_state["running"]:
        for port in scan_state["open_ports"]:
            scan_state["banner_queue"].put(port)

        for _ in range(20):
            thread = threading.Thread(target=banner_grab_worker, daemon=True)
            thread.start()
            scan_state["threads"].append(thread)
        
        scan_state["banner_queue"].join()

    if scan_state["running"]:
        stop_scan()

def stop_scan():
    global scan_state
    with scan_state["lock"]:
        if not scan_state["running"]:
            return
        utils.log_message('+', "Arrêt du scan.")
        scan_state["running"] = False
        # Vider les files d'attente pour débloquer les threads
        while not scan_state["port_queue"].empty():
            scan_state["port_queue"].get()
            scan_state["port_queue"].task_done()
        while not scan_state["banner_queue"].empty():
            scan_state["banner_queue"].get()
            scan_state["banner_queue"].task_done()

def get_status():
    with scan_state["lock"]:
        return {
            "running": scan_state["running"],
            "target": scan_state["target"],
            "progress": f"{len(COMMON_PORTS) - scan_state['port_queue'].qsize()}/{len(COMMON_PORTS)} ports scannés",
            "open_ports": len(scan_state["open_ports"])
        }

def run(target, session_dir, use_tor=False):
    if use_tor:
        try:
            utils.get_requests_session(force_tor=True)
        except Exception as e:
            utils.log_message('-', f"Erreur lors de l'initialisation de Tor : {e}")
            return

    start_scan(target, use_tor)

    while get_status()["running"]:
        status = get_status()
        print(f'    [+] Scan en cours sur {status["target"]} | {status["progress"]} | {status["open_ports"]} ports ouverts trouvés      ', end='\r')
        time.sleep(1)
    print()

    results = f"--- RÉSULTATS DU SCAN POUR {scan_state['target']} ({scan_state['target_ip']}) ---\n\n"
    os_info = get_os_from_ttl(scan_state['target_ip'])
    results += f"[+] Détection de l'OS (via TTL) : {os_info}\n"
    try:
        rev_dns = socket.gethostbyaddr(scan_state['target_ip'])
        results += f"[+] Reverse DNS : {rev_dns[0]}\n"
    except socket.herror:
        results += "[+] Reverse DNS : Aucune entrée trouvée\n"
    
    results += "\n--- SCAN DE PORTS TCP ---\n"
    if scan_state["open_ports"]:
        results += "Ports ouverts :\n"
        scan_state["open_ports"].sort()
        for port in scan_state["open_ports"]:
            banner = scan_state["banners"].get(port, "Erreur inconnue lors de la récupération.")
            results += f"  [>] Port {port}/tcp : OUVERT | Bannière : {banner}\n"
    else:
        results += "Aucun port ouvert trouvé parmi les ports courants.\n"

    output_path = os.path.join(session_dir, 'scan_results.txt')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(results)

    utils.log_message('+', f"Résultats du scan enregistrés dans {output_path}")
    print(results)
