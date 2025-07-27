from scapy.all import sniff, wrpcap
from scapy.arch import get_if_list, get_if_addr
from rich.console import Console
from rich.table import Table
import threading
import json
import time
import subprocess
import re

console = Console()

# --- Global State Management for the Sniffer Module ---
sniffer_state = {
    "running": False,
    "thread": None,
    "packets": [],
    "lock": threading.Lock(),
    "output_file": "outputs/sniffed_packets.json"
}

def get_friendly_names():
    """Exécute ipconfig et retourne un mapping IP -> nom convivial."""
    friendly_names = {}
    try:
        # Exécuter ipconfig et capturer la sortie
        result = subprocess.run(["ipconfig"], capture_output=True, text=True, encoding='cp850', errors='ignore')
        output = result.stdout

        # Analyser la sortie pour extraire les noms et les IPs
        current_adapter = None
        for line in output.splitlines():
            if "Carte" in line:
                match = re.search(r'Carte (.*?):', line)
                if match:
                    current_adapter = match.group(1).strip()
            elif "Adresse IPv4" in line and current_adapter:
                match = re.search(r'Adresse IPv4. . . . . . . . . . . . . .: (\S+)', line)
                if match:
                    ip = match.group(1)
                    friendly_names[ip] = current_adapter
                    current_adapter = None # Réinitialiser pour la prochaine carte
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la récupération des noms d'interfaces: {e}[/bold red]")
    return friendly_names

def get_interfaces():
    """Retourne une liste de dictionnaires contenant les détails de chaque interface."""
    interfaces = []
    friendly_names = get_friendly_names()
    
    for iface_name in get_if_list():
        try:
            ip_addr = get_if_addr(iface_name)
            friendly_name = friendly_names.get(ip_addr, "Inconnu")
            interfaces.append({"name": iface_name, "ip": ip_addr, "friendly_name": friendly_name})
        except Exception:
            interfaces.append({"name": iface_name, "ip": "N/A", "friendly_name": "N/A"})
    return interfaces

def packet_callback(packet):
    """Fonction appelée pour chaque paquet capturé."""
    with sniffer_state["lock"]:
        sniffer_state["packets"].append(packet.summary())

def run_sniffer(iface, filter=None, count=0):
    """Lance la capture de paquets dans un thread séparé."""
    global sniffer_state
    sniffer_state["running"] = True
    
    kwargs = {
        'iface': iface,
        'filter': filter,
        'prn': packet_callback,
        'count': 10
    }

    while sniffer_state["running"]:
        try:
            sniff(**kwargs)
            time.sleep(1)
        except Exception as e:
            console.print(f"[bold red]Erreur dans le thread du sniffer: {e}[/bold red]")
            sniffer_state["running"] = False

def start(iface=None, filter=None, count=0, output=None):
    """Démarre la capture de paquets."""
    global sniffer_state
    if sniffer_state["running"]:
        return {"error": "Une capture est déjà en cours."}

    sniffer_state["packets"] = []
    
    effective_iface = iface
    if not effective_iface:
        available_interfaces = get_interfaces()
        if not available_interfaces:
            return {"error": "Aucune interface réseau trouvée."}
        first_valid_iface = next((iface_info for iface_info in available_interfaces if iface_info.get("ip") != "N/A"), None)
        if not first_valid_iface:
             return {"error": "Aucune interface avec une adresse IP valide n'a été trouvée."}
        effective_iface = first_valid_iface['name']

    sniffer_state["thread"] = threading.Thread(target=run_sniffer, args=(effective_iface, filter, count), daemon=True)
    sniffer_state["thread"].start()
    
    return {"message": f"Capture démarrée sur l'interface {effective_iface}."}

def stop():
    """Arrête la capture de paquets et sauvegarde les résultats."""
    global sniffer_state
    if not sniffer_state["running"]:
        return {"error": "Aucune capture en cours."}

    sniffer_state["running"] = False
    if sniffer_state["thread"]:
        sniffer_state["thread"].join(timeout=2)
    
    if sniffer_state["packets"]:
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        txt_file = f"outputs/sniff_{timestamp}.txt"
        
        with open(txt_file, "w") as f:
            for packet_summary in sniffer_state["packets"]:
                f.write(packet_summary + "\n")
        
        return {"message": f"Capture arrêtée. Rapport sauvegardé : {txt_file}"}
    
    return {"message": "Capture arrêtée. Aucun paquet capturé."}

def get_status():
    """Retourne les paquets capturés."""
    with sniffer_state["lock"]:
        packets = sniffer_state["packets"][:]
        sniffer_state["packets"] = [] # Vider la liste après lecture
    return {"running": sniffer_state["running"], "packets": packets}
