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

from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, flash, get_flashed_messages
from werkzeug.utils import secure_filename
import os
import sys
import json
import re
import datetime
import logging
import threading 
import time
import shutil # Added for robust directory deletion

VERSION = "1.0" # Définir la version ici

# Configuration de la journalisation
logging.basicConfig(filename='app.log', level=logging.ERROR, 
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

# Ajouter le dossier des modules au path pour pouvoir les importer
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

# Importer les modules de BlackPyReconX
from modules import osint, scanner, exploit_web, reporting, exfiltration, utils, dos, bruteforce, sniffer, crypto_tools, wireless
from modules.exploit_web import generate_xss_payload, generate_sqli_payload, generate_lfi_payload


# --- Global State for Brute-force Thread Management ---
bruteforce_thread = None 


app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = 'super_secret_key' # For development purposes

OUTPUTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'outputs'))

@app.context_processor
def inject_version():
    return dict(version=VERSION)

@app.after_request
def add_header(response):
    """Désactive la mise en cache pour s'assurer que les modifs sont toujours visibles."""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response



# --- ROUTES DE L'INTERFACE WEB (Nouvelle Structure) ---

@app.route('/')
def index():
    """Affiche le tableau de bord principal."""
    return render_template('index.html')

@app.route('/recon')
def recon():
    """Affiche la page de Reconnaissance."""
    return render_template('recon.html')

@app.route('/web')
def web():
    """Affiche la page d'Analyse Web."""
    return render_template('web.html')

@app.route('/exploit')
def exploit():
    """Affiche la page d'Exploitation."""
    config = utils.load_config() # Load global config
    return render_template('exploit.html', config=config) # Pass config to template

@app.route('/utils')
def utils_page():
    """Affiche la page des Utilitaires."""
    return render_template('utils_page.html')

@app.route('/reports')
def reports():
    """Affiche la page de gestion des rapports."""
    # Cette page pourrait être plus complexe, mais pour l'instant, elle n'a besoin que du template.
    # Le chargement des rapports se fait via l'API '/api/reports' appelée par le JS.
    return render_template('reports.html')

@app.route('/wireless')
def wireless_page():
    """Affiche la page des outils Wireless."""
    return render_template('wireless.html')

# --- ROUTES API POUR LE MODULE WIRELESS ---

@app.route('/api/wireless/list_interfaces', methods=['GET'])
def api_wireless_list_interfaces():
    try:
        interfaces = wireless.list_interfaces()
        return jsonify(interfaces)
    except Exception as e:
        app.logger.error(f'Erreur lors de la liste des interfaces sans fil: {e}', exc_info=True)
        return jsonify({'error': str(e)}), 500

# Global state for wireless operations to manage long-running tasks
wireless_status = {
    "monitor_mode": {"active": False, "interface": None, "original_interface": None},
    "scan": {"running": False, "interface": None, "results": []}
}

# Thread management for monitor mode to prevent blocking
monitor_mode_thread = None

def _run_enable_monitor_mode(interface):
    global wireless_status
    try:
        success, new_iface = wireless.enable_monitor_mode(interface)
        if success:
            wireless_status["monitor_mode"]["active"] = True
            wireless_status["monitor_mode"]["interface"] = new_iface if new_iface else interface
            wireless_status["monitor_mode"]["original_interface"] = interface
        else:
            wireless_status["monitor_mode"]["active"] = False
            wireless_status["monitor_mode"]["interface"] = None
            wireless_status["monitor_mode"]["original_interface"] = None
            app.logger.error(f"Failed to enable monitor mode on {interface}.")
    except Exception as e:
        app.logger.error(f"Error enabling monitor mode on {interface}: {e}", exc_info=True)
        wireless_status["monitor_mode"]["active"] = False
        wireless_status["monitor_mode"]["interface"] = None
        wireless_status["monitor_mode"]["original_interface"] = None

@app.route('/api/wireless/monitor_start', methods=['POST'])
def api_wireless_monitor_start():
    global monitor_mode_thread
    data = request.get_json()
    iface = data.get('iface')
    if not iface:
        return jsonify({'error': 'Nom d\'interface manquant.'}), 400

    if wireless_status["monitor_mode"]["active"]:
        return jsonify({'message': f"Le mode moniteur est déjà actif sur {wireless_status['monitor_mode']['interface']}."}), 200

    if monitor_mode_thread and monitor_mode_thread.is_alive():
        return jsonify({'error': "Une opération de mode moniteur est déjà en cours."}), 409 # Conflict

    monitor_mode_thread = threading.Thread(target=_run_enable_monitor_mode, args=(iface,), daemon=True)
    monitor_mode_thread.start()
    
    return jsonify({'message': f"Tentative d'activation du mode moniteur sur {iface}. Vérifiez le statut."}), 202 # Accepted

def _run_disable_monitor_mode(interface):
    global wireless_status
    try:
        success = wireless.disable_monitor_mode(interface)
        if success:
            wireless_status["monitor_mode"]["active"] = False
            wireless_status["monitor_mode"]["interface"] = None
            wireless_status["monitor_mode"]["original_interface"] = None
        else:
            app.logger.error(f"Failed to disable monitor mode on {interface}.")
    except Exception as e:
        app.logger.error(f"Error disabling monitor mode on {interface}: {e}", exc_info=True)

@app.route('/api/wireless/monitor_stop', methods=['POST'])
def api_wireless_monitor_stop():
    global monitor_mode_thread
    if not wireless_status["monitor_mode"]["active"]:
        return jsonify({'message': "Le mode moniteur n'est pas actif."}), 200

    iface_to_stop = wireless_status["monitor_mode"]["interface"]
    if not iface_to_stop:
        return jsonify({'error': "Aucune interface en mode moniteur active n'est enregistrée."}), 400

    monitor_mode_thread = threading.Thread(target=_run_disable_monitor_mode, args=(iface_to_stop,), daemon=True)
    monitor_mode_thread.start()

    return jsonify({'message': f"Tentative de désactivation du mode moniteur sur {iface_to_stop}. Vérifiez le statut."}), 202

@app.route('/api/wireless/monitor_status', methods=['GET'])
def api_wireless_monitor_status():
    return jsonify(wireless_status["monitor_mode"])


# Thread management for scan to prevent blocking
scan_thread = None

def _run_scan_networks(interface, duration):
    global wireless_status
    try:
        wireless_status["scan"]["running"] = True
        wireless_status["scan"]["interface"] = interface
        networks = wireless.scan_networks(interface, duration)
        wireless_status["scan"]["results"] = networks
    except Exception as e:
        app.logger.error(f"Error scanning networks on {interface}: {e}", exc_info=True)
        wireless_status["scan"]["results"] = []
    finally:
        wireless_status["scan"]["running"] = False

@app.route('/api/wireless/scan_networks', methods=['POST'])
def api_wireless_scan_networks():
    global scan_thread
    data = request.get_json()
    iface = data.get('iface')
    duration = data.get('duration', 10)

    if not iface:
        return jsonify({'error': 'Nom d\'interface manquant.'}), 400

    if not wireless_status["monitor_mode"]["active"] or wireless_status["monitor_mode"]["interface"] != iface:
        return jsonify({'error': 'L\'interface spécifiée n\'est pas en mode moniteur, ou le mode moniteur n\'est pas actif sur cette interface.'}), 400

    if scan_thread and scan_thread.is_alive():
        return jsonify({'error': "Un scan est déjà en cours."}), 409 # Conflict

    wireless_status["scan"]["results"] = [] # Clear previous results
    scan_thread = threading.Thread(target=_run_scan_networks, args=(iface, duration,), daemon=True)
    scan_thread.start()

    return jsonify({'message': f"Lancement du scan sur {iface} pour {duration} secondes. Vérifiez le statut pour les résultats."}), 202

@app.route('/api/wireless/scan_status', methods=['GET'])
def api_wireless_scan_status():
    return jsonify(wireless_status["scan"])

# --- ROUTES API (Anciennes routes qui deviennent des points d'API) ---

@app.route('/run_module', methods=['POST'])
def run_module():
    """Route générique pour lancer les différents modules."""
    data = request.get_json()
    module_name = data.get('module')
    target = data.get('target')

    if not target and module_name not in ['exfil', 'report']:
        return jsonify({'error': 'La cible ne peut pas être vide.'}), 400

    print(f"[WEB UI] Lancement du module '{module_name}' sur la cible '{target}'")
    
    try:
        # Charger la configuration TOR depuis le fichier pour être toujours à jour
        config = utils.load_config()
        use_tor_flag = config.get('use_tor', False)

        # Nettoyage sélectif du fichier de résultat correspondant
        result_file_map = {
            'osint': 'osint.txt',
            'scan': 'scan_results.txt',
            'web': 'web_vulns.txt'
        }
        if module_name in result_file_map:
            file_to_clear = os.path.join(OUTPUTS_DIR, result_file_map[module_name])
            if os.path.exists(file_to_clear):
                os.remove(file_to_clear)

        # Pour les modules de scan, on exécute puis on génère un rapport complet
        if module_name in ['osint', 'scan', 'web']:
            # Créer un répertoire de session pour ce scan
            session_dir = utils.get_current_session_dir()

            # Préparer la session pour les modules qui en ont besoin
            if module_name == 'osint':
                osint.session = utils.get_requests_session(force_tor=use_tor_flag)
                # Shodan API key should be passed to osint module
                osint.SHODAN_API_KEY = utils.get_api_key('shodan')
            elif module_name == 'web':
                exploit_web.session = utils.get_requests_session(force_tor=use_tor_flag)

            # Exécuter le module de scan
            if module_name == 'osint':
                osint.run(target, session_dir)
                result_file = 'osint.txt'
            elif module_name == 'scan':
                scanner.run(target, session_dir, use_tor=use_tor_flag)
                result_file = 'scan_results.txt'
            elif module_name == 'web':
                exploit_web.run(target, session_dir)
                result_file = 'web_vulns.txt'
            
            # Lire le résultat brut pour l'afficher directement
            output_path = os.path.join(session_dir, result_file)
            with open(output_path, 'r', encoding='utf-8', errors='replace') as f:
                output_content = f.read()

            # Générer automatiquement les rapports après le scan
            print(f"[WEB UI] Génération automatique des rapports pour la cible '{target}'")
            txt_file, pdf_file, html_file = reporting.run(target, session_dir)

            # Petite pause pour s'assurer que les fichiers sont bien écrits sur le disque
            time.sleep(1)

            return jsonify({
                'output': output_content,
                'txt_file': txt_file, 
                'pdf_file': pdf_file, 
                'html_file': html_file
            })

        # Pour le module de rapport seul, on ne fait que générer les fichiers
        elif module_name == 'report':
            txt_file, pdf_file, html_file = reporting.run(target)
            return jsonify({
                'output': f"Rapports générés : {txt_file}, {pdf_file}, {html_file}",
                'txt_file': txt_file, 
                'pdf_file': pdf_file, 
                'html_file': html_file
            })

        elif module_name == 'exfil':
            exfiltration.run()
            return jsonify({'output': "Processus d'exfiltration terminé. Vérifiez les fichiers chiffrés dans le dossier 'outputs'."})

        elif module_name == 'dos':
            port = data.get('port')
            duration = data.get('duration')
            if not port or not duration:
                return jsonify({'error': "Le port et la durée sont obligatoires pour l'attaque DoS."}), 400
            
            dos.run(target, port, duration)
            return jsonify({'output': f"Attaque DoS sur {target}:{port} terminée après {duration} secondes."})


        
        else:
            return jsonify({'error': 'Module inconnu.'}), 400

    except Exception as e:
        app.logger.error(f'Erreur lors de l\'exécution du module {module_name}', exc_info=True)
        return jsonify({'error': f'Une erreur interne est survenue. Consultez app.log pour les détails.'}), 500

# --- ROUTES POUR L\'ATTAQUE DoS ---

@app.route('/dos/start', methods=['POST'])
def start_dos():
    data = request.get_json()
    target = data.get('target')
    port = data.get('port')
    duration = data.get('duration')

    if not all([target, port, duration]):
        return jsonify({'error': 'Les paramètres target, port et duration sont requis.'}), 400

    try:
        dos.start_attack(target, int(port), int(duration))
        return jsonify({'message': 'Attaque DoS démarrée.'})
    except Exception as e:
        return jsonify({'error': f"Erreur lors du démarrage de l\'attaque: {e}"}), 500

@app.route('/dos/status', methods=['GET'])
def dos_status():
    return jsonify(dos.get_status())

@app.route('/dos/stop', methods=['POST'])
def stop_dos():
    try:
        dos.stop_attack()
        return jsonify({'message': 'Attaque DoS arrêtée.'})
    except Exception as e:
        return jsonify({'error': f"Erreur lors de l\'arrêt de l\'attaque: {e}"}), 500

# --- ROUTES POUR L\'ATTAQUE BRUTE-FORCE ---
def _run_bruteforce_in_thread(attack_type, options):
    """Wrapper pour exécuter bruteforce.start_bruteforce dans un thread."""
    global bruteforce_thread
    app.logger.debug(f"[_run_bruteforce_in_thread] Thread started. Name: {threading.current_thread().name}")
    try:
        bruteforce.start_bruteforce(attack_type, options)
        # Laisser le thread en vie tant que l'attaque tourne
        while bruteforce.bruteforce_state["running"]:
            app.logger.debug(f"[_run_bruteforce_in_thread] bruteforce_state['running'] is True. Sleeping...")
            time.sleep(0.5) 
    except Exception as e:
        app.logger.error(f"[_run_bruteforce_in_thread] Error in brute-force thread: {e}", exc_info=True)
    finally:
        app.logger.debug(f"[_run_bruteforce_in_thread] Finally block entered. bruteforce_state['running']: {bruteforce.bruteforce_state['running']}")
        # S'assurer que l'état est bien nettoyé si le thread se termine
        if bruteforce.bruteforce_state["running"]: # Only stop if it's still marked as running
            app.logger.debug("[_run_bruteforce_in_thread] Calling bruteforce.stop_bruteforce() from finally block.")
            bruteforce.stop_bruteforce() # Assure un arrêt propre si une erreur survient
        else:
            app.logger.debug("[_run_bruteforce_in_thread] bruteforce_state['running'] is False, no need to call stop_bruteforce.")
        
        bruteforce_thread = None # Libérer le thread une fois terminé

@app.route('/bruteforce/start', methods=['POST'])
def start_bruteforce_web():
    global bruteforce_thread
    app.logger.debug(f"start_bruteforce_web called. bruteforce_thread: {bruteforce_thread}, is_alive: {bruteforce_thread.is_alive() if bruteforce_thread else 'N/A'}")
    # Check if a brute-force attack is already running
    if bruteforce_thread and bruteforce_thread.is_alive():
        app.logger.warning("Une attaque par force brute est déjà en cours. Arrêt de l'attaque précédente pour démarrer la nouvelle.")
        try:
            bruteforce.stop_bruteforce()
            # Wait for the previous thread to actually stop
            wait_timeout = 10 # seconds
            start_time = time.time()
            # Poll bruteforce_state["running"] flag as it's updated by the worker
            while bruteforce.bruteforce_state["running"] and (time.time() - start_time < wait_timeout):
                time.sleep(0.1) # Wait a bit for the thread to stop
            if bruteforce.bruteforce_state["running"]:
                app.logger.error("L'attaque précédente n'a pas pu être arrêtée à temps dans les délais impartis. Tentative de démarrage d'une nouvelle attaque malgré tout.")
            else:
                app.logger.info("L'attaque précédente a été arrêtée avec succès.")
            bruteforce_thread = None # Reset the thread reference
        except Exception as e:
            app.logger.error(f"Erreur lors de l'arrêt de l'attaque précédente: {e}", exc_info=True)
            return jsonify({'error': f"Erreur lors de l'arrêt de l'attaque précédente : {e}"}), 500

    data = request.get_json()
    attack_type = data.get('attack_type')
    options = data.get('options')

    # Inject wordlist paths from global config if attack_type is dictionary
    if attack_type == 'dictionary':
        global_config = utils.load_config()
        wordlists_config = global_config.get('wordlists', {})
        options['userlist'] = wordlists_config.get('darkc0de_usernames', options.get('userlist')) # Default to current userlist if not found in global
        options['passlist'] = wordlists_config.get('passwords', options.get('passlist')) # Default to current passlist if not found in global
        app.logger.debug(f"Bruteforce: Injected userlist: {options['userlist']}, passlist: {options['passlist']} from global config.")


    if not attack_type or not options:
        app.logger.debug("Missing attack_type or options.")
        return jsonify({'error': 'Les paramètres de l\'attaque brute-force sont manquants.'}), 400
    
    # Validation minimale pour la cible
    if not options.get('target') and options.get('service') != 'web': # For web, target is the URL, not the target parameter
        app.logger.debug("Missing target for non-web service.")
        return jsonify({'error': 'La cible est obligatoire pour la plupart des services.'}), 400

    bruteforce_thread = threading.Thread(target=_run_bruteforce_in_thread, args=(attack_type, options), daemon=True)
    bruteforce_thread.start()
    app.logger.debug(f"Brute-force thread started. Thread: {bruteforce_thread}")

    return jsonify({'message': 'Attaque par force brute démarrée.'})

@app.route('/bruteforce/status', methods=['GET'])
def bruteforce_status():
    status = bruteforce.get_status()
    app.logger.debug(f"bruteforce_status called. Current status: {status}")
    return jsonify(status)

@app.route('/bruteforce/stop', methods=['POST'])
def stop_bruteforce_web():
    app.logger.debug("stop_bruteforce_web called.")
    try:
        bruteforce.stop_bruteforce()
        app.logger.debug("bruteforce.stop_bruteforce() called.")
        return jsonify({'message': 'Attaque par force brute arrêtée.'})
    except Exception as e:
        app.logger.error(f"Erreur lors de l\'arrêt de l\'attaque par force brute: {e}", exc_info=True)
        return jsonify({'error': f"Erreur lors de l'arrêt de l\'attaque: {e}"}), 500

# --- ROUTES POUR LA GESTION DES SERVICES ET TÉLÉCHARGEMENTS ---

@app.route('/download/<path:filename>')
def download_file(filename):
    """Permet de télécharger un fichier depuis le dossier outputs."""
    print(f"--- DEBUG: Tentative de téléchargement ---")
    print(f"Chemin du dossier (OUTPUTS_DIR): {OUTPUTS_DIR}")
    print(f"Nom de fichier demandé: {filename}")
    full_path = os.path.join(OUTPUTS_DIR, filename)
    print(f"Chemin complet assemblé: {full_path}")
    print(f"Le fichier existe-t-il ? : {os.path.exists(full_path)}")
    print(f"-----------------------------------------")
    return send_from_directory(OUTPUTS_DIR, filename, as_attachment=True)

@app.route('/view/report/<path:filename>')
def view_report(filename):
    """Sert un fichier rapport pour l\'affichage dans le navigateur."""
    return send_from_directory(OUTPUTS_DIR, filename)

@app.route('/get_tor_status', methods=['GET'])
def get_tor_status():
    config = utils.load_config()
    use_tor = config.get('use_tor', False)
    if use_tor:
        try:
            utils.get_requests_session(force_tor=True)
        except Exception:
            pass # L'erreur est déjà loggée dans get_requests_session

    tor_ip = None
    tor_ip_country = None
    tor_ip_city = None
    tor_ip_country_code = None
    try:
        with open('status.json', 'r') as f:
            status_data = json.load(f)
            tor_ip = status_data.get('tor_ip')
            tor_ip_country = status_data.get('tor_ip_country')
            tor_ip_city = status_data.get('tor_ip_city')
            tor_ip_country_code = status_data.get('tor_ip_country_code')
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return jsonify({'tor_enabled': use_tor, 'tor_ip': tor_ip, 'tor_ip_country': tor_ip_country, 'tor_ip_city': tor_ip_city, 'tor_ip_country_code': tor_ip_country_code})

@app.route('/toggle_tor', methods=['POST'])
def toggle_tor():
    config = utils.load_config()
    config['use_tor'] = not config.get('use_tor', False)
    utils.save_config(config)
    return jsonify({'tor_enabled': config['use_tor']})



# --- ROUTE POUR LA CONFIGURATION DES RAPPORTS ---

REPORT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'data', 'report_config.json')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'assets') # Modified path
app.logger.debug(f"UPLOAD_FOLDER set to: {UPLOAD_FOLDER}")

@app.route('/config/report', methods=['GET', 'POST'])
def configure_report():
    if request.method == 'POST':
        # --- Sauvegarde de la configuration ---
        with open(REPORT_CONFIG_PATH, 'r') as f:
            config = json.load(f)

        config['company_name'] = request.form.get('company_name', config['company_name'])
        config['direction'] = request.form.get('direction', config['direction'])
        config['department'] = request.form.get('department', config['department'])
        config['engineer_name'] = request.form.get('engineer_name', config['engineer_name'])
        config['engineer_contact'] = request.form.get('engineer_contact', config['engineer_contact'])
        config['engineer_email'] = request.form.get('engineer_email', config['engineer_email'])

        # Gérer le téléversement du logo
        if 'logo' in request.files:
            file = request.files['logo']
            if file.filename != '':
                filename = secure_filename(file.filename)
                logo_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(logo_path)
                config['logo_path'] = logo_path
        
        # Gérer la suppression du logo
        if request.form.get('remove_logo') == 'true':
            config['logo_path'] = ""

        with open(REPORT_CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=4)
        
        # Renvoyer uniquement le nom du fichier pour l\'affichage
        display_logo = os.path.basename(config['logo_path']) if config.get('logo_path') else ''
        return jsonify({'message': 'Configuration sauvegardée', 'logo_path': display_logo})

    # --- Affichage du formulaire ---
    try:
        with open(REPORT_CONFIG_PATH, 'r') as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        config = {"company_name": "", "direction": "", "department": "", "engineer_name": "", "engineer_contact": "", "engineer_email": "", "logo_path": ""}
        with open(REPORT_CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=4)
    
    # Passer uniquement le nom du fichier au template
    config['display_logo'] = os.path.basename(config.get('logo_path', ''))
    return render_template('config_report.html', config=config)


# --- ROUTE POUR LA CONFIGURATION GLOBALE ---
@app.route('/config/global', methods=['GET', 'POST'])
def configure_global():
    if request.method == 'POST':
        config = utils.load_config()
        
        # Mettre à jour les chemins des wordlists
        if 'wordlists' not in config:
            config['wordlists'] = {}
        config['wordlists']['common_paths'] = request.form.get('wordlist_common_paths', config['wordlists'].get('common_paths'))
        config['wordlists']['darkc0de_usernames'] = request.form.get('wordlist_darkc0de_usernames', config['wordlists'].get('darkc0de_usernames'))
        config['wordlists']['passwords'] = request.form.get('wordlist_passwords', config['wordlists'].get('passwords'))
        config['wordlists']['usernames'] = request.form.get('wordlist_usernames', config['wordlists'].get('usernames'))
        
        utils.save_config(config)
        return jsonify({'message': 'Configuration globale sauvegardée avec succès.'})

    config = utils.load_config()
    return render_template('global_config.html', config=config)


# --- ROUTE POUR LE TÉLÉVERSEMENT DE LISTES ---

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

@app.route('/upload_list', methods=['POST'])
def upload_list():
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier fourni'}), 400
    
    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400

    if file and file.filename.endswith('.txt'):
        filename = secure_filename(file.filename)
        save_path = os.path.join(DATA_DIR, filename)
        file.save(save_path)
        
        # On retourne le chemin relatif utilisable par les modules
        relative_path = os.path.join('data', filename).replace('\\', '/')
        return jsonify({'message': 'Fichier téléversé', 'file_path': relative_path})
    
    return jsonify({'error': 'Type de fichier invalide, seul .txt est accepté'}), 400

# --- ROUTES POUR LE BOT TELEGRAM ---

@app.route('/bot/status', methods=['GET'])
def bot_status():
    try:
        with open('status.json', 'r') as f:
            status = json.load(f)
        is_running = status.get('bot_status') == 'active'
        return jsonify({'running': is_running})
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({'running': False})

# --- ROUTES POUR LA GESTION DES RAPPORTS ---

@app.route('/api/reports', methods=['GET'])
def list_reports():
    """Liste les fichiers de rapport dans le dossier outputs, y compris les sous-dossiers."""
    try:
        all_reports = []
        report_patterns = ('rapport_', 'osint.txt', 'scan_results.txt', 'web_vulns.txt')
        
        for root, dirs, files in os.walk(OUTPUTS_DIR):
            for file in files:
                # Check if the file matches any of the report patterns
                is_report_file = False
                for pattern in report_patterns:
                    if pattern.endswith('.txt') or pattern.endswith('.html') or pattern.endswith('.pdf'):
                        if file == pattern: # Exact match for specific files
                            is_report_file = True
                            break
                    elif file.startswith(pattern): # Starts with match for general reports
                        is_report_file = True
                        break
                        
                if is_report_file:
                    relative_path = os.path.relpath(os.path.join(root, file), OUTPUTS_DIR)
                    all_reports.append(relative_path)
        
        all_reports.sort(reverse=True) # Afficher les plus récents en premier
        return jsonify(all_reports)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/delete', methods=['POST'])
def delete_report():
    """Supprime un ou plusieurs fichiers ou dossiers de rapport."""
    data = request.get_json()
    filenames = data.get('filenames')

    if not filenames or not isinstance(filenames, list):
        return jsonify({'error': 'La liste de noms de fichiers est manquante ou invalide.'}), 400

    errors = []
    success_count = 0
    
    # Obtenir le chemin absolu et résolu du dossier de base pour la comparaison
    real_outputs_dir = os.path.realpath(OUTPUTS_DIR)

    for filename in filenames:
        # Valider que le nom de fichier ne contient pas de caractères de traversée de répertoire "absolus"
        if '..' in filename.split(os.path.sep):
            errors.append(f"'{filename}' contient des caractères invalides ('..').")
            continue

        # Construire le chemin complet et le résoudre
        file_path = os.path.join(real_outputs_dir, filename)
        real_file_path = os.path.realpath(file_path)

        # Vérification de sécurité : s'assurer que le chemin est bien dans le dossier outputs
        if not real_file_path.startswith(real_outputs_dir):
            errors.append(f"Accès non autorisé pour le fichier '{filename}'.")
            continue

        if os.path.exists(real_file_path):
            try:
                if os.path.isfile(real_file_path):
                    os.remove(real_file_path)
                    success_count += 1
                    app.logger.info(f"Fichier supprimé: {real_file_path}")
                    
                    # Tenter de supprimer le dossier parent s'il est vide
                    parent_dir = os.path.dirname(real_file_path)
                    if parent_dir != real_outputs_dir and not os.listdir(parent_dir):
                        os.rmdir(parent_dir)
                        app.logger.info(f"Dossier parent vide supprimé: {parent_dir}")

                elif os.path.isdir(real_file_path):
                    shutil.rmtree(real_file_path)
                    success_count += 1
                    app.logger.info(f"Dossier supprimé: {real_file_path}")
                else:
                    errors.append(f"'{filename}' n'est ni un fichier ni un dossier valide.")

            except Exception as e:
                app.logger.error(f"Erreur lors de la suppression de '{real_file_path}': {e}", exc_info=True)
                errors.append(f"Erreur lors de la suppression de {filename}: {e}")
        else:
            errors.append(f"Fichier ou dossier non trouvé: {filename}")

    if not errors:
        plural = 's' if success_count > 1 else ''
        return jsonify({'message': f'{success_count} élément{plural} supprimé{plural} avec succès.'})
    elif success_count > 0:
        return jsonify({'message': f'{success_count} élément(s) supprimé(s), mais {len(errors)} erreur(s) sont survenues: {"; ".join(errors)}'}), 207 # Multi-Status
    else:
        return jsonify({'error': f'Échec de la suppression. Erreurs: {"; ".join(errors)}'}), 500

@app.route('/api/osint/geo', methods=['POST'])
def get_geo_info():
    data = request.get_json()
    target = data.get('target')

    if not target:
        return jsonify({'error': 'La cible est manquante pour la géolocalisation.'}), 400

    try:
        # Assurez-vous que la session requests est initialisée
        # Le module osint gère déjà la création d'une session si 'session' est None
        geolocation_info = osint.get_geolocation_formatted(target)
        return jsonify({'geolocation_info': geolocation_info})
    except Exception as e:
        app.logger.error(f'Erreur lors de la géolocalisation pour {target}: {e}', exc_info=True)
        return jsonify({'error': f'Erreur lors de la géolocalisation: {e}'}), 500

# --- ROUTES POUR LE SNIFFER ---

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Retourne la liste des interfaces réseau disponibles avec leurs noms conviviaux et adresses IP."""
    try:
        interfaces = sniffer.get_interfaces()
        return jsonify(interfaces)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sniffer/start', methods=['POST'])
def start_sniffer():
    data = request.get_json()
    iface = data.get('iface')
    filter = data.get('filter')
    result = sniffer.start(iface=iface, filter=filter)
    return jsonify(result)

@app.route('/sniffer/status', methods=['GET'])
def sniffer_status():
    return jsonify(sniffer.get_status())

@app.route('/sniffer/stop', methods=['POST'])
def stop_sniffer():
    result = sniffer.stop()
    return jsonify(result)




# --- ROUTES POUR LA STÉGANOGRAPHIE ---

@app.route('/stegano/hide', methods=['POST'])
def stegano_hide():
    if 'image' not in request.files or 'secret' not in request.files:
        return "Erreur: Fichiers manquants.", 400
    
    image_file = request.files['image']
    secret_file = request.files['secret']

    if image_file.filename == '' or secret_file.filename == '':
        return "Erreur: Fichiers non sélectionnés.", 400

    image_filename = secure_filename(image_file.filename)
    secret_filename = secure_filename(secret_file.filename)
    
    temp_image_path = os.path.join(OUTPUTS_DIR, image_filename)
    temp_secret_path = os.path.join(OUTPUTS_DIR, secret_filename)
    
    image_file.save(temp_image_path)
    secret_file.save(temp_secret_path)

    output_filename = "stegano_" + image_filename
    output_path = os.path.join(OUTPUTS_DIR, output_filename)

    result = crypto_tools.stegano_hide_file(temp_image_path, temp_secret_path, output_path)

    os.remove(temp_image_path)
    os.remove(temp_secret_path)

    if "Succès" in result:
        return send_from_directory(OUTPUTS_DIR, output_filename, as_attachment=True)
    else:
        if os.path.exists(output_path):
            os.remove(output_path)
        # Assuming result string often contains "Erreur :", we can try to infer status code
        status_code = 400 if "Erreur :" in result else 500
        return jsonify({'status': 'error', 'message': result}), status_code

@app.route('/stegano/reveal', methods=['POST'])
def stegano_reveal():
    if 'image' not in request.files:
        return "Erreur: Fichier image manquant.", 400
    
    image_file = request.files['image']

    if image_file.filename == '':
        return "Erreur: Fichier non sélectionné.", 400

    image_filename = secure_filename(image_file.filename)
    temp_image_path = os.path.join(OUTPUTS_DIR, image_filename)
    image_file.save(temp_image_path)

    output_filename = "revealed_secret.dat"
    output_path = os.path.join(OUTPUTS_DIR, output_filename)

    result = crypto_tools.stegano_reveal_file(temp_image_path, output_path)

    os.remove(temp_image_path)

    if "Succès" in result:
        return send_from_directory(OUTPUTS_DIR, output_filename, as_attachment=True)
    else:
        if os.path.exists(output_path):
            os.remove(output_path)
        return jsonify({'status': 'error', 'message': result}), 200 # Return JSON for error/no data found




if __name__ == '__main__':
    print("[*] Pour lancer l'interface web, exécutez la commande : flask --app app run")