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

from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import os
import sys
import json
import re
import datetime
import logging
import time

# Configuration de la journalisation
logging.basicConfig(filename='app.log', level=logging.ERROR, 
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

# Ajouter le dossier des modules au path pour pouvoir les importer
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

# Importer les modules de BlackPyReconX
from modules import osint, scanner, exploit_web, reporting, exfiltration, utils, dos, bruteforce, sniffer, crypto_tools


app = Flask(__name__)

OUTPUTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'outputs'))

@app.after_request
def add_header(response):
    """Désactive la mise en cache pour s'assurer que les modifs sont toujours visibles."""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/favicon.svg')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'data', 'assets'), 'favicon.svg', mimetype='image/svg+xml')

# Variable globale pour l'état de TOR
USE_TOR = False

# --- ROUTES DE L'INTERFACE WEB ---

@app.route('/')
def index():
    """Affiche la page d'accueil avec des panneaux de résultats vierges."""
    results = {
        'osint': 'Les résultats OSINT apparaîtront ici.',
        'scan': 'Les résultats du scan réseau apparaîtront ici.',
        'web': "Les résultats de l'analyse web apparaîtront ici."
    }
    tor_ip = None
    try:
        with open('status.json', 'r') as f:
            status_data = json.load(f)
            tor_ip = status_data.get('tor_ip')
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return render_template('index.html', results=results, tor_ip=tor_ip)

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
            if module_name in ['osint', 'web']:
                session = utils.get_requests_session(force_tor=use_tor_flag)
                if module_name == 'osint':
                    osint.session = session
                else:
                    exploit_web.session = session

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

        elif module_name == 'bruteforce':
            attack_type = data.get('attack_type')
            service = data.get('service')

            # Mapper le service au port
            service_to_port = {
                'ssh': 22, 'ftp': 21, 'telnet': 23, 'mysql': 3306, 'postgres': 5432, 'web': 80 # Port par défaut pour web
            }
            port = service_to_port.get(service)

            if not port:
                return jsonify({'error': f'Service non supporté: {service}'}), 400

            options = {
                'service': service,
                'target': target,
                'port': port,
            }

            if attack_type == 'dictionary':
                options.update({
                    'userlist': data.get('userlist'),
                    'passlist': data.get('passlist'),
                    'password': data.get('password'),
                })
                if service == 'web':
                    options.update({
                        'url': data.get('url'),
                        'user_field': data.get('user_field'),
                        'pass_field': data.get('pass_field'),
                        'fail_string': data.get('fail_string'),
                    })

            elif attack_type == 'bruteforce':
                options.update({
                    'username': data.get('username'),
                    'charset': data.get('charset'),
                    'min_len': data.get('min_len'),
                    'max_len': data.get('max_len'),
                })
            
            found = bruteforce.run(attack_type, options)
            if found:
                return jsonify({'output': f"Identifiants trouvés : {found[0]}:{found[1]}"})
            else:
                return jsonify({'output': "Aucun identifiant trouvé."})
        
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
    try:
        with open('status.json', 'r') as f:
            status_data = json.load(f)
            tor_ip = status_data.get('tor_ip')
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return jsonify({'tor_enabled': use_tor, 'tor_ip': tor_ip})

@app.route('/toggle_tor', methods=['POST'])
def toggle_tor():
    config = utils.load_config()
    config['use_tor'] = not config.get('use_tor', False)
    utils.save_config(config)
    return jsonify({'tor_enabled': config['use_tor']})



# --- ROUTE POUR LA CONFIGURATION DES RAPPORTS ---

REPORT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'data', 'report_config.json')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'data', 'assets')

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
    """Liste les fichiers de rapport dans le dossier outputs."""
    try:
        # On ne liste que les fichiers qui commencent par "rapport_"
        files = [f for f in os.listdir(OUTPUTS_DIR) if f.startswith('rapport_')]
        files.sort(reverse=True) # Afficher les plus récents en premier
        return jsonify(files)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/delete', methods=['POST'])
def delete_report():
    """Supprime un fichier de rapport spécifique."""
    data = request.get_json()
    filename = data.get('filename')

    if not filename:
        return jsonify({'error': 'Nom de fichier manquant'}), 400

    # Sécurité : Valider le nom du fichier pour éviter les attaques par traversée de répertoire
    safe_filename = secure_filename(filename)
    if safe_filename != filename:
        return jsonify({'error': 'Nom de fichier invalide'}), 400

    file_path = os.path.join(OUTPUTS_DIR, safe_filename)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return jsonify({'message': f'Fichier {safe_filename} supprimé avec succès.'})
        except Exception as e:
            return jsonify({'error': f'Erreur lors de la suppression : {str(e)}'}), 500
    else:
        return jsonify({'error': 'Fichier non trouvé'}), 404

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

# --- ROUTES POUR LA CONFIGURATION DU PAYLOAD ---

PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), 'modules', 'exploit_sys.py')

@app.route('/config/payload', methods=['GET'])
def get_payload_config():
    """Lit la configuration actuelle du payload (IP et date)."""
    try:
        with open(PAYLOAD_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        
        host_match = re.search(r"REVERSE_HOST\s*=\s*'([^']+)'", content)
        date_match = re.search(r"ACTIVATION_DATE\s*=\s*datetime\.date\((\d+),\s*(\d+),\s*(\d+)\)", content)

        if not host_match or not date_match:
            # Fournir une configuration par défaut si le parsing échoue
            return jsonify({
                'host': '127.0.0.1',
                'year': datetime.date.today().year,
                'month': datetime.date.today().month,
                'day': datetime.date.today().day,
                'error': 'Parsing failed, showing default values.'
            })

        config = {
            'host': host_match.group(1),
            'year': int(date_match.group(1)),
            'month': int(date_match.group(2)),
            'day': int(date_match.group(3)),
        }
        return jsonify(config)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/config/payload', methods=['POST'])
def set_payload_config():
    """Met à jour la configuration du payload."""
    data = request.get_json()
    new_host = data.get('host')
    new_date = data.get('date') # Format YYYY-MM-DD

    if not new_host or not new_date:
        return jsonify({'error': 'Les données fournies sont incomplètes.'}), 400

    try:
        year, month, day = map(int, new_date.split('-'))
        
        with open(PAYLOAD_FILE, 'r', encoding='utf-8') as f:
            content = f.read()

        # Remplacer l\'IP de manière robuste
        content = re.sub(r"(REVERSE_HOST\s*=\s*')([^']*)(')", rf"\1{new_host}\3", content)
        # Remplacer la date de manière robuste
        content = re.sub(r"(ACTIVATION_DATE\s*=\s*datetime\.date\()([^)]*)(\))", rf"\1{year}, {month}, {day}\3", content)

        with open(PAYLOAD_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
            
        return jsonify({'message': 'Configuration du payload mise à jour avec succès.'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        return result, 500

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
        return result, 500

if __name__ == '__main__':
    print("[*] Pour lancer l'interface web, exécutez la commande : flask --app app run")