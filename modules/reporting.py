import os
import json
from datetime import datetime
from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader
import os

OUTPUTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'outputs')

def read_output_file(filename, session_dir):
    """Lit le contenu d'un fichier de résultats s'il existe dans le répertoire de session."""
    try:
        path = os.path.join(session_dir, filename)
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except FileNotFoundError:
        return f"Le fichier de résultats '{filename}' n'a pas été trouvé dans la session.\n"
    except Exception as e:
        return f"Erreur lors de la lecture du fichier {filename}: {e}\n"

class PDF(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = self.load_report_config()

    def load_report_config(self):
        try:
            with open(os.path.join(os.path.dirname(__file__), '..', 'data', 'report_config.json'), 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def header(self):
        # Logo
        if self.config.get('logo_path') and os.path.exists(self.config['logo_path']):
            self.image(self.config['logo_path'], 10, 8, 33)
            self.set_y(10)
            self.set_x(50)
        else:
            self.set_y(10)
            self.set_x(10)

        # Informations de l'entreprise
        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 6, self.config.get('company_name', 'Rapport de Sécurité'), 0, 1, 'R')
        self.set_font('Helvetica', '', 9)
        self.cell(0, 6, self.config.get('direction', ''), 0, 1, 'R')
        self.cell(0, 6, self.config.get('department', ''), 0, 1, 'R')
        self.ln(10)

    def footer(self):
        self.set_y(-20)
        self.set_font('Helvetica', 'I', 8)
        engineer_info = f"Rapport préparé par : {self.config.get('engineer_name', 'N/A')} | {self.config.get('engineer_email', 'N/A')}"
        self.cell(0, 10, engineer_info, 0, 0, 'L')
        self.set_y(-15)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Helvetica', 'B', 12)
        self.set_fill_color(220, 220, 220)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        """Écrit le corps du chapitre en interprétant le Markdown simple (**gras**)."""
        self.set_font('Helvetica', '', 10)
        parts = body.split('**')
        
        for i, part in enumerate(parts):
            if not part:
                continue
            
            if i % 2 == 1:
                self.set_font('Helvetica', 'B', 10)
            else:
                self.set_font('Helvetica', '', 10)
            
            encoded_part = part.encode('latin-1', 'replace').decode('latin-1')
            self.write(5, encoded_part)

        self.ln() # Terminer la ligne après avoir écrit toutes les parties

def create_pdf_report(data, filename):
    pdf = PDF()
    pdf.add_page()
    
    pdf.chapter_title('Résumé Exécutif')
    pdf.chapter_body(data['resume_executif'])

    pdf.chapter_title('Détail Technique des Vulnérabilités')
    pdf.chapter_body(data['detail_technique'])

    pdf.chapter_title('Impact Métier Potentiel')
    pdf.chapter_body(data['impact'])

    pdf.chapter_title('Recommandations de Sécurité')
    pdf.chapter_body(data['recommandations'])

    pdf.chapter_title('Annexes (Logs Bruts)')
    pdf.chapter_body(data['annexes'])

    pdf_path = os.path.join(OUTPUTS_DIR, filename)
    pdf.output(pdf_path)
    return filename

def generate_recommendations(data):
    """Génère des recommandations de sécurité basées sur les résultats."""
    reco_text = ""
    
    # Recommandations pour les en-têtes de sécurité manquants
    if "Manquant" in data['web_vulns_results']:
        reco_text += "- En-têtes de sécurité : Il est recommandé de mettre en place les en-têtes HTTP de sécurité manquants (ex: Content-Security-Policy, X-Frame-Options) pour protéger le site contre les attaques de type XSS et clickjacking.\n\n"

    # Recommandations pour XSS
    if "Potentiel XSS trouvé" in data['web_vulns_results']:
        reco_text += "- Failes XSS : Les entrées utilisateurs ne sont pas correctement validées. Il est crucial de filtrer et d'échapper toutes les données fournies par l'utilisateur avant de les afficher sur une page web pour prévenir les attaques Cross-Site Scripting.\n\n"

    # Recommandations pour LFI/SQLi
    if "Potentiel LFI trouvé" in data['web_vulns_results'] or "Potentiel SQLi trouvé" in data['web_vulns_results']:
        reco_text += "- Injection de code (LFI/SQLi) : Des vulnérabilités d'injection ont été détectées. Il est impératif de ne jamais faire confiance aux entrées utilisateur et d'utiliser des requêtes paramétrées (pour le SQL) et des listes blanches de fichiers autorisés (pour l'inclusion de fichiers).\n\n"

    # Recommandations pour les ports ouverts
    if "Port 21/tcp : OUVERT" in data['scan_results']:
        reco_text += "- Port 21 (FTP) : Le port FTP est ouvert. Ce protocole transmet les identifiants en clair. Si possible, utilisez un protocole sécurisé comme SFTP (qui utilise le port 22) et restreignez l'accès par IP.\n\n"
    if "Port 22/tcp : OUVERT" in data['scan_results']:
        reco_text += "- Port 22 (SSH) : Le port SSH est ouvert. Assurez-vous que l'authentification par mot de passe est désactivée au profit de l'authentification par clé, et utilisez un outil comme fail2ban pour bloquer les tentatives de brute-force.\n\n"

    if not reco_text:
        return "Aucune recommandation spécifique à générer pour les problèmes détectés."

    return reco_text

def generate_professional_report(data):
    """Génère le contenu du rapport en suivant le format professionnel."""
    
    # --- 1. Résumé Exécutif ---
    critical_vulns = []
    if "Potentiel XSS trouvé" in data['web_vulns_results']: critical_vulns.append("Injection XSS")
    if "Potentiel LFI trouvé" in data['web_vulns_results']: critical_vulns.append("Inclusion de Fichier Local (LFI)")
    if "Potentiel SQLi trouvé" in data['web_vulns_results']: critical_vulns.append("Injection SQL")

    # Ajouter les ports dangereux à la liste des points critiques
    if "Port 21/tcp : OUVERT" in data['scan_results']: critical_vulns.append("Port FTP ouvert (21)")
    if "Port 22/tcp : OUVERT" in data['scan_results']: critical_vulns.append("Port SSH ouvert (22)")
    if "Port 3389/tcp : OUVERT" in data['scan_results']: critical_vulns.append("Port RDP ouvert (3389)")
    
    risk_level = "Élevé" if critical_vulns else "Moyen"
    resume_executif = f"Un audit de sécurité a été réalisé sur la cible {data['target']}. "
    resume_executif += f"Le niveau de risque global est estimé à **{risk_level}**. "
    if critical_vulns:
        resume_executif += f"Les vulnérabilités critiques suivantes ont été identifiées : {', '.join(critical_vulns)}. "
        resume_executif += "Une correction rapide est impérative."
    else:
        resume_executif += "Quelques vulnérabilités de criticité faible à moyenne ont été trouvées, principalement liées à la configuration du serveur."

    # --- 2. Détail Technique ---
    if data['web_vulns_results'].strip() and "n'a pas été trouvé" not in data['web_vulns_results']:
        detail_technique = data['web_vulns_results']
    else:
        detail_technique = "Le module d'analyse de vulnérabilités web n'a pas été exécuté ou n'a trouvé aucune information pertinente."

    # --- 3. Impact ---
    impact = ""
    if critical_vulns:
        impact += "Un attaquant exploitant ces vulnérabilités pourrait potentiellement:\n"
        if "Injection SQL" in critical_vulns or "Inclusion de Fichier Local (LFI)" in critical_vulns:
            impact += "- Accéder, modifier ou supprimer des données sensibles de la base de données.\n"
            impact += "- Obtenir un accès non autorisé au système de fichiers du serveur.\n"
        if "Injection XSS" in critical_vulns:
            impact += "- Voler les sessions et les cookies des utilisateurs légitimes.\n"
            impact += "- Rediriger les utilisateurs vers des sites malveillants.\n"
    else:
        impact = "L'impact principal des vulnérabilités trouvées est une fuite d'informations sur la configuration du serveur, ce qui pourrait aider un attaquant à préparer une attaque plus sophistiquée."

    # --- 4. Recommandations ---
    recommandations = generate_recommendations(data)

    # --- 5. Annexes ---
    annexes = f"**Résultats OSINT :**\n{data['osint_results']}\n\n**Résultats Scan Réseau :**\n{data['scan_results']}"

    return {
        "resume_executif": resume_executif,
        "detail_technique": detail_technique,
        "impact": impact,
        "recommandations": recommandations,
        "annexes": annexes
    }


def sanitize_filename(filename):
    """Nettoie une chaîne de caractères pour qu'elle soit un nom de fichier valide."""
    return "".join(c for c in filename if c.isalnum() or c in ('.', '-')).rstrip()

def markdown_to_html(text):
    """Convertit une syntaxe Markdown simple (**gras**) en HTML."""
    text = text.replace('**', '<b>', 1) # Première occurrence devient <b>
    text = text.replace('**', '</b>', 1) # Deuxième devient </b>
    return text

def run(target, session_dir):
    """Génère le rapport final en consolidant les résultats d'une session spécifique."""
    print(f"[+] Génération du rapport final professionnel pour la session : {session_dir}...")

    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Nettoyer le nom de la cible pour l'utiliser dans les noms de fichiers
    safe_target_name = sanitize_filename(target)

    report_data = {
        'target': target,
        'start_time': start_time,
        'osint_results': read_output_file('osint.txt', session_dir),
        'scan_results': read_output_file('scan_results.txt', session_dir),
        'web_vulns_results': read_output_file('web_vulns.txt', session_dir),
        'keylog_status': "Fichier de log trouvé." if os.path.exists(os.path.join(session_dir, 'keylogs', 'keylog.txt')) else "Aucun log trouvé.",
        'screenshot_status': "Capture trouvée." if os.path.exists(os.path.join(session_dir, 'screenshots', 'screenshot.png')) else "Aucune capture trouvée.",
        'shell_status': "Tentative de connexion effectuée (vérifier manuellement).",
        'exfil_status': "Succès." if any(f.endswith('.zip.enc') for f in os.listdir(session_dir)) else "Non effectuée ou échec."
    }

    # Charger la configuration de branding
    try:
        with open(os.path.join(os.path.dirname(__file__), '..', 'data', 'report_config.json'), 'r') as f:
            branding_config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        branding_config = {}
    report_data.update(branding_config)

    # Générer le contenu structuré
    professional_content = generate_professional_report(report_data)
    report_data.update(professional_content)

    # --- Création des rapports ---
    report_txt_filename = f"rapport_{safe_target_name}_{timestamp_filename}.txt"
    report_pdf_filename = f"rapport_{safe_target_name}_{timestamp_filename}.pdf"
    report_html_filename = f"rapport_{safe_target_name}_{timestamp_filename}.html"

    # 1. Générer le rapport TXT
    txt_content = f"""RAPPORT D'AUDIT DE SÉCURITÉ - {report_data['target']}
============================================================

## RÉSUMÉ EXÉCUTIF
{report_data['resume_executif']}

## DÉTAIL TECHNIQUE
{report_data['detail_technique']}

## IMPACT MÉTIER
{report_data['impact']}

## RECOMMANDATIONS
{report_data['recommandations']}

## ANNEXES
{report_data['annexes']}
"""
    report_txt_path = os.path.join(OUTPUTS_DIR, report_txt_filename)
    with open(report_txt_path, 'w', encoding='utf-8') as f:
        f.write(txt_content)
    print(f"[+] Rapport TXT généré : {report_txt_filename}")

    # 2. Générer le rapport PDF
    create_pdf_report(report_data, report_pdf_filename)
    print(f"[+] Rapport PDF généré : {report_pdf_filename}")

    # Appliquer la conversion Markdown pour le HTML
    for key, value in report_data.items():
        if isinstance(value, str):
            report_data[key] = markdown_to_html(value)

    # 3. Générer le rapport HTML
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), '..', 'templates')))
    template = env.get_template('report_template.html')
    html_content = template.render(report_data)
    report_html_path = os.path.join(OUTPUTS_DIR, report_html_filename)
    with open(report_html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"[+] Rapport HTML généré : {report_html_filename}")

    return report_txt_filename, report_pdf_filename, report_html_filename


if __name__ == '__main__':
    run(target="exemple.com")