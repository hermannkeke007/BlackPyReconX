# BlackPyReconX - Un framework d'attaque complet
# Copyright (C) 2025 Hermann KEKE
#
# Ce programme est un logiciel libre ; vous pouvez le redistribuer et/ou le
# modifier selon les termes de la Licence publique générale GNU telle que
# publiée par la Free Software Foundation ; soit la version 3 de la Licence,
# soit (à votre choix) toute version ultérieure.
#
# Vous devriez avoir reçu une copie de la Licence publique générale GNU
# avec ce programme. Si non, voir <https://www.gnu.org/licenses/>.

import argparse
import sys
import os
import time
from rich.console import Console
from rich.panel import Panel
from modules import osint, scanner, exploit_web, exploit_sys, exfiltration, reporting, utils, dos, bruteforce, sniffer, crypto_tools, wireless

console = Console()

def main():
    console.print(Panel(
        "Framework développé par [bold cyan]Hermann KEKE[/bold cyan]", 
        style="bold white", 
        title="[bold green]BlackPyReconX[/bold green]", 
        subtitle="[blue]Framework d'Attaque Complet v1.0[/blue]",
        border_style="bright_magenta",
        title_align="center",
        subtitle_align="center"
    ))
    parser = argparse.ArgumentParser(
        description="""BlackPyReconX - Un framework d'attaque complet et modulaire pour la reconnaissance, l'analyse de vulnérabilités, l'exploitation et la post-exploitation.
        Conçu pour les tests d'intrusion éthiques, il offre une suite d'outils allant de l'OSINT au sniffer réseau, en passant par le bruteforce et la stéganographie.
        """,
        epilog="""
        Pour obtenir de l'aide sur un module spécifique, utilisez :
        python main.py <nom_du_module> --help

        Exemples d'utilisation rapide :
        * OSINT : python main.py osint --target exemple.com
        * Scan : python main.py scan --target exemple.com --tor
        * DoS : python main.py dos --target 192.168.1.1 --port 80 --duration 60
        * Stéganographie (cacher) : python main.py crypto hide --image input.png --file secret.txt --output output.png
        """
    )

    subparsers = parser.add_subparsers(dest="module", help="Modules disponibles")

    # Subparser pour OSINT
    osint_parser = subparsers.add_parser(
        "osint", 
        help="""
        Lance le module de reconnaissance en sources ouvertes (OSINT), y compris la géolocalisation IP.
        Ce module collecte des informations publiques sur une cible, telles que les sous-domaines,
        les adresses e-mail associées, les enregistrements DNS et d'autres données exposées,
        et peut géolocaliser une adresse IP ou un domaine.
        """
    )
    osint_parser.add_argument("--target", help="Cible de l'attaque (domaine ou IP)", required=True)
    osint_parser.add_argument("--geo", action="store_true", help="Afficher les informations de géolocalisation détaillées pour la cible.")

    # Subparser pour Scan
    scan_parser = subparsers.add_parser(
        "scan", 
        help="""
        Lance le module de scan de ports et services.
        Ce module identifie les ports ouverts sur la cible, les services associés,
        et peut détecter des vulnérabilités basiques ou des versions de logiciels.
        """
    )
    scan_parser.add_argument("--target", help="Cible de l'attaque (domaine ou IP)", required=True)

    # Subparser pour Web
    web_parser = subparsers.add_parser(
        "web", 
        help="""
        Lance le module de test de vulnérabilités web.
        Ce module est conçu pour identifier des failles courantes dans les applications web,
        telles que les injections SQL, les XSS, les LFI/RFI, et d'autres erreurs de configuration.
        """
    )
    web_parser.add_argument("--target", help="Cible de l'attaque (domaine ou IP)", required=True)

    # Subparser pour Exploit (système)
    exploit_parser = subparsers.add_parser(
        "exploit", 
        help="""
        Lance le module d'exploitation système.
        Ce module contient des outils et des scripts pour exploiter des vulnérabilités
        au niveau du système d'exploitation ou des services couramment installés.
        """
    )
    exploit_parser.add_argument("--target", help="Cible de l'attaque (domaine ou IP)", required=True)

    # Subparser pour DoS
    dos_parser = subparsers.add_parser(
        "dos", 
        help="""
        Lance une attaque par déni de service (DoS), spécifiquement une attaque TCP Flood.
        Cette attaque vise à submerger une cible avec un grand nombre de requêtes TCP,
        rendant le service indisponible pour les utilisateurs légitimes.
        """
    )
    dos_parser.add_argument("--target", help="Cible de l'attaque (domaine ou IP)", required=True)
    dos_parser.add_argument("--port", type=int, help="Port à utiliser pour l'attaque DoS", required=True)
    dos_parser.add_argument("--duration", type=int, default=60, help="Durée de l'attaque DoS en secondes (défaut: 60)")

    # Subparser pour Brute-Force
    bruteforce_parser = subparsers.add_parser(
        "bruteforce", 
        help="""
        Lance une attaque par brute-force contre divers services (SSH, FTP, Telnet, Web, etc.).
        Prend en charge les attaques par dictionnaire (avec listes d'utilisateurs/mots de passe)
        et les attaques par force brute pure (génération de mots de passe basée sur un jeu de caractères).
        Inclut également des options spécifiques pour les formulaires de connexion web.
        """
    )
    bruteforce_parser.add_argument("--target", help="Cible de l'attaque (domaine ou IP)", required=True)
    bruteforce_parser.add_argument("--service", help="Service à attaquer (ssh, ftp, telnet, etc.)", required=True)
    bruteforce_parser.add_argument("--port", type=int, help="Port à utiliser", required=True)
    bruteforce_parser.add_argument("--attack-type", default='dictionary', choices=['dictionary', 'bruteforce'], help="Type d'attaque: par dictionnaire ou par force brute pure (défaut: dictionary)")
    # Options pour le mode dictionnaire
    bruteforce_parser.add_argument("--userlist", default="data/usernames.txt", help="Chemin vers la liste de noms d'utilisateur (pour le mode dictionnaire)")
    bruteforce_parser.add_argument("--passlist", default="data/passwords.txt", help="Chemin vers la liste de mots de passe (pour le mode dictionnaire)")
    bruteforce_parser.add_argument("--password", help="Mot de passe unique à tester contre une liste d'utilisateurs")
    # Options pour le mode force brute pure
    bruteforce_parser.add_argument("--username", help="Nom d'utilisateur unique à tester (pour le mode force brute)")
    bruteforce_parser.add_argument("--charset", default='alphanum', help="Jeu de caractères à utiliser (ex: alphanum, lower, digits, ou 'abc123') (défaut: alphanum)")
    bruteforce_parser.add_argument("--min-len", type=int, default=4, help="Longueur minimale du mot de passe (défaut: 4)")
    bruteforce_parser.add_argument("--max-len", type=int, default=6, help="Longueur maximale du mot de passe (défaut: 6)")
    # Options de performance
    bruteforce_parser.add_argument("--threads", type=int, default=50, help="Nombre de threads à utiliser (défaut: 50)")
    bruteforce_parser.add_argument("--timeout", type=int, default=5, help="Timeout pour chaque tentative de connexion en secondes (défaut: 5)")
    bruteforce_parser.add_argument("--verbose", action="store_true", help="Afficher chaque tentative de mot de passe")
    # Options pour le mode web
    bruteforce_parser.add_argument("--url", help="URL de la page de connexion pour le mode web")
    bruteforce_parser.add_argument("--user-field", help="Nom du champ utilisateur pour le mode web")
    bruteforce_parser.add_argument("--pass-field", help="Nom du champ mot de passe pour le mode web")
    bruteforce_parser.add_argument("--fail-string", help="Chaîne de caractères indiquant un échec de connexion pour le mode web")

    # Subparser pour Exfiltration
    exfil_parser = subparsers.add_parser(
        "exfil", 
        help="""
        Lance le module d'exfiltration de données.
        Ce module permet de simuler ou de réaliser l'extraction non autorisée
        de données sensibles d'un système cible.
        """
    )

    # Subparser pour Report
    report_parser = subparsers.add_parser(
        "report", 
        help="""
        Génère un rapport final consolidant les résultats des différents modules exécutés.
        Le rapport peut inclure les découvertes OSINT, les vulnérabilités scannées,
        les résultats d'exploitation, etc., pour une cible donnée.
        """
    )
    report_parser.add_argument("--target", help="Cible pour laquelle générer le rapport (optionnel)")

    # Subparser pour Sniffer
    sniffer_parser = subparsers.add_parser(
        "sniff", 
        help="""
        Lance le module sniffer de paquets réseau.
        Permet de capturer et d'analyser le trafic réseau sur une interface spécifiée,
        en utilisant des filtres BPF pour cibler des paquets spécifiques.
        Utile pour l'analyse de protocole ou la détection d'activités suspectes.
        """
    )
    sniffer_parser.add_argument("--iface", choices=['eth0', 'wi-fi', 'bluetooth', 'loopback'], help="Interface réseau à écouter", required=True)
    sniffer_parser.add_argument("--filter", help="Filtre de capture (format BPF)")
    sniffer_parser.add_argument("--count", type=int, default=0, help="Nombre de paquets à capturer (0 pour infini)")
    sniffer_parser.add_argument("--output", help="Fichier de sortie pour la capture (.pcap)")

    # Subparser pour Crypto
    crypto_parser = subparsers.add_parser(
        "crypto", 
        help="""
        Module dédié à la cryptographie et à la stéganographie.
        Permet de cacher des fichiers dans des images (stéganographie) ou de révéler
        des fichiers qui y sont cachés.
        """
    )
    crypto_subparsers = crypto_parser.add_subparsers(dest="crypto_action", help="Actions disponibles pour la cryptographie et la stéganographie")

    # Crypto Stegano Hide
    stegano_hide_parser = crypto_subparsers.add_parser(
        "hide", 
        help="""
        Cache un fichier secret à l'intérieur d'une image en utilisant des techniques de stéganographie.
        L'image résultante aura un aspect visuel similaire à l'originale, mais contiendra le fichier caché.
        """
    )
    stegano_hide_parser.add_argument("--image", help="Chemin de l'image source (PNG/BMP recommandé) où cacher le fichier", required=True)
    stegano_hide_parser.add_argument("--file", help="Chemin du fichier à cacher", required=True)
    stegano_hide_parser.add_argument("--output", help="Chemin du fichier image de sortie où le fichier est caché", required=True)

    # Crypto Stegano Reveal
    stegano_reveal_parser = crypto_subparsers.add_parser(
        "reveal", 
        help="""
        Révèle un fichier secret qui a été caché à l'intérieur d'une image stéganographiée.
        """
    )
    stegano_reveal_parser.add_argument("--image", help="Chemin de l'image stéganographiée contenant le fichier caché", required=True)
    stegano_reveal_parser.add_argument("--output", help="Chemin du fichier de sortie où le fichier révélé sera sauvegardé", required=True)
    
    # Subparser pour Wireless
    wireless_parser = subparsers.add_parser(
        "wireless",
        help="""
        Lance le module d'outils Wi-Fi pour la gestion des interfaces, le scan, la capture et les attaques.
        """
    )
    wireless_subparsers = wireless_parser.add_subparsers(dest="wireless_action", help="Actions disponibles pour le module Wi-Fi")

    # Wireless: list interfaces
    wireless_list_parser = wireless_subparsers.add_parser(
        "list",
        help="Liste les interfaces Wi-Fi disponibles sur le système."
    )

    # Wireless: monitor mode start
    wireless_monitor_start_parser = wireless_subparsers.add_parser(
        "monitor_start",
        help="Active le mode moniteur sur une interface Wi-Fi spécifiée."
    )
    wireless_monitor_start_parser.add_argument("--iface", help="Interface Wi-Fi à passer en mode moniteur (ex: wlan0)", required=True)

    # Wireless: monitor mode stop
    wireless_monitor_stop_parser = wireless_subparsers.add_parser(
        "monitor_stop",
        help="Désactive le mode moniteur sur une interface Wi-Fi spécifiée."
    )
    wireless_monitor_stop_parser.add_argument("--iface", help="Interface Wi-Fi à désactiver du mode moniteur (ex: wlan0mon)", required=True)

    # Wireless: scan networks
    wireless_scan_parser = wireless_subparsers.add_parser(
        "scan",
        help="Scan les réseaux Wi-Fi disponibles sur une interface en mode moniteur."
    )
    wireless_scan_parser.add_argument("--iface", help="Interface Wi-Fi en mode moniteur (ex: wlan0mon)", required=True)
    wireless_scan_parser.add_argument("--duration", type=int, default=10, help="Durée du scan en secondes (défaut: 10)")
    
    # Options générales (comme --tor, si elles s'appliquent à plusieurs modules)
    parser.add_argument("--tor", action="store_true", help="Forcer l'utilisation de TOR pour cette session. Applique un proxy SOCKS5 à toutes les requêtes HTTP/HTTPS effectuées par les modules compatibles.")


    args = parser.parse_args()

    if not hasattr(args, 'module') or args.module is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # L'utilisation de TOR en CLI est maintenant totalement indépendante.
    use_tor_flag = args.tor
    if use_tor_flag:
        utils.log_message('*', "TOR activé via l'argument --tor pour cette session uniquement.")

    # Les modules qui nécessitent une session requests doivent l'initialiser
    # en fonction de l'utilisation de TOR.
    # Pour l'instant, on initialise pour tous les modules potentiellement concernés.
    # Dans une version future, on pourrait rendre cela plus granulaire.
    if args.module in ['osint', 'scan', 'web', 'dos', 'bruteforce']:
        try:
            current_session = utils.get_requests_session(force_tor=use_tor_flag)
            if args.module == 'osint':
                osint.session = current_session
            if args.module == 'web':
                exploit_web.session = current_session
            if args.module == 'bruteforce':
                bruteforce.session = current_session
        except Exception as e:
            utils.log_message('-', f"Impossible d'initialiser la session requests (problème TOR ?): {e}")
            sys.exit(1)

    report_needed = False
    session_dir = None
    if hasattr(args, 'target') and args.target:
        session_dir = utils.get_current_session_dir()
    elif args.module == 'sniff' or args.module == 'exfil':
        session_dir = utils.get_current_session_dir() # Ces modules peuvent aussi créer des fichiers

    # --- Nettoyage sélectif des anciens résultats ---
    # Cette logique devra être revue si les fichiers de sortie sont gérés par session_dir
    # et non plus dans outputs/
    if args.module == 'osint':
        if os.path.exists('outputs/osint.txt'): os.remove('outputs/osint.txt')
    if args.module == 'scan':
        if os.path.exists('outputs/scan_results.txt'): os.remove('outputs/scan_results.txt')
    if args.module == 'web':
        if os.path.exists('outputs/web_vulns.txt'): os.remove('outputs/web_vulns.txt')
    utils.log_message('*', "Les anciens fichiers de résultats pertinents ont été nettoyés (si présents).")


    # Dispatch des commandes
    if args.module == "osint":
        utils.log_message('*', "Lancement du module OSINT...")
        osint.run(args.target, session_dir, geo_flag=args.geo)
        report_needed = True

    elif args.module == "scan":
        utils.log_message('*', "Lancement du module de scan...")
        scanner.run(args.target, session_dir, use_tor=use_tor_flag)
        report_needed = True

    elif args.module == "web":
        utils.log_message('*', "Lancement du module d'exploitation web...")
        exploit_web.run(args.target, session_dir)
        report_needed = True

    elif args.module == "exploit":
        utils.log_message('*', "Lancement du module d'exploitation système...")
        exploit_sys.run(args.target) # Exploit sys n'utilise pas session_dir ou TOR directement
        report_needed = True

    elif args.module == "dos":
        utils.log_message('*', "Lancement du module d'attaque DoS...")
        dos.run(args.target, args.port, args.duration, use_tor=use_tor_flag)

    elif args.module == "bruteforce":
        utils.log_message('*', "Lancement du module d'attaque par brute-force...")
        # Recueillir les options spécifiques au brute-force
        bf_options = {
            'service': args.service,
            'target': args.target,
            'port': args.port,
            'attack_type': args.attack_type,
            'userlist': args.userlist,
            'passlist': args.passlist,
            'password': args.password,
            'username': args.username,
            'charset': args.charset,
            'min_len': args.min_len,
            'max_len': args.max_len,
            'threads': args.threads,
            'timeout': args.timeout,
            'verbose': args.verbose,
            'url': args.url,
            'user_field': args.user_field,
            'pass_field': args.pass_field,
            'fail_string': args.fail_string,
        }
        bruteforce.run(bf_options['attack_type'], bf_options)

    elif args.module == "exfil":
        utils.log_message('*', "Lancement du module d'exfiltration...")
        exfiltration.run()

    elif args.module == "sniff":
        utils.log_message('*', "Lancement du module Sniffer...")
        report_needed = True # Marquer qu'un rapport est nécessaire
        result = sniffer.start(iface=args.iface, filter=args.filter, count=args.count, output=args.output)
        if result.get('error'):
            utils.log_message('-', result['error'])
            sys.exit(1)
        
        utils.log_message('+', result['message'])
        
        # Si count est 0, on attend une interruption manuelle, sinon on attend la fin
        if args.count == 0:
            utils.log_message('*', "Capture en cours... Appuyez sur Ctrl+C pour arrêter.")
            try:
                # Boucle pour maintenir le script en vie pendant que le thread du sniffer tourne
                while sniffer.get_status()['running']:
                    time.sleep(1)
            except KeyboardInterrupt:
                utils.log_message('!', "\nInterruption manuelle détectée. Arrêt de la capture...")
        else:
            utils.log_message('*', f"Capture de {args.count} paquets en cours...")
            while sniffer.get_status()['running']:
                time.sleep(1)

        # On arrête le sniffer dans tous les cas (Ctrl+C ou fin du count)
        stop_result = sniffer.stop(session_dir=session_dir)
        if 'message' in stop_result:
            utils.log_message('+', stop_result['message'])
        elif 'error' in stop_result:
            utils.log_message('-', stop_result['error'])

    elif args.module == "crypto":
        if not hasattr(args, 'crypto_action') or args.crypto_action is None:
            crypto_parser.print_help(sys.stderr)
            sys.exit(1)
        
        if args.crypto_action == "hide":
            utils.log_message('*', "Lancement de la stéganographie (cacher un fichier)...")
            result = crypto_tools.stegano_hide_file(args.image, args.file, args.output)
            utils.log_message('+' if 'Succès' in result else '-', result)
            
        elif args.crypto_action == "reveal":
            utils.log_message('*', "Lancement de la stéganographie (révéler un fichier)...")
            result = crypto_tools.stegano_reveal_file(args.image, args.output)
            utils.log_message('+' if 'Succès' in result else '-', result)
        
    elif args.module == "report":
        utils.log_message('*', "Génération du rapport...")
        # Le rapport peut être généré sans cible si on veut un rapport global
        # ou un rapport sur une session spécifique.
        # Pour l'instant, on conserve la logique avec args.target
        target_for_report = getattr(args, 'target', None) # target n'est pas obligatoire pour le module report
        
        if target_for_report and session_dir is None:
            # Si une cible est donnée mais qu'aucun module n'a créé de session_dir,
            # on doit en créer un pour le rapport.
            session_dir = utils.get_current_session_dir() # Créera un nouveau dossier si inexistant

        if session_dir is None:
            utils.log_message('-', "Impossible de générer un rapport : aucun répertoire de session actif ou spécifié.")
            sys.exit(1)
            
        txt_file, pdf_file, html_file = reporting.run(target_for_report, session_dir)
        utils.log_message('+', f"Rapport TXT généré : {txt_file}")
        utils.log_message('+', f"Rapport PDF généré : {pdf_file}")
        utils.log_message('+', f"Rapport HTML généré : {html_file}")

    elif args.module == "wireless":
        if not hasattr(args, 'wireless_action') or args.wireless_action is None:
            wireless_parser.print_help(sys.stderr)
            sys.exit(1)

        if args.wireless_action == "list":
            utils.log_message('*', "Listing wireless interfaces...")
            interfaces = wireless.list_interfaces()
            if interfaces:
                utils.log_message('+', "Available Wireless Interfaces:")
                for iface in interfaces:
                    utils.log_message('+', f"  - Name: {iface['name']}, Type: {iface['type']}, MAC: {iface['mac']}")
            else:
                utils.log_message('!', "No wireless interfaces found or an error occurred.")

        elif args.wireless_action == "monitor_start":
            utils.log_message('*', f"Attempting to enable monitor mode on {args.iface}...")
            success, new_iface = wireless.enable_monitor_mode(args.iface)
            if success:
                utils.log_message('+', f"Monitor mode enabled successfully. New interface: {new_iface if new_iface else args.iface}")
            else:
                utils.log_message('!', f"Failed to enable monitor mode on {args.iface}. Check permissions and if aircrack-ng is installed.")
        
        elif args.wireless_action == "monitor_stop":
            utils.log_message('*', f"Attempting to disable monitor mode on {args.iface}...")
            success = wireless.disable_monitor_mode(args.iface)
            if success:
                utils.log_message('+', f"Monitor mode disabled successfully on {args.iface}.")
            else:
                utils.log_message('!', f"Failed to disable monitor mode on {args.iface}. Check permissions.")
        
        elif args.wireless_action == "scan":
            utils.log_message('*', f"Starting network scan on {args.iface} for {args.duration} seconds...")
            networks = wireless.scan_networks(args.iface, args.duration)
            if networks:
                utils.log_message('+', "Discovered Networks:")
                for net in networks:
                    utils.log_message('+', f"  ESSID: {net.get('essid', 'N/A')}, BSSID: {net.get('bssid', 'N/A')}, Channel: {net.get('channel', 'N/A')}, Privacy: {net.get('privacy', 'N/A')}, Power: {net.get('power', 'N/A')}")
            else:
                utils.log_message('!', "No networks found or an error occurred during scan.")
        
    utils.log_message('+', "Opérations terminées.")

if __name__ == "__main__":
    main()