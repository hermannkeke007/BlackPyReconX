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

import argparse
import sys
import os
import time
from rich.console import Console
from rich.panel import Panel
from modules import osint, scanner, exploit_web, exploit_sys, exfiltration, reporting, utils, dos, bruteforce, sniffer, crypto_tools

console = Console()

def main():
    # banner = r'''
    # ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗ ██╗   ██╗███████╗██████╗  ██████╗
    # ██╔══██╗██║     ██╔══██╗██╔════╝██║  ██║██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██╔═══██╗
    # ██████╔╝██║     ███████║██║     ███████║██████╔╝ ╚████╔╝ █████╗  ██████╔╝██║   ██║
    # ██╔══██╗██║     ██╔══██║██║     ██╔══██║██╔═══╝   ╚██╔╝  ██╔══╝  ██╔══██╗██║   ██║
    # ██████╔╝███████╗██║  ██║╚██████╗██║  ██║██║        ██║   ███████╗██║  ██║╚██████╔╝
    # ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝
    # '''
    # console.print(Panel(banner, style="bold green", border_style="green"))
    console.print(Panel("Framework développé par [bold cyan]Hermann KEKE[/bold cyan]", style="yellow", title="[bold green]BlackPyReconX[/bold green]", subtitle="[blue]Framework d'Attaque Complet[/blue]"))
    parser = argparse.ArgumentParser(
        description="BlackPyReconX - Framework d'attaque complet",
        epilog="Exemple: python main.py --target exemple.com --osint --scan --tor"
    )
    parser.add_argument("--target", help="Cible de l'attaque (domaine ou IP)")
    
    # Modules
    parser.add_argument("--osint", action="store_true", help="Lancer le module de reconnaissance (OSINT)")
    parser.add_argument("--scan", action="store_true", help="Lancer le module de scan de ports et services")
    parser.add_argument("--web", action="store_true", help="Lancer le module de test de vulnérabilités web")
    parser.add_argument("--exploit", action="store_true", help="Lancer le module d'exploitation système")
    parser.add_argument("--dos", action="store_true", help="Lancer une attaque DoS (TCP Flood)")
    parser.add_argument("--bruteforce", action="store_true", help="Lancer une attaque par brute-force")
    parser.add_argument("--exfil", action="store_true", help="Lancer le module d'exfiltration de données")
    parser.add_argument("--report", action="store_true", help="Générer le rapport final")

    # Module Sniffer
    sniffer_group = parser.add_argument_group('Sniffer Options')
    sniffer_group.add_argument("--sniff", action="store_true", help="Lancer le sniffer de paquets")
    sniffer_group.add_argument("--iface", choices=['eth0', 'wi-fi', 'bluetooth', 'loopback'], help="Interface réseau à écouter (choisir parmi: eth0, wi-fi, bluetooth, loopback)")
    sniffer_group.add_argument("--filter", help="Filtre de capture (format BPF)")
    sniffer_group.add_argument("--count", type=int, default=0, help="Nombre de paquets à capturer (0 pour infini)")
    sniffer_group.add_argument("--output", help="Fichier de sortie pour la capture (.pcap)")

    # Module Crypto
    crypto_group = parser.add_argument_group('Crypto & Stegano Options')
    crypto_group.add_argument("--stegano-hide", action="store_true", help="Cacher un fichier dans une image")
    crypto_group.add_argument("--stegano-reveal", action="store_true", help="Révéler un fichier caché dans une image")
    crypto_group.add_argument("--image", help="Chemin de l'image pour la stéganographie")
    crypto_group.add_argument("--file", help="Chemin du fichier à cacher/révéler")

    # Options générales
    parser.add_argument("--port", type=int, help="Port à utiliser pour l'attaque DoS ou Brute-Force")
    parser.add_argument("--duration", type=int, default=60, help="Durée de l'attaque DoS en secondes (défaut: 60)")
    parser.add_argument("--tor", action="store_true", help="Forcer l'utilisation de TOR pour cette session")
    # Options Brute-Force
    bf_group = parser.add_argument_group('Brute-Force Options')
    bf_group.add_argument("--attack-type", default='dictionary', choices=['dictionary', 'bruteforce'], help="Type d'attaque: par dictionnaire ou par force brute pure (défaut: dictionary)")
    bf_group.add_argument("--service", help="Service à attaquer (ssh, ftp, telnet, etc.)")
    # Options pour le mode dictionnaire
    bf_group.add_argument("--userlist", default="data/usernames.txt", help="Chemin vers la liste de noms d'utilisateur (pour le mode dictionnaire)")
    bf_group.add_argument("--passlist", default="data/passwords.txt", help="Chemin vers la liste de mots de passe (pour le mode dictionnaire)")
    bf_group.add_argument("--password", help="Mot de passe unique à tester contre une liste d'utilisateurs")
    # Options pour le mode force brute pure
    bf_group.add_argument("--username", help="Nom d'utilisateur unique à tester (pour le mode force brute)")
    bf_group.add_argument("--charset", default='alphanum', help="Jeu de caractères à utiliser (ex: alphanum, lower, digits, ou 'abc123') (défaut: alphanum)")
    bf_group.add_argument("--min-len", type=int, default=4, help="Longueur minimale du mot de passe (défaut: 4)")
    bf_group.add_argument("--max-len", type=int, default=6, help="Longueur maximale du mot de passe (défaut: 6)")
    # Options de performance
    bf_group.add_argument("--threads", type=int, default=50, help="Nombre de threads à utiliser (défaut: 50)")
    bf_group.add_argument("--timeout", type=int, default=5, help="Timeout pour chaque tentative de connexion en secondes (défaut: 5)")
    bf_group.add_argument("--verbose", action="store_true", help="Afficher chaque tentative de mot de passe")
    # Options pour le mode web
    bf_group.add_argument("--url", help="URL de la page de connexion pour le mode web")
    bf_group.add_argument("--user-field", help="Nom du champ utilisateur pour le mode web")
    bf_group.add_argument("--pass-field", help="Nom du champ mot de passe pour le mode web")
    bf_group.add_argument("--fail-string", help="Chaîne de caractères indiquant un échec de connexion pour le mode web")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()

    # --- Gestion des modules autonomes (Crypto) ---
    if args.stegano_hide:
        if not all([args.image, args.file, args.output]):
            utils.log_message('-', "Les arguments --image, --file, et --output sont requis pour --stegano-hide.")
            sys.exit(1)
        result = crypto_tools.stegano_hide_file(args.image, args.file, args.output)
        utils.log_message('+' if 'Succès' in result else '-', result)
        sys.exit(0)

    if args.stegano_reveal:
        if not all([args.image, args.output]):
            utils.log_message('-', "Les arguments --image et --output sont requis pour --stegano-reveal.")
            sys.exit(1)
        result = crypto_tools.stegano_reveal_file(args.image, args.output)
        utils.log_message('+' if 'Succès' in result else '-', result)
        sys.exit(0)

    if not args.target and not args.exfil and not args.sniff:
        utils.log_message('-', "L'argument --target est obligatoire pour la plupart des modules.")
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.target:
        utils.log_message('*', f"Cible configurée : {args.target}")
        # Créer un répertoire de session pour cette exécution
        session_dir = utils.get_current_session_dir()
    else:
        session_dir = None

    # --- Nettoyage sélectif des anciens résultats ---
    if args.osint:
        if os.path.exists('outputs/osint.txt'): os.remove('outputs/osint.txt')
    if args.scan:
        if os.path.exists('outputs/scan_results.txt'): os.remove('outputs/scan_results.txt')
    if args.web:
        if os.path.exists('outputs/web_vulns.txt'): os.remove('outputs/web_vulns.txt')
    utils.log_message('*', "Les anciens fichiers de résultats pertinents ont été nettoyés.")

    # L'utilisation de TOR en CLI est maintenant totalement indépendante.
    use_tor_flag = args.tor
    if use_tor_flag:
        utils.log_message('*', "TOR activé via l'argument --tor pour cette session uniquement.")

    report_needed = False

    # La session est créée en passant directement le flag, sans lire de config
    if args.osint or args.web:
        osint.session = utils.get_requests_session(force_tor=use_tor_flag)
        exploit_web.session = utils.get_requests_session(force_tor=use_tor_flag)

    if args.osint:
        utils.log_message('*', "Lancement du module OSINT...")
        osint.run(args.target, session_dir)
        report_needed = True
    
    if args.scan:
        utils.log_message('*', "Lancement du module de scan...")
        scanner.run(args.target, session_dir, use_tor=use_tor_flag)
        report_needed = True

    if args.web:
        utils.log_message('*', "Lancement du module d'exploitation web...")
        exploit_web.run(args.target, session_dir)
        report_needed = True

    if args.exploit:
        utils.log_message('*', "Lancement du module d'exploitation système...")
        exploit_sys.run(args.target)
        report_needed = True # L'exploitation doit aussi être dans le rapport

    if args.dos:
        if not args.port:
            utils.log_message('-', "L'argument --port est obligatoire pour l'attaque DoS.")
            sys.exit(1)
        utils.log_message('*', "Lancement du module d'attaque DoS...")
        dos.run(args.target, args.port, args.duration, use_tor=use_tor_flag)

    if args.bruteforce:
        if not args.service or not args.port:
            utils.log_message('-', "Les arguments --service et --port sont obligatoires pour l'attaque par brute-force.")
            sys.exit(1)

        options = {
            'service': args.service,
            'target': args.target,
            'port': args.port,
        }

        if args.attack_type == 'dictionary':
            if args.password and args.passlist != 'data/passwords.txt':
                utils.log_message('-', "Les arguments --passlist et --password ne peuvent pas être utilisés en même temps.")
                sys.exit(1)
            options.update({
                'userlist': args.userlist,
                'passlist': args.passlist if not args.password else None,
                'password': args.password
            })
            if args.service == 'web':
                if not all([args.url, args.user_field, args.pass_field, args.fail_string]):
                    utils.log_message('-', "Les arguments --url, --user-field, --pass-field, et --fail-string sont obligatoires pour le mode web.")
                    sys.exit(1)
                options.update({
                    'url': args.url,
                    'user_field': args.user_field,
                    'pass_field': args.pass_field,
                    'fail_string': args.fail_string
                })

        elif args.attack_type == 'bruteforce':
            if not args.username:
                utils.log_message('-', "L'argument --username est obligatoire pour le mode force brute.")
                sys.exit(1)
            options.update({
                'username': args.username,
                'charset': args.charset,
                'min_len': args.min_len,
                'max_len': args.max_len,
            })

        # Ajout des options de performance
        options.update({
            'threads': args.threads,
            'timeout': args.timeout,
            'verbose': args.verbose,
        })

        bruteforce.run(args.attack_type, options)

    if args.exfil:
        utils.log_message('*', "Lancement du module d'exfiltration...")
        exfiltration.run()

    if args.sniff:
        utils.log_message('*', "Lancement du module Sniffer...")
        result = sniffer.start(iface=args.iface, filter=args.filter, count=args.count, output=args.output)
        if result.get('error'):
            utils.log_message('-', result['error'])
            sys.exit(1)
        
        utils.log_message('+', result['message'])
        utils.log_message('*', "Appuyez sur Ctrl+C pour arrêter la capture.")

        try:
            while True:
                status = sniffer.get_status()
                if not status['running'] and args.count > 0:
                    break # Sortir si le nombre de paquets est atteint
                
                for packet in status['packets']:
                    console.print(f"  [green]Paquet capturé:[//] {packet}")
                time.sleep(1)
        except KeyboardInterrupt:
            utils.log_message('!', "\nInterruption manuelle détectée. Arrêt de la capture...")
        finally:
            stop_result = sniffer.stop()
            if 'message' in stop_result:
                utils.log_message('+', stop_result['message'])
            elif 'error' in stop_result:
                utils.log_message('-', stop_result['error'])
            sys.exit(0)

    # Génération du rapport si nécessaire ou demandé
    if report_needed or args.report:
        utils.log_message('*', "Génération du rapport...")
        txt_file, pdf_file, html_file = reporting.run(args.target, session_dir)
        utils.log_message('+', f"Rapport TXT généré : {txt_file}")
        utils.log_message('+', f"Rapport PDF généré : {pdf_file}")
        utils.log_message('+', f"Rapport HTML généré : {html_file}")
        
    utils.log_message('+', "Opérations terminées.")

if __name__ == "__main__":
    main()
