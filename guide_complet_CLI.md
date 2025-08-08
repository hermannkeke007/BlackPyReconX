BlackPyReconX - Manuel de l'Interface en Ligne de Commande (CLI)

  Version 1.0

  ---

  Page 1 : Introduction à la CLI et Commandes de Base

  1.1 Philosophie de la CLI

  L'interface en ligne de commande (CLI) de BlackPyReconX, accessible via main.py, est le cœur du framework. Elle est conçue pour la puissance, la
  rapidité et l'automatisation. Contrairement à l'interface web, la CLI vous donne un accès direct et granulaire à toutes les options de chaque module,
  ce qui la rend idéale pour les scénarios suivants :
   * Scripting : Enchaîner plusieurs commandes pour automatiser des audits sur de multiples cibles.
   * Tâches rapides : Lancer un scan spécifique sans avoir à naviguer dans une interface graphique.
   * Intégration : Utiliser la sortie de BlackPyReconX comme entrée pour d'autres outils en ligne de commande.

  1.2 Syntaxe Fondamentale

  Toutes les commandes suivent la même structure de base :

   1 python main.py [--target <cible>] [--module1] [--module2] [--option_module1 <valeur>] ...

   * python main.py : L'appel de base pour exécuter le framework.
   * --target <cible> : (Quasi-obligatoire) Spécifie la cible de l'audit. Il peut s'agir d'un nom de domaine (exemple.com), d'une adresse IPv4 (8.8.8.8),
     ou d'une URL pour les modules web.
   * --<module> : Des "drapeaux" (action="store_true") qui activent un module spécifique. Par exemple, --osint active le module OSINT.
   * --<option> <valeur> : Des arguments qui passent une valeur à un module (ex: --port 80).

  1.3 Options Globales

  Ces options affectent plusieurs modules ou le comportement général du framework.

   * --target <cible>
       * Description : Définit la cible principale pour les modules de scan.
       * Exemple : python main.py --target exemple.com ...

   * --tor
       * Description : Force tout le trafic HTTP/S et les scans de ports à passer par le réseau Tor. Cela anonymise votre adresse IP source.
       * Prérequis : Le Navigateur Tor doit être en cours d'exécution sur la machine pour que le proxy sur le port 9150 soit disponible.
       * Exemple : python main.py --target <cible> --scan --tor

   * --report
       * Description : Force la génération d'un rapport complet (.txt, .pdf, .html) à la fin de l'exécution, même si aucun module de scan n'a été lancé
         (utile pour regénérer un rapport à partir de résultats existants).
       * Exemple : python main.py --target <cible> --report

  ---

  Page 2 : Modules de Reconnaissance et Scan

  2.1 Module OSINT (`--osint`)

   * Objectif : Collecter des informations passivement sur une cible depuis des sources externes.
   * Commande :
   1     python main.py --target <cible> --osint
   * Fonctionnement : Ce module lance des requêtes parallèles vers plusieurs API pour agréger des informations.
       * Services interrogés : ipinfo.io, ip-api.com, shodan.io, abuseipdb.com.
       * Prérequis : Les clés API pour Shodan et AbuseIPDB doivent être configurées dans le fichier .env pour obtenir des résultats complets.
   * Exemple d'utilisation :

   1     # Obtenir des informations publiques sur l'adresse IP 104.21.23.21
   2     python main.py --target 104.21.23.21 --osint

  2.2 Module de Scan Réseau (`--scan`)

   * Objectif : Scanner activement la cible pour trouver des ports ouverts et identifier les services.
   * Commande :
   1     python main.py --target <cible> --scan
   * Fonctionnement :
       * Lance un scan multi-thread sur une liste de ports TCP courants (21, 22, 80, 443, etc.).
       * Pour chaque port ouvert, il tente une "prise de bannière" (banner grabbing) pour identifier la version du service.
       * Tente une détection basique de l'OS via l'analyse du TTL des paquets.
   * Options Associées :
       * --tor : Le scan de ports sera beaucoup plus lent mais passera par le réseau Tor.
   * Exemple d'utilisation :

   1     # Scanner les ports de scanme.nmap.org
   2     python main.py --target scanme.nmap.org --scan

  2.3 Module d'Analyse Web (`--web`)

   * Objectif : Effectuer des tests de vulnérabilités basiques sur une application web.
   * Commande :
   1     python main.py --target <url_ou_domaine> --web
   * Fonctionnement : Ce module exécute plusieurs tests en parallèle :
       * Analyse des en-têtes de sécurité : Vérifie la présence d'en-têtes comme Content-Security-Policy, X-Frame-Options, etc.
       * Test XSS : Recherche des formulaires sur la page et injecte des payloads XSS basiques pour voir s'ils sont reflétés.
       * Test LFI/SQLi : Teste les paramètres dans l'URL pour des vulnérabilités d'inclusion de fichiers locaux (LFI) et d'injection SQL (SQLi) basées
         sur les erreurs.
       * Recherche de chemins sensibles : Utilise une liste de mots (data/common_paths.txt) pour trouver des fichiers et dossiers cachés (ex: /admin,
         /.git, /backup).
   * Options Associées :
       * --tor : Toutes les requêtes web passeront par Tor.
   * Exemple d'utilisation :
   1     # Analyser le site web http://testphp.vulnweb.com
   2     python main.py --target http://testphp.vulnweb.com --web

  ---

  Page 3 : Modules d'Attaque Active

  3.1 Module de Déni de Service (`--dos`)

   * Objectif : Lancer une attaque par TCP SYN Flood pour saturer une cible.
   * AVERTISSEMENT : À n'utiliser que dans un environnement de laboratoire contrôlé et avec une autorisation explicite.
   * Commande :
   1     python main.py --target <ip_cible> --dos --port <port> [--duration <secondes>]
   * Options Requises :
       * --port <port> : Spécifie le port à attaquer (ex: 80 pour un serveur web).
   * Options Optionnelles :
       * --duration <secondes> : Durée de l'attaque en secondes. La valeur par défaut est 60.
   * Exemple d'utilisation :

   1     # Lancer une attaque DoS sur le port 80 de l'IP 192.168.1.50 pendant 300 secondes
   2     python main.py --target 192.168.1.50 --dos --port 80 --duration 300

  3.2 Module de Force Brute (`--bruteforce`)

   * Objectif : Deviner des mots de passe pour un service.
   * Commande de base :

   1     python main.py --target <ip> --bruteforce --service <nom_service> --port <port> [options...]
   * Options Requises :
       * --service <nom> : Le service à attaquer (ssh, ftp, telnet, web, etc.).
       * --port <port> : Le port du service.

   * Sous-Module : Attaque par Dictionnaire (`--attack-type dictionary`, par défaut)
       * --userlist <chemin> : Chemin vers la liste de noms d'utilisateur. Défaut : data/usernames.txt.
       * --passlist <chemin> : Chemin vers la liste de mots de passe. Défaut : data/passwords.txt.
       * --password <mdp> : Utiliser un seul mot de passe contre une liste d'utilisateurs. Incompatible avec --passlist.
       * Exemple : python main.py --target 192.168.1.50 --bruteforce --service ssh --port 22 --userlist myusers.txt --passlist mypass.txt

   * Sous-Module : Force Brute Pure (`--attack-type bruteforce`)
       * --username <nom> : (Requis) Le nom d'utilisateur unique à cibler.
       * --charset <set> : Jeu de caractères à utiliser. Défaut : alphanum.
       * --min-len <num> / --max-len <num> : Longueur minimale et maximale du mot de passe à générer. Défaut : 4-6.
       * Exemple : python main.py --target 192.168.1.50 --bruteforce --attack-type bruteforce --service ftp --port 21 --username admin --max-len 4

   * Sous-Module : Attaque de Formulaire Web (`--service web`)
       * Nécessite les options de l'attaque par dictionnaire, plus :
       * --url <url_login> : (Requis) L'URL exacte de la page de connexion.
       * --user-field <nom> : (Requis) Le nom du champ input pour l'utilisateur (ex: username, user_id).
       * --pass-field <nom> : (Requis) Le nom du champ input pour le mot de passe (ex: password, pass).
       * --fail-string <texte> : (Requis) Le message qui apparaît sur la page en cas d'échec de connexion (ex: "Mot de passe incorrect").
       * Exemple : python main.py --bruteforce --service web --url http://test.com/login --user-field user --pass-field pass --fail-string "Login failed"
         --userlist u.txt --passlist p.txt

   * Options de Performance (pour toutes les attaques de force brute) :
       * --threads <num> : Nombre de tentatives simultanées. Défaut : 50.
       * --timeout <sec> : Temps d'attente maximal pour une tentative de connexion. Défaut : 5.
       * --verbose : Affiche chaque tentative, et pas seulement les succès.

  ---

  Page 4 : Modules de Post-Exploitation et Utilitaires

  4.1 Module d'Exfiltration (`--exfil`)

   * Objectif : Collecter, compresser et chiffrer les fichiers de résultats du dossier outputs/.
   * Commande :
   1     python main.py --exfil
   * Fonctionnement :
       1. Crée une archive .zip de tous les fichiers dans outputs/.
       2. Génère une clé de chiffrement Fernet.
       3. Chiffre l'archive, créant un fichier .zip.enc.
       4. Sauvegarde la clé dans outputs/encryption_key.key.
       5. Supprime l'archive .zip non chiffrée.
   * Note : Ce module n'a pas besoin de l'argument --target.

  4.2 Module de Payload (`--exploit`)

   * Objectif : Simuler l'exécution du payload exploit_sys.py sur la machine locale.
   * AVERTISSEMENT : Lancer ce module activera le keylogger et le reverse shell sur votre propre machine. À n'utiliser que pour des tests de
     fonctionnement du payload.
   * Commande :
   1     python main.py --exploit
   * Note : Ce module est principalement destiné au débogage du payload lui-même. L'utilisation normale se fait via la compilation avec build_payload.py
     et l'exécution sur une machine cible.

  ---

  Page 5 : Modules Spécialisés (Sniffer & Crypto)

  5.1 Module Sniffer (`--sniff`)

   * Objectif : Capturer et afficher le trafic réseau en temps réel.
   * Commande :

   1     python main.py --sniff [--iface <interface>] [--filter "<filtre>"] [--count <num>] [--output <fichier>]
   * Fonctionnement :
       * Démarre un thread de capture en arrière-plan.
       * Le script principal entre dans une boucle pour afficher les paquets capturés au fur et à mesure.
       * Appuyez sur Ctrl+C pour arrêter la capture et sauvegarder les résultats si demandé.
   * Options :
       * --iface <interface> : Nom de l'interface à écouter (eth0, wi-fi, etc.). Si omis, le script tente de choisir la meilleure interface disponible.
       * --filter "<filtre>" : Applique un filtre au format BPF. Les guillemets sont importants si le filtre contient des espaces.
       * --count <num> : S'arrête après avoir capturé <num> paquets. 0 pour infini (par défaut).
       * --output <fichier.pcap> : Sauvegarde la capture brute dans un fichier .pcap lisible par Wireshark.
   * Exemples :

   1     # Écouter tout le trafic sur l'interface par défaut
   2     python main.py --sniff
   3
   4     # Capturer le trafic DNS (port 53) sur l'interface 'eth0'
   5     python main.py --sniff --iface eth0 --filter "udp port 53"

  5.2 Module de Cryptographie (`--stegano-hide` / `--stegano-reveal`)

   * Objectif : Cacher ou révéler des fichiers dans des images PNG.
   * Sous-Module : Cacher un Fichier (`--stegano-hide`)
       * Commande :
   1         python main.py --stegano-hide --image <image_hote.png> --file <fichier_secret> --output <image_resultat.png>
       * Options Requises :
           * --image <chemin> : L'image qui servira de couverture.
           * --file <chemin> : Le fichier à cacher.
           * --output <chemin> : Le nom du fichier image de sortie.

   * Sous-Module : Révéler un Fichier (`--stegano-reveal`)
       * Commande :

   1         python main.py --stegano-reveal --image <image_contenant_secret.png> --output <fichier_revele>
       * Options Requises :
           * --image <chemin> : L'image à analyser.
           * --output <chemin> : Le nom du fichier où sera sauvegardé le secret extrait.

  ---

  Page 6 : Combinaison des Commandes et Scénarios

  La véritable puissance de la CLI réside dans la capacité à combiner les modules pour simuler un test d'intrusion complet en une seule ligne de
  commande.

  Scénario 1 : Audit de base d'un serveur web

   * Objectif : Obtenir des informations publiques, scanner les ports, et analyser les vulnérabilités web d'un serveur.
   * Commande :
   1     python main.py --target exemple.com --osint --scan --web --report
   * Déroulement :
       1. Le module OSINT est lancé.
       2. Le module de scan de ports est lancé.
       3. Le module d'analyse web est lancé.
       4. À la fin, le module de reporting est appelé automatiquement (report_needed = True) pour agréger tous les résultats dans des rapports .txt, .pdf
          et .html.

  Scénario 2 : Audit furtif via Tor

   * Objectif : Faire la même chose que le scénario 1, mais en faisant passer tout le trafic par le réseau Tor pour masquer son origine.
   * Commande :
   1     python main.py --target exemple.com --osint --scan --web --report --tor
   * Déroulement : Identique au scénario 1, mais chaque requête HTTP et chaque tentative de connexion pour le scan de port sera routée via le proxy Tor
     local.

  Scénario 3 : Scripting pour un audit de plusieurs cibles

  Vous pouvez utiliser la CLI dans un script pour automatiser les audits.

   * Exemple (script `audit.bat` sur Windows) :

   1     @echo off
   2     echo Lancement de l'audit pour server1.example.com...
   3     python main.py --target server1.example.com --scan --report
   4
   5     echo Lancement de l'audit pour server2.example.com...
   6     python main.py --target server2.example.com --scan --report
   7
   8     echo Audits terminés.

  Ce manuel devrait vous servir de référence complète pour toutes les opérations possibles via la ligne de commande.