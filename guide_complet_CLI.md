### **BlackPyReconX - Manuel de l'Interface en Ligne de Commande (CLI)**

**Version 1.0**

---

### **Page 1 : Introduction à la CLI et Commandes de Base**

#### **1.1 Philosophie de la CLI**

L'interface en ligne de commande (CLI) de BlackPyReconX, accessible via `main.py`, est le cœur du framework. Elle est conçue pour la **puissance, la rapidité et l'automatisation**. Contrairement à l'interface web, la CLI vous donne un accès direct et granulaire à toutes les options de chaque module, ce qui la rend idéale pour les scénarios suivants :
*   **Scripting :** Enchaîner plusieurs commandes pour automatiser des audits sur de multiples cibles.
*   **Tâches rapides :** Lancer un scan spécifique sans avoir à naviguer dans une interface graphique.
*   **Intégration :** Utiliser la sortie de BlackPyReconX comme entrée pour d'autres outils en ligne de commande.

#### **1.2 Syntaxe Fondamentale**

La CLI de BlackPyReconX utilise désormais une structure de sous-commandes, ce qui la rend plus organisée et intuitive. Toutes les commandes suivent la structure de base :

```bash
python main.py [options_globales] <module> [options_du_module]
```

*   `python main.py` : L'appel de base pour exécuter le framework.
*   `[options_globales]` : Options qui affectent le comportement général du framework, comme `--tor`. Ces options doivent toujours être placées **avant** le nom du module.
*   `<module>` : Le nom du module que vous souhaitez exécuter (par exemple, `osint`, `scan`, `dos`, `crypto`).
*   `[options_du_module]` : Arguments spécifiques au module sélectionné (par exemple, `--target <cible>`, `--port <valeur>`).

Pour obtenir une aide détaillée sur les options d'un module, utilisez :
`python main.py <nom_du_module> --help`

#### **1.3 Options Globales**

Ces options affectent plusieurs modules ou le comportement général du framework et sont placées avant le nom du module.

*   `--tor`
    *   **Description :** Force tout le trafic HTTP/S et les scans de ports à passer par le réseau Tor. Cela anonymise votre adresse IP source.
    *   **Prérequis :** Le **Navigateur Tor doit être en cours d'exécution** sur la machine pour que le proxy sur le port 9150 soit disponible.
    *   **Placement :** Doit être placé **avant** le nom du module.
    *   **Exemple :** `python main.py --tor scan --target exemple.com`

---

### **Page 2 : Modules de Reconnaissance et Scan**

#### **2.1 Module OSINT (`osint`)**

*   **Objectif :** Collecter des informations passivement sur une cible depuis des sources ouvertes.
*   **Commande :**
    ```bash
    python main.py osint --target <cible>
    ```
*   **Description :** Ce module lance des requêtes parallèles vers plusieurs API pour agréger des informations publiques (sous-domaines, adresses e-mail, enregistrements DNS, etc.).
    *   **Services interrogés :** `ipinfo.io`, `ip-api.com`, `shodan.io`, `abuseipdb.com`.
    *   **Prérequis :** Les clés API pour Shodan et AbuseIPDB doivent être configurées dans le fichier `.env` pour obtenir des résultats complets.
*   **Options :**
    *   `--target <cible>` : **(Obligatoire)** Spécifie la cible de l'audit (domaine ou IP).
*   **Exemple d'utilisation :**
    ```bash
    # Obtenir des informations publiques sur l'adresse IP 104.21.23.21
    python main.py osint --target 104.21.23.21
    ```

#### **2.2 Module de Scan Réseau (`scan`)**

*   **Objectif :** Scanner activement la cible pour trouver des ports ouverts et identifier les services.
*   **Commande :**
    ```bash
    python main.py scan --target <cible>
    ```
*   **Description :** Ce module effectue un scan multi-thread sur une liste de ports TCP courants. Pour chaque port ouvert, il tente une "prise de bannière" (`banner grabbing`) et une détection basique de l'OS.
*   **Options :**
    *   `--target <cible>` : **(Obligatoire)** Spécifie la cible de l'audit (domaine ou IP).
*   **Exemple d'utilisation :**
    ```bash
    # Scanner les ports de scanme.nmap.org
    python main.py scan --target scanme.nmap.org

    # Scanner les ports via Tor
    python main.py --tor scan --target scanme.nmap.org
    ```

#### **2.3 Module d'Analyse Web (`web`)**

*   **Objectif :** Effectuer des tests de vulnérabilités basiques sur une application web.
*   **Commande :**
    ```bash
    python main.py web --target <url_ou_domaine>
    ```
*   **Description :** Ce module exécute plusieurs tests en parallèle : analyse des en-têtes de sécurité, tests XSS, LFI/SQLi basiques, et recherche de chemins sensibles.
*   **Options :**
    *   `--target <url_ou_domaine>` : **(Obligatoire)** L'URL ou le domaine de l'application web à analyser.
*   **Exemple d'utilisation :**
    ```bash
    # Analyser le site web http://testphp.vulnweb.com
    python main.py web --target http://testphp.vulnweb.com

    # Analyser le site web via Tor
    python main.py --tor web --target http://testphp.vulnweb.com
    ```

---

### **Page 3 : Modules d'Attaque Active**

#### **3.1 Module de Déni de Service (`dos`)**

*   **Objectif :** Lancer une attaque par TCP SYN Flood pour saturer une cible.
*   **AVERTISSEMENT :** À n'utiliser que dans un environnement de laboratoire contrôlé et avec une autorisation explicite. L'attaque par déni de service (DoS) peut être illégale et avoir de graves conséquences.
*   **Commande :**
    ```bash
    python main.py dos --target <ip_cible> --port <port> [--duration <secondes>]
    ```
*   **Options :**
    *   `--target <ip_cible>` : **(Obligatoire)** L'adresse IP de la cible.
    *   `--port <port>` : **(Obligatoire)** Spécifie le port à attaquer (ex: 80 pour un serveur web).
    *   `--duration <secondes>` : Durée de l'attaque en secondes. La valeur par défaut est `60`.
*   **Arrêter l'attaque :**
    *   Pour arrêter une attaque DoS en cours lancée via la CLI, utilisez `Ctrl+C` (KeyboardInterrupt). Le script tentera un arrêt propre des threads d'attaque.
*   **Exemple d'utilisation :**
    ```bash
    # Lancer une attaque DoS sur le port 80 de l'IP 192.168.1.50 pendant 300 secondes
    python main.py dos --target 192.168.1.50 --port 80 --duration 300
    
    # Lancer une attaque DoS via Tor sur le port 443
    python main.py --tor dos --target 192.168.1.50 --port 443 --duration 120
    ```

#### **3.2 Module de Force Brute (`bruteforce`)**

*   **Objectif :** Deviner des mots de passe pour un service.
*   **Commande de base :**
    ```bash
    python main.py bruteforce --target <ip_ou_domaine> --service <nom_service> --port <port> [options...]
    ```
*   **Options Requises :**
    *   `--target <ip_ou_domaine>` : **(Obligatoire)** La cible de l'attaque.
    *   `--service <nom>` : **(Obligatoire)** Le service à attaquer (`ssh`, `ftp`, `telnet`, `web`, etc.).
    *   `--port <port>` : **(Obligatoire)** Le port du service.

*   **Type d'Attaque : Attaque par Dictionnaire (`--attack-type dictionary`, par défaut)**
    *   `--userlist <chemin>` : Chemin vers la liste de noms d'utilisateur. Défaut : `data/usernames.txt`.
    *   `--passlist <chemin>` : Chemin vers la liste de mots de passe. Défaut : `data/passwords.txt`.
    *   `--password <mdp>` : Utiliser un seul mot de passe contre une liste d'utilisateurs. Incompatible avec `--passlist`.
    *   **Exemple :** `python main.py bruteforce --target 192.168.1.50 --service ssh --port 22 --userlist myusers.txt --passlist mypass.txt`

*   **Type d'Attaque : Force Brute Pure (`--attack-type bruteforce`)**
    *   `--username <nom>` : **(Requis)** Le nom d'utilisateur unique à cibler.
    *   `--charset <set>` : Jeu de caractères à utiliser (ex: `alphanum`, `lower`, `digits`, ou une chaîne personnalisée comme `'abc123'`). Défaut : `alphanum`.
    *   `--min-len <num>` / `--max-len <num>` : Longueur minimale et maximale du mot de passe à générer. Défaut : 4-6.
    *   **Exemple :** `python main.py bruteforce --target 192.168.1.50 --service ftp --port 21 --attack-type bruteforce --username admin --max-len 4`

*   **Mode Web (lorsque `--service web`)**
    *   `--url <url_login>` : **(Requis)** L'URL exacte de la page de connexion.
    *   `--user-field <nom>` : **(Requis)** Le nom de l'attribut `name` du champ `input` pour l'utilisateur (ex: `username`, `user_id`).
    *   `--pass-field <nom>` : **(Requis)** Le nom de l'attribut `name` du champ `input` pour le mot de passe (ex: `password`, `pass`).
    *   `--fail-string <texte>` : **(Requis)** La chaîne de caractères qui apparaît sur la page en cas d'échec de connexion (ex: "Mot de passe incorrect").
    *   **Exemple :** `python main.py bruteforce --service web --url http://test.com/login --user-field user --pass-field pass --fail-string "Login failed" --userlist u.txt --passlist p.txt`

*   **Options de Performance (pour toutes les attaques de force brute) :**
    *   `--threads <num>` : Nombre de tentatives simultanées. Défaut : 50.
    *   `--timeout <sec>` : Temps d'attente maximal pour une tentative de connexion. Défaut : 5.
    *   `--verbose` : Affiche chaque tentative, et pas seulement les succès.

---

### **Page 4 : Modules de Post-Exploitation et Utilitaires**

#### **4.1 Module d'Exfiltration (`exfil`)**

*   **Objectif :** Collecter, compresser et chiffrer les fichiers de résultats du dossier `outputs/`.
*   **Commande :**
    ```bash
    python main.py exfil
    ```
*   **Description :** Ce module crée une archive `.zip` de tous les fichiers dans `outputs/`, la chiffre avec une clé `Fernet`, sauvegarde la clé et supprime l'archive non chiffrée.
*   **Note :** Ce module n'a pas besoin de l'argument `--target`.

#### **4.2 Module d'Exploitation Système (`exploit`)**

*   **Objectif :** Lancer des scripts d'exploitation de niveau système.
*   **Commande :**
    ```bash
    python main.py exploit --target <cible>
    ```
*   **Description :** Ce module contient des outils et des scripts pour exploiter des vulnérabilités au niveau du système d'exploitation ou des services couramment installés. **Attention :** Ce module peut inclure des fonctionnalités comme l'exécution d'un keylogger ou l'ouverture d'un reverse shell si le payload est configuré. N'utilisez ce module que dans un environnement contrôlé et avec une autorisation explicite.
*   **Options :**
    *   `--target <cible>` : **(Obligatoire)** La cible de l'exploitation.
*   **Note :** Le script `exploit_sys.py` dans le dossier `modules/` contient la logique réelle du payload.

#### **4.3 Module de Rapport (`report`)**

*   **Objectif :** Générer un rapport final consolidant les résultats des différents modules exécutés.
*   **Commande :**
    ```bash
    python main.py report [--target <cible>]
    ```
*   **Description :** Ce module agrège les découvertes OSINT, les vulnérabilités scannées, les résultats d'exploitation, etc., pour une cible donnée ou pour la dernière session si aucune cible n'est spécifiée et qu'une session est active.
*   **Options :**
    *   `--target <cible>` : **(Optionnel)** La cible pour laquelle générer le rapport. Si omis, le framework tentera de générer un rapport pour la dernière session active.
*   **Exemple :**
    ```bash
    # Générer un rapport pour la cible exemple.com
    python main.py report --target exemple.com
    ```

---

### **Page 5 : Modules Spécialisés (Sniffer & Crypto)**

#### **5.1 Module Sniffer (`sniff`)**

*   **Objectif :** Capturer et analyser le trafic réseau en temps réel.
*   **Commande :**
    ```bash
    python main.py sniff --iface <interface> [--filter "<filtre>"] [--count <num>] [--output <fichier>]
    ```
*   **Description :** Démarre un thread de capture en arrière-plan et affiche les paquets capturés.
*   **Options :**
    *   `--iface <interface>` : **(Obligatoire)** Nom de l'interface à écouter (`eth0`, `wi-fi`, `bluetooth`, `loopback`).
    *   `--filter "<filtre>"` : Applique un filtre au format BPF. **Les guillemets sont importants** si le filtre contient des espaces.
    *   `--count <num>` : S'arrête après avoir capturé `<num>` paquets. `0` pour une capture infinie (par défaut).
    *   `--output <fichier.pcap>` : Sauvegarde la capture brute dans un fichier `.pcap` lisible par Wireshark.
*   **Arrêter la capture :**
    *   Pour arrêter une capture en cours lancée via la CLI, utilisez `Ctrl+C`. Le script tentera un arrêt propre du sniffer.
*   **Exemples :**
    ```bash
    # Capturer le trafic DNS (port 53) sur l'interface 'eth0' pour 100 paquets
    python main.py sniff --iface eth0 --filter "udp port 53" --count 100

    # Capturer tout le trafic sur 'wi-fi' et sauvegarder dans un fichier .pcap (Ctrl+C pour arrêter)
    python main.py sniff --iface wi-fi --output ma_capture.pcap
    ```

#### **5.2 Module de Cryptographie (`crypto`)**

*   **Objectif :** Cacher ou révéler des fichiers dans des images (stéganographie).
*   **Sous-commandes :** Ce module a deux sous-commandes principales : `hide` (cacher) et `reveal` (révéler).

*   **5.2.1 Sous-commande : Cacher un Fichier (`crypto hide`)**
    *   **Commande :**
        ```bash
        python main.py crypto hide --image <image_hote> --file <fichier_secret> --output <image_resultat>
        ```
    *   **Description :** Cache un fichier secret à l'intérieur d'une image en utilisant des techniques de stéganographie. L'image résultante aura un aspect visuel similaire à l'originale, mais contiendra le fichier caché.
    *   **Options :**
        *   `--image <chemin>` : **(Obligatoire)** Le chemin de l'image qui servira de couverture (PNG/BMP recommandé).
        *   `--file <chemin>` : **(Obligatoire)** Le chemin du fichier à cacher.
        *   `--output <chemin>` : **(Obligatoire)** Le chemin du fichier image de sortie où le fichier est caché.
    *   **Exemple :**
        ```bash
        python main.py crypto hide --image images/base.png --file secrets/message.txt --output images/cachee.png
        ```

*   **5.2.2 Sous-commande : Révéler un Fichier (`crypto reveal`)**
    *   **Commande :**
        ```bash
        python main.py crypto reveal --image <image_contenant_secret> --output <fichier_revele>
        ```
    *   **Description :** Révèle un fichier secret qui a été caché à l'intérieur d'une image stéganographiée.
    *   **Options :**
        *   `--image <chemin>` : **(Obligatoire)** Le chemin de l'image stéganographiée contenant le fichier caché.
        *   `--output <chemin>` : **(Obligatoire)** Le chemin du fichier de sortie où le secret extrait sera sauvegardé.
    *   **Exemple :**
        ```bash
        python main.py crypto reveal --image images/cachee.png --output secrets/message_revele.txt
        ```

---

### **Page 6 : Combinaison des Commandes et Scénarios**

La véritable puissance de la CLI réside dans la capacité à combiner les modules pour simuler un test d'intrusion complet en une seule ligne de commande.

#### **Scénario 1 : Audit de base d'un serveur web**

*   **Objectif :** Obtenir des informations publiques, scanner les ports, et analyser les vulnérabilités web d'un serveur.
*   **Commandes :**
    ```bash
    python main.py osint --target exemple.com
    python main.py scan --target exemple.com
    python main.py web --target exemple.com
    python main.py report --target exemple.com
    ```
*   **Déroulement :** Chaque module est lancé séquentiellement, et le module `report` consolide les résultats.

#### **Scénario 2 : Audit furtif via Tor**

*   **Objectif :** Faire la même chose que le scénario 1, mais en faisant passer tout le trafic par le réseau Tor pour masquer son origine.
*   **Commandes :**
    ```bash
    python main.py --tor osint --target exemple.com
    python main.py --tor scan --target exemple.com
    python main.py --tor web --target exemple.com
    python main.py report --target exemple.com # Le rapport n'utilise pas TOR
    ```
*   **Déroulement :** Identique au scénario 1, mais les requêtes des modules `osint`, `scan` et `web` sont routées via le proxy Tor local.

#### **Scénario 3 : Scripting pour un audit de plusieurs cibles**

Vous pouvez utiliser la CLI dans un script pour automatiser les audits.

*   **Exemple (script `audit.bat` sur Windows) :**
    ```batch
    @echo off
    echo Lancement de l'audit pour server1.example.com...
    python main.py osint --target server1.example.com
    python main.py scan --target server1.example.com
    python main.py report --target server1.example.com

    echo Lancement de l'audit pour server2.example.com...
    python main.py osint --target server2.example.com
    python main.py scan --target server2.example.com
    python main.py report --target server2.example.com

    echo Audits terminés.
    ```

