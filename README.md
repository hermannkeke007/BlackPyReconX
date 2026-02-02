# BlackPyReconX - Framework d'Attaque Modulaire

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Status-En%20D%C3%A9veloppement-orange" alt="Status">
</p>

<p align="center">
  <i>Un framework de sécurité offensif complet, conçu pour l'automatisation et l'efficacité des tests d'intrusion.</i>
</p>

---

**BlackPyReconX** est un framework de sécurité offensif modulaire écrit en Python. Il unifie une suite d'outils puissants pour la reconnaissance, le scan, l'exploitation et la post-exploitation dans une interface de contrôle unique, accessible via la ligne de commande (CLI), une interface web, ou un bot Telegram.

## ⚠️ Avertissement Éthique

Cet outil est conçu à des fins **éducatives** et pour les **professionnels de la sécurité** dans le cadre de tests d'intrusion **autorisés**. L'utilisation de cet outil sur des systèmes ou des réseaux sans une autorisation explicite et écrite est **illégale**. Les auteurs ne sont en aucun cas responsables d'une utilisation malveillante ou de dommages causés par cet outil.

---

## ✨ Fonctionnalités Principales

*   **Interfaces Multiples :**
    *   **CLI Puissante :** Pour le scripting, l'automatisation et un contrôle granulaire.
    *   **Interface Web Conviviale :** Un tableau de bord pour piloter les scans, visualiser les résultats et gérer le framework.
    *   **Bot Telegram :** Pour un contrôle et des notifications à distance.

*   **Reconnaissance & OSINT :**
    *   Agrégation d'informations depuis `ipinfo.io`, `Shodan`, `AbuseIPDB`, etc.

*   **Scan & Analyse :**
    *   Scan de ports multi-thread rapide.
    *   Prise de bannières de services.
    *   Analyse de vulnérabilités web (XSS, LFI, SQLi basiques, en-têtes de sécurité).
    *   Découverte de fichiers et dossiers sensibles.

*   **Exploitation & Post-Exploitation :**
    *   Attaques par force brute (Dictionnaire & Pure) sur les services `ssh`, `ftp`, `telnet`.
    *   Attaque par déni de service (TCP SYN Flood).
    *   Génération de payload `.exe` pour Windows avec **reverse shell**, **keylogger**, et **capture d'écran**.

*   **Utilitaires Spécialisés :**
    *   **Sniffer réseau** pour capturer le trafic en temps réel.
    *   Outils de **stéganographie** pour cacher des fichiers dans des images.
    *   Module d'**exfiltration** pour compresser et chiffrer les données collectées.

*   **Reporting Automatisé :**
    *   Génération de rapports professionnels et personnalisables aux formats `.txt`, `.pdf`, et `.html`.

---

## 🚀 Installation

*  **Vous mettre d'abord en adminitarteur**

1.  **Clonez le dépôt :**
    ```bash
    git clone https://github.com/hermannkeke007/BlackPyReconX.git
    cd BlackPyReconX
    ```

2.  **Créez un environnement virtuel (recommandé) :**
    ```bash
    python -m venv venv
    # Sur Windows
    venv\Scripts\activate
    # Sur macOS/Linux
    source venv/bin/activate
    ```

3.  **Installez les dépendances :**
    ```bash
    pip install -r requirements.txt
    ```
  **Pour utilser Tor vous devez avoir installer tor browser et être connecté(e)**
  
4.  **Configurez les clés API :**
    *   Copiez le fichier `.env.example` et renommez-le en `.env`.
    *   Ouvrez le fichier `.env` et remplissez les clés API requises (Shodan, AbuseIPDB, Telegram).
5.  **Créer un dossier nommé "outputs" dans la racine du projet :**
---

## 🕹️ Guide d'Utilisation Rapide

### Lancement des Services

Pour lancer l'interface web et le bot Telegram simultanément :
```bash
python start_all.py
```
L'interface web sera disponible à l'adresse `http://127.0.0.1:5000`.

### Exemples de Commandes CLI

La CLI est l'outil le plus puissant du framework.

*   **Lancer une reconnaissance OSINT sur une cible :**
    ```bash
    python main.py osint --target exemple.com
    ```

*   **Lancer un scan de ports sur une cible en utilisant Tor :**
    ```bash
    # Assurez-vous que le Navigateur Tor est lancé !
    python main.py scan --target site-a-tester.com --tor
    ```

*   **Lancer une analyse web sur une cible :**
    ```bash
    python main.py web --target site-a-tester.com
    ```

*   **Lancer une attaque DoS sur une cible et un port pendant 60 secondes :**
    ```bash
    python main.py dos --target 192.168.1.1 --port 80 --duration 60
    ```

*   **Lancer une attaque de force brute SSH par dictionnaire :**
    ```bash
    python main.py bruteforce --target 192.168.1.10 --service ssh --port 22 --userlist data/usernames.txt --passlist data/passwords.txt
    ```

*   **Capturer le trafic DNS et le sauvegarder :**
    ```bash
    python main.py sniff --iface eth0 --filter "udp port 53" --output capture_dns.pcap
    ```

*   **Cacher un fichier dans une image (stéganographie) :**
    ```bash
    python main.py crypto hide --image input.png --file secret.txt --output output.png
    ```

*   **Révéler un fichier d'une image stéganographiée :**
    ```bash
    python main.py crypto reveal --image output.png --output revealed_secret.txt
    ```

*   **Générer un rapport pour une cible :**
    ```bash
    # Assurez-vous d'avoir exécuté un module comme osint, scan ou web au préalable.
    python main.py report --target exemple.com
    ```

*   **Compiler un payload de reverse shell :**
    ```bash
    # 1. Configurez votre IP dans modules/exploit_sys.py
    # 2. Lancez le build
    python build_payload.py
    # 3. Récupérez le .exe dans le dossier /payloads
    ```

---

## 🏛️ Architecture du Projet

```
BlackPyReconX/
├── modules/           # Cœur du framework, chaque fichier est une fonctionnalité
│   ├── osint.py
│   ├── scanner.py
│   ├── exploit_web.py
│   ├── bruteforce.py
│   └── ...
├── data/              # Données utilisées par les modules (wordlists, etc.)
├── outputs/           # Tous les résultats et rapports sont sauvegardés ici
├── templates/         # Fichiers HTML pour l'interface web et les rapports
├── main.py            # Point d'entrée de la CLI
├── app.py             # Application web Flask
├── start_all.py       # Script pour lancer tous les services
├── build_payload.py   # Script pour compiler le payload Windows
└── requirements.txt   # Dépendances Python
```

---

## 🗺️ Feuille de Route (Roadmap)

Voici quelques-unes des fonctionnalités prévues pour les futures versions :

-   [ ] **Amélioration du Bruteforce :** Support de plus de services (RDP, SMB) et de l'authentification web plus complexe.
-   [ ] **Payloads Multi-plateformes :** Génération de payloads pour Linux et macOS.
-   [ ] **Visualisation des Données :** Graphiques et tableaux de bord plus avancés dans l'interface web.
-   [ ] **Persistance Avancée :** Ajout de techniques de persistance pour le payload (ex: clés de registre, services).
-   [ ] **Intégration de Nouveaux Outils :** Ajout de modules pour des outils comme Nmap, SQLMap, etc.

---

## 🚀 Nouveautés Récentes

*   **Correction du bug de suppression de rapports :** Le mécanisme de suppression des rapports a été amélioré pour gérer correctement les requêtes du frontend et permettre la suppression de plusieurs rapports à la fois.
*   **Mises à jour des modules :** Diverses améliorations et corrections ont été apportées aux modules `DoS`, `Telegram Bot` et `Utilitaires`.
*   **Améliorations de l'interface web :** Des ajustements ont été réalisés sur les pages de rapports et d'utilitaires pour une meilleure expérience utilisateur.
*   **Mise à jour de la documentation CLI :** La documentation `guide_complet_CLI.md` a été révisée.

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Si vous souhaitez améliorer le projet, n'hésitez pas à forker le dépôt, à créer une nouvelle branche et à soumettre une Pull Request.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---
