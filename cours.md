### **Cours Complet sur le Framework BlackPyReconX**

#### **Table des Matières**

1.  **Chapitre 1 : Introduction et Philosophie du Framework**
    *   1.1. Qu'est-ce que BlackPyReconX ?
    *   1.2. Architecture Modulaire
    *   1.3. Les Trois Interfaces (CLI, Web, Telegram)
    *   1.4. Avertissement Éthique

2.  **Chapitre 2 : Installation et Configuration**
    *   2.1. Prérequis
    *   2.2. Procédure d'Installation
    *   2.3. Configuration des Clés API (`.env`)
    *   2.4. Configuration du Framework (`config.json`)

3.  **Chapitre 3 : Le Cœur du Framework - Les Modules Utilitaires**
    *   3.1. Le Module `utils.py` : La Colonne Vertébrale
    *   3.2. Le Module `reporting.py` : Génération de Rapports
    *   3.3. Le Module `evasion.py` : Techniques d'Évasion

4.  **Chapitre 4 : Les Modules de Reconnaissance et de Scan**
    *   4.1. Module `osint.py` : Open Source Intelligence
    *   4.2. Module `scanner.py` : Scan de Ports et Bannières
    *   4.3. Module `exploit_web.py` : Analyse de Vulnérabilités Web

5.  **Chapitre 5 : Les Modules d'Exploitation et de Post-Exploitation**
    *   5.1. Module `bruteforce.py` : Attaques par Force Brute
    *   5.2. Module `dos.py` : Attaques par Déni de Service
    *   5.3. Module `exploit_sys.py` : Le Payload Principal (Reverse Shell)
    *   5.4. Module `exfiltration.py` : Vol de Données

6.  **Chapitre 6 : Les Modules Spécialisés**
    *   6.1. Module `sniffer.py` : Capture de Paquets Réseau
    *   6.2. Module `crypto_tools.py` : Outils Cryptographiques et Stéganographie

7.  **Chapitre 7 : Guide d'Utilisation des Interfaces**
    *   7.1. Interface en Ligne de Commande (CLI)
    *   7.2. Interface Web (Dashboard)
    *   7.3. Bot de Contrôle Telegram

---

#### **Chapitre 1 : Introduction et Philosophie du Framework**

##### **1.1. Qu'est-ce que BlackPyReconX ?**

BlackPyReconX est un framework de sécurité offensif, écrit en Python, conçu pour simuler les différentes phases d'un test d'intrusion (pentest). Son but est d'automatiser les tâches répétitives et de fournir une plateforme unifiée pour la reconnaissance, le scan, l'exploitation et le reporting. Il est destiné à un public de professionnels de la sécurité, de chercheurs et d'étudiants souhaitant comprendre les mécanismes d'une attaque informatique dans un cadre légal et éthique.

##### **1.2. Architecture Modulaire**

Le framework est construit autour d'une architecture modulaire. Chaque fonctionnalité principale est isolée dans son propre fichier Python (un "module") dans le dossier `modules/`. Cette approche offre plusieurs avantages :
*   **Maintenance facile :** Mettre à jour ou corriger un bug dans le module de scan n'affecte pas le module OSINT.
*   **Extensibilité :** Il est simple d'ajouter de nouvelles fonctionnalités en créant un nouveau fichier de module et en l'intégrant aux interfaces.
*   **Clarté :** Le code est organisé logiquement, ce qui le rend plus facile à lire et à comprendre.

##### **1.3. Les Trois Interfaces (CLI, Web, Telegram)**

BlackPyReconX peut être contrôlé de trois manières différentes, pour s'adapter à divers scénarios d'utilisation :
1.  **CLI (`main.py`) :** Idéale pour le scripting, l'automatisation et les tâches rapides. Elle offre un contrôle granulaire sur chaque option des modules.
2.  **Interface Web (`app.py`) :** Un tableau de bord visuel et convivial, parfait pour lancer des scans, visualiser les résultats en temps réel et gérer le framework de manière centralisée.
3.  **Bot Telegram (`telegram_bot.py`) :** Permet un contrôle à distance. Un auditeur peut lancer des scans et recevoir des rapports depuis son téléphone, ce qui est utile lors d'audits sur site.

##### **1.4. Avertissement Éthique**

**Cet outil est conçu à des fins éducatives et pour des tests d'intrusion autorisés uniquement.** L'utilisation de BlackPyReconX sur des systèmes ou des réseaux sans une autorisation écrite et explicite du propriétaire est **illégale** et peut entraîner des poursuites judiciaires. Les auteurs de ce framework ne sont en aucun cas responsables d'une utilisation malveillante.

---

#### **Chapitre 2 : Installation et Configuration**

##### **2.1. Prérequis**
*   Python 3.10 ou supérieur.
*   L'outil de gestion de paquets `pip`.
*   (Optionnel mais recommandé) `git` pour cloner le dépôt.

##### **2.2. Procédure d'Installation**
1.  **Cloner le dépôt :**
    ```bash
    git clone <URL_DU_PROJET>
    cd BlackPyReconX
    ```
2.  **Créer un environnement virtuel (recommandé) :**
    ```bash
    python -m venv venv
    # Sur Windows
    venv\Scripts\activate
    # Sur macOS/Linux
    source venv/bin/activate
    ```
3.  **Installer les dépendances :**
    ```bash
    pip install -r requirements.txt
    ```

##### **2.3. Configuration des Clés API (`.env`)**

Certains modules (OSINT, Telegram) nécessitent des clés API pour fonctionner.
1.  Copiez le fichier `.env.example` et renommez-le en `.env`.
2.  Ouvrez le fichier `.env` et remplissez les valeurs :
    ```dotenv
    SHODAN_API_KEY="Votre_Clé_Shodan"
    ABUSEIPDB_API_KEY="Votre_Clé_AbuseIPDB"
    TELEGRAM_BOT_TOKEN="Votre_Token_de_Bot_Telegram"
    ```

##### **2.4. Configuration du Framework (`config.json`)**

Ce fichier stocke l'état de configuration global, principalement pour l'utilisation de Tor. Il est géré automatiquement par l'interface web et le bot Telegram.

---

#### **Chapitre 5 : Les Modules d'Exploitation et de Post-Exploitation**

Ce chapitre couvre les modules conçus pour attaquer activement une cible ou exploiter un accès déjà obtenu. C'est ici que se trouvent les outils les plus puissants et les plus sensibles du framework.

##### **5.1. Module `bruteforce.py` : Attaques par Force Brute**

*   **Objectif :** Tenter de deviner des identifiants (nom d'utilisateur et mot de passe) pour un service réseau (SSH, FTP, etc.) ou un formulaire web.
*   **Modes d'Attaque :**
    1.  **Attaque par Dictionnaire :** Le module essaie toutes les combinaisons possibles entre une liste de noms d'utilisateur (`userlist`) et une liste de mots de passe (`passlist`). C'est la méthode la plus rapide et la plus efficace si les listes sont de bonne qualité.
    2.  **Force Brute Pure :** Pour un nom d'utilisateur donné, le module génère toutes les combinaisons de mots de passe possibles en fonction d'un jeu de caractères (`charset`) et d'une longueur (`min-len`, `max-len`). C'est beaucoup plus lent et n'est utile que pour des mots de passe très courts et simples.
*   **Fonctions Clés :**
    *   `run(attack_type, options)` : La fonction principale qui orchestre l'attaque en fonction des options fournies.
    *   `BruteForceManager` (classe) : Gère la logique de l'attaque, y compris le multi-threading pour lancer des dizaines ou des centaines de tentatives de connexion en parallèle, ce qui est crucial pour la vitesse.
    *   `test_credentials()` : La fonction exécutée par chaque thread. Elle prend une paire d'identifiants, tente de se connecter au service cible, et met le résultat dans une file d'attente.
*   **Services Cibles :** Le module est conçu pour être extensible, mais il cible par défaut les protocoles courants comme SSH (port 22), FTP (21), Telnet (23), et peut même s'attaquer à des formulaires de connexion web.
*   **Commandes CLI :**
    ```bash
    # Attaque par dictionnaire sur un service SSH
    python main.py --target <ip> --bruteforce --service ssh --port 22 --userlist data/users.txt --passlist data/pass.txt

    # Attaque par force brute pure sur un utilisateur 'admin'
    python main.py --target <ip> --bruteforce --attack-type bruteforce --service ssh --port 22 --username admin --min-len 4 --max-len 5
    ```

---

##### **5.2. Module `dos.py` : Attaques par Déni de Service**

*   **Objectif :** Saturer une machine ou un service cible avec un grand nombre de requêtes pour le rendre indisponible pour les utilisateurs légitimes. **C'est un outil extrêmement dangereux.**
*   **Technique Implémentée :** TCP SYN Flood.
    *   Le module envoie une très grande quantité de paquets `SYN` (la première étape d'une connexion TCP) à la cible.
    *   Le serveur de la victime répond avec un paquet `SYN-ACK` et attend la réponse finale (`ACK`) qui ne viendra jamais.
    *   Cela force le serveur à garder de nombreuses connexions "à moitié ouvertes", ce qui épuise ses ressources (mémoire, CPU) jusqu'à ce qu'il ne puisse plus accepter de nouvelles connexions légitimes.
*   **Fonctions Clés :**
    *   `run(target, port, duration, use_tor)` : Lance et gère l'attaque.
    *   `attack_worker()` : La fonction exécutée par de multiples threads. Chaque thread est une boucle infinie qui envoie des paquets `SYN` à la cible aussi vite que possible.
*   **Avertissement :** L'utilisation de ce module sans autorisation est **illégale** et peut causer des dommages importants. Il est inclus à des fins purement éducatives pour comprendre le fonctionnement de ce type d'attaque.
*   **Commande CLI :**
    ```bash
    python main.py --target <ip_cible> --dos --port 80 --duration 120
    ```

---

##### **5.3. Module `exploit_sys.py` : Le Payload Principal (Reverse Shell)**

*   **Objectif :** C'est le module qui génère le "payload" final, un agent malveillant conçu pour être exécuté sur une machine victime afin d'en obtenir le contrôle à distance. (Voir le cours détaillé précédent pour une explication complète).
*   **Fonctionnalités Intégrées :**
    1.  **Agent Dormant :** Ne s'active qu'à une date (`ACTIVATION_DATE`) future pour déjouer les antivirus.
    2.  **Keylogger :** Enregistre toutes les frappes au clavier.
    3.  **Capture d'Écran :** Prend une capture d'écran au moment de l'activation.
    4.  **Reverse Shell :** Établit une connexion sortante vers la machine de l'attaquant, lui donnant un accès à l'invite de commande (`cmd.exe`) de la victime.
    5.  **Persistance :** Tente de se reconnecter en boucle si la connexion est perdue.
*   **Utilisation :** Ce module n'est pas conçu pour être lancé directement. Il est utilisé par le script `build_payload.py` pour être compilé en un fichier `.exe` autonome.
*   **Commande (pour la compilation) :**
    ```bash
    python build_payload.py
    ```

---

##### **5.4. Module `exfiltration.py` : Vol de Données**

*   **Objectif :** Simuler la dernière phase d'une attaque : le vol de données. Ce module collecte, compresse et chiffre les informations sensibles trouvées sur la machine.
*   **Processus :**
    1.  **Collecte :** Le script recherche des fichiers potentiellement intéressants (documents, clés, etc.). Dans notre cas, il se concentre sur le contenu du dossier `outputs/` pour exfiltrer les résultats des autres scans.
    2.  **Compression :** Tous les fichiers trouvés sont regroupés dans une seule archive `.zip` pour faciliter le transfert.
    3.  **Chiffrement :** L'archive `.zip` est chiffrée à l'aide d'une clé `Fernet` (un algorithme de chiffrement symétrique puissant). Cela rend le contenu illisible pour les systèmes de sécurité réseau (DLP).
    4.  **Nettoyage :** L'archive `.zip` originale (non chiffrée) est supprimée pour ne laisser que la version chiffrée (`.zip.enc`) et la clé (`.key`).
*   **Fonctions Clés :**
    *   `run()` : Orchestre le processus complet.
    *   `zip_outputs()` : Gère la compression.
    *   `encrypt_file()` : Gère la génération de la clé et le chiffrement.
*   **Commande CLI :**
    ```bash
    python main.py --exfil
    ```