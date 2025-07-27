# BlackPyReconX - Framework d'Attaque Modulaire

BlackPyReconX est un framework de sécurité offensif modulaire écrit en Python, conçu pour automatiser les différentes phases d'un test d'intrusion. Il combine des outils de reconnaissance, de scan, d'exploitation et de reporting dans une interface unifiée, accessible via la ligne de commande, une interface web locale, ou un bot Telegram.

## Fonctionnalités

- **Interfaces Multiples** : Ligne de commande, interface web (Flask), et bot Telegram.
- **Reconnaissance (OSINT)** : Collecte d'informations via des services publics (ipinfo.io, Shodan, AbuseIPDB).
- **Scan Réseau** : Détection de l'OS, des ports ouverts et des bannières de service.
- **Analyse Web** : Détection de vulnérabilités basiques (XSS, LFI, Injection SQL) et analyse des en-têtes de sécurité.
- **Post-Exploitation** : Payload configurable avec keylogger et reverse shell.
- **Exfiltration** : Compression et chiffrement des données collectées.
- **Reporting** : Génération automatique de rapports en format `.txt` et `.pdf`.

## Installation

1.  **Clonez le dépôt :**
    ```bash
    git clone <url_du_depot>
    cd BlackPyReconX
    ```

2.  **Créez un environnement virtuel (recommandé) :**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Sur Windows: venv\Scripts\activate
    ```

3.  **Installez les dépendances :**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configurez les clés API :**
    -   Copiez le fichier `.env.example` en `.env`.
    -   Ouvrez le fichier `.env` et remplissez les clés API requises (Shodan, AbuseIPDB, Telegram).

## Utilisation

### Lancement des Services

Pour lancer l'interface web et le bot Telegram simultanément :

```bash
python start_all.py
```

L'interface web sera disponible à l'adresse `http://127.0.0.1:5000`.

### Ligne de Commande (`main.py`)

La ligne de commande est idéale pour le scripting et les tâches rapides.

**Syntaxe :** `python main.py --target <cible> [modules...]`

**Exemples :**

-   **Lancer un scan complet (OSINT, réseau, web) sur une cible :**
    ```bash
    python main.py --target exemple.com --osint --scan --web
    ```

-   **Lancer une analyse web en utilisant TOR :**
    ```bash
    python main.py --target site-a-tester.com --web --tor
    ```

### Interface Web

L'interface web fournit un tableau de bord visuel pour contrôler toutes les fonctionnalités de l'outil. Entrez une cible, sélectionnez les modules à exécuter, et lancez l'analyse.

### Bot Telegram

Interagissez avec le bot pour lancer des scans et recevoir les résultats à distance. Envoyez la commande `/start` pour commencer.

## Avertissement Éthique

Cet outil est conçu à des fins éducatives et pour les professionnels de la sécurité dans le cadre de tests d'intrusion autorisés. L'utilisation de cet outil sur des systèmes ou des réseaux sans autorisation explicite est illégale. Les auteurs ne sont pas responsables de toute utilisation malveillante.

L'outil d'attaque par déni de service (DoS) est particulièrement puissant et peut causer des dommages importants. Ne l'utilisez jamais sans une autorisation écrite et explicite du propriétaire du système cible.
