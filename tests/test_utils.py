import os
import sys
import datetime
import re

# Ajouter le chemin du projet au sys.path pour permettre les imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules import utils

def test_log_message_format(capsys):
    """
    Vérifie que log_message formate correctement le message et l'affiche.
    On ne peut pas tester les couleurs, mais on peut vérifier le contenu.
    """
    # 1. Préparation
    level = '+'
    message = "Ceci est un message de test."
    
    # 2. Exécution
    utils.log_message(level, message)
    
    # 3. Vérification
    captured = capsys.readouterr()
    output = captured.out.strip() # Nettoyer les espaces et sauts de ligne

    # Vérifie que le message est bien dans la sortie
    assert message in output
    
    # Vérifie qu'une icône est présente (ex: '[+]')
    assert f'[{level}]' in output

    # Vérifie la présence d'un horodatage au format YYYY-MM-DD HH:MM:SS
    # On utilise une expression régulière pour cela.
    timestamp_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
    assert re.search(timestamp_pattern, output) is not None
