
import hashlib
from PIL import Image
import base64

# --- Fonctions de Hachage ---

def hash_string(data, algo='sha256'):
    """
    Hache une chaîne de caractères avec l'algorithme spécifié.
    """
    hasher = hashlib.new(algo)
    hasher.update(data.encode('utf-8'))
    return hasher.hexdigest()

# --- Fonctions de Stéganographie LSB (Optimisées) ---

def _data_to_binary(data):
    """Convertit des données (bytes) en une chaîne binaire."""
    return ''.join(format(byte, '08b') for byte in data)

def _hide_data_in_image(image, secret_data):
    """
    Cache les données binaires dans les pixels de l'image.
    Le format est : [longueur_données_en_binaire:32 bits][données_en_binaire]
    Retourne un nouvel objet Image avec les données cachées.
    """
    # Le préfixe contient la longueur des données secrètes, encodée sur 32 bits.
    # Cela nous permettra de savoir exactement combien de bits lire lors du décodage.
    data_length_prefix = format(len(secret_data), '032b')
    binary_secret_data = data_length_prefix + _data_to_binary(secret_data)
    
    data_len_total = len(binary_secret_data)
    
    image_capacity = image.width * image.height * 3
    if data_len_total > image_capacity:
        raise ValueError("Erreur : L'image est trop petite pour contenir le fichier secret.")

    new_image = image.copy()
    pixels = new_image.load()
    
    data_index = 0
    for y in range(image.height):
        for x in range(image.width):
            r, g, b = pixels[x, y]
            
            if data_index < data_len_total:
                r = (r & 0xFE) | int(binary_secret_data[data_index])
                data_index += 1
            if data_index < data_len_total:
                g = (g & 0xFE) | int(binary_secret_data[data_index])
                data_index += 1
            if data_index < data_len_total:
                b = (b & 0xFE) | int(binary_secret_data[data_index])
                data_index += 1
            
            pixels[x, y] = (r, g, b)
            
            if data_index >= data_len_total:
                return new_image
    return new_image

def _reveal_data_from_image(image):
    """
    Extrait les données binaires cachées en lisant d'abord la longueur.
    Version simplifiée et plus robuste.
    """
    pixels = image.load()
    binary_data_str = ""
    
    # 1. Extraire tous les bits LSB de l'image
    for y in range(image.height):
        for x in range(image.width):
            r, g, b = pixels[x, y]
            binary_data_str += str(r & 1)
            binary_data_str += str(g & 1)
            binary_data_str += str(b & 1)

    # 2. Lire les 32 premiers bits pour la longueur
    if len(binary_data_str) < 32:
        return b'' # Pas assez de données pour même contenir la longueur
    
    data_len_in_bytes = int(binary_data_str[:32], 2)
    total_bits_to_read = 32 + (data_len_in_bytes * 8)

    if len(binary_data_str) < total_bits_to_read:
        return b'' # L'image ne contient pas toutes les données annoncées

    # 3. Extraire les données secrètes
    secret_binary_data = binary_data_str[32:total_bits_to_read]
    
    all_bytes = [secret_binary_data[i:i+8] for i in range(0, len(secret_binary_data), 8)]
    
    revealed_data = bytearray()
    for byte_str in all_bytes:
        if len(byte_str) == 8:
            revealed_data.append(int(byte_str, 2))
            
    return bytes(revealed_data)

def stegano_hide_file(image_path, file_to_hide_path, output_image_path):
    """
    Fonction principale pour cacher un fichier dans une image.
    """
    try:
        with Image.open(image_path, 'r') as image:
            image = image.convert("RGB")
            with open(file_to_hide_path, 'rb') as f:
                secret_data = f.read()
            
            new_image = _hide_data_in_image(image, secret_data)
            new_image.save(output_image_path, 'PNG')
            return f"Succès : Fichier '{file_to_hide_path}' caché dans '{output_image_path}'."
    except FileNotFoundError as e:
        return f"Erreur : Fichier non trouvé - {e.filename}"
    except ValueError as e:
        return f"Erreur : {e}"
    except Exception as e:
        return f"Une erreur inattendue est survenue : {e}"

def stegano_reveal_file(image_path, output_file_path):
    """
    Fonction principale pour révéler un fichier caché dans une image.
    """
    try:
        with Image.open(image_path, 'r') as image:
            image = image.convert("RGB")
            revealed_data = _reveal_data_from_image(image)
            
            if not revealed_data:
                return "Aucune donnée cachée trouvée."

            with open(output_file_path, 'wb') as f:
                f.write(revealed_data)
            return f"Succès : Données extraites et sauvegardées dans '{output_file_path}'."
    except FileNotFoundError:
        return f"Erreur : L'image '{image_path}' n'a pas été trouvée."
    except Exception as e:
        return f"Une erreur inattendue est survenue : {e}"

# --- Fonctions d'Encodage ---

def encode_base64(data):
    """Encode des données en Base64."""
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def decode_base64(encoded_data):
    """Décode des données depuis Base64."""
    return base64.b64decode(encoded_data.encode('utf-8')).decode('utf-8')
