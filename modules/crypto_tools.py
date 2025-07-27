import base64
from cryptography.fernet import Fernet
from PIL import Image
import os

# --- CHIFFREMENT DE BASE ---

def encode_base64(data: bytes) -> bytes:
    return base64.b64encode(data)

def decode_base64(data: bytes) -> bytes:
    return base64.b64decode(data)

def rot13(text: str) -> str:
    return text.encode('rot13')

def xor_cipher(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

# --- CHIFFREMENT FERNET (SYMETRIQUE) ---

def generate_fernet_key() -> bytes:
    """Génère une nouvelle clé Fernet."""
    return Fernet.generate_key()

def encrypt_fernet(data: bytes, key: bytes) -> bytes:
    """Chiffre des données avec une clé Fernet."""
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_fernet(token: bytes, key: bytes) -> bytes:
    """Déchiffre des données avec une clé Fernet."""
    f = Fernet(key)
    return f.decrypt(token)

# --- STÉGANOGRAPHIE (LSB) ---

def _str_to_binary(data):
    """Convertit une chaîne de caractères en sa représentation binaire."""
    return ''.join(format(ord(i), '08b') for i in data)

def _binary_to_str(binary_data):
    """Convertit une chaîne binaire en caractères."""
    return "".join(chr(int(binary_data[i:i+8], 2)) for i in range(0, len(binary_data), 8))

def hide_message_in_image(image_path: str, secret_message: str, output_path: str):
    """Cache un message dans une image en utilisant la méthode LSB."""
    try:
        img = Image.open(image_path, 'r')
        width, height = img.size
        img_data = list(img.getdata())

        binary_secret = _str_to_binary(secret_message + "####") # Ajout d'un délimiteur
        if len(binary_secret) > len(img_data) * 3:
            raise ValueError("Message trop long pour l'image.")

        data_index = 0
        new_img_data = []
        for pixel in img_data:
            if data_index < len(binary_secret):
                new_pixel = list(pixel)
                # Modifier le bit de poids faible (LSB) de chaque canal de couleur
                for i in range(3): # R, G, B
                    if data_index < len(binary_secret):
                        new_pixel[i] = int(bin(pixel[i])[2:-1] + binary_secret[data_index], 2)
                        data_index += 1
                new_img_data.append(tuple(new_pixel))
            else:
                new_img_data.append(pixel)
        
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_img_data)
        new_img.save(output_path)
        print(f"[+] Message caché dans {output_path}")
        return True
    except Exception as e:
        print(f"[-] Erreur lors de la dissimulation du message : {e}")
        return False

def extract_message_from_image(image_path: str) -> str:
    """Extrait un message caché d'une image."""
    try:
        img = Image.open(image_path, 'r')
        img_data = img.getdata()
        binary_data = ""
        for pixel in img_data:
            for i in range(3): # R, G, B
                binary_data += bin(pixel[i])[-1]
        
        message = _binary_to_str(binary_data)
        delimiter_pos = message.find("####")
        if delimiter_pos != -1:
            return message[:delimiter_pos]
        return "Aucun message trouvé ou délimiteur manquant."
    except Exception as e:
        return f"Erreur lors de l'extraction du message : {e}"

# --- EXEMPLE D'UTILISATION ---
def run():
    print("--- Démonstration des outils de cryptographie ---")
    
    # Base64
    b64_encoded = encode_base64(b"test_base64")
    print(f"Base64 Encoded: {b64_encoded}")
    print(f"Base64 Decoded: {decode_base64(b64_encoded)}")

    # ROT13
    print(f"ROT13: {rot13('hello world')}")

    # XOR
    xor_encrypted = xor_cipher(b"secret data", "mykey")
    print(f"XOR Encrypted: {xor_encrypted}")
    print(f"XOR Decrypted: {xor_cipher(xor_encrypted, 'mykey')}")

    # Fernet
    fernet_key = generate_fernet_key()
    fernet_encrypted = encrypt_fernet(b"donnees tres secretes", fernet_key)
    print(f"Fernet Encrypted: {fernet_encrypted}")
    print(f"Fernet Decrypted: {decrypt_fernet(fernet_encrypted, fernet_key)}")

    # Stéganographie
    # Créer une image de test si elle n'existe pas
    test_image_path = os.path.join(os.path.dirname(__file__), 'test_image.png')
    if not os.path.exists(test_image_path):
        Image.new('RGB', (100, 100), color = 'red').save(test_image_path)
    
    stego_image_path = os.path.join(os.path.dirname(__file__), 'stego_image.png')
    hide_message_in_image(test_image_path, "Ceci est un message caché !", stego_image_path)
    extracted = extract_message_from_image(stego_image_path)
    print(f"Message extrait de l'image : {extracted}")

if __name__ == '__main__':
    run()
