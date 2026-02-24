"""
encryption.py

Laboratorio de Cifrado y Manejo de Credenciales

En este módulo deberás implementar:

- Descifrado AES (MODE_EAX)
- Hash de contraseña con salt usando PBKDF2-HMAC-SHA256
- Verificación de contraseña usando el mismo salt

NO modificar la función encrypt_aes().
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import hmac

# ==========================================================
# AES-GCM (requiere pip install pycryptodome)
# ==========================================================

def encrypt_aes(texto, clave):
    """
    Cifra un texto usando AES en modo EAX.

    Retorna:
        texto_cifrado_hex
        nonce_hex
        tag_hex
    """

    texto_bytes = texto.encode()

    cipher = AES.new(clave, AES.MODE_EAX)

    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)

    return (
        texto_cifrado.hex(),
        nonce.hex(),
        tag.hex()
    )




def decrypt_aes(texto_cifrado_hex, nonce_hex, tag_hex, clave):
    """
    Descifra texto cifrado con AES-EAX.

    Debes:

    1. Convertir texto_cifrado_hex, nonce_hex y tag_hex a bytes.
    2. Crear el objeto AES usando:
           AES.new(clave, AES.MODE_EAX, nonce=nonce)
    3. Usar decrypt_and_verify() para validar integridad.
    4. Retornar el texto descifrado como string.
    """

    
    # TODO: Implementar conversión de hex a bytes
    texto_cifrado_hex = bytes.fromhex(texto_cifrado_hex)
    nonce_hex = bytes.fromhex(nonce_hex)
    tag_hex = bytes.fromhex(tag_hex)

    # TODO: Crear objeto AES con nonce
    cipher = AES.new(clave, AES.MODE_EAX, nonce = nonce_hex)


    texto_descifrado = cipher.decrypt_and_verify(texto_cifrado_hex, tag_hex)
    
    return texto_descifrado.decode()

    pass

# ==========================================================
# PASSWORD HASHING (PBKDF2 - SHA256)
# ==========================================================


def hash_password(password):
    """
    Genera un hash seguro usando:

        PBKDF2-HMAC-SHA256

    Requisitos:

    - Generar salt aleatoria de 16 bytes.
    - Usar al menos 200000 iteraciones.
    - Derivar clave de 32 bytes.
    - Retornar un diccionario con:

        {
            "algorithm": "pbkdf2_sha256",
            "iterations": ...,
            "salt": salt_en_hex,
            "hash": hash_en_hex
        }

    Pista:
        hashlib.pbkdf2_hmac(...)
    """

    def generate_hmac_sha256(key, message):
        hmac_object = hmac.new(key, message, hashlib.sha256)
        hash_hex = hmac_object.hexdigest()
        return hash_hex

    salt = os.urandom(16)


    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000, 32)
    return {
            "algorithm": "pbkdf2_sha256",
            "iterations": 200000,
            "salt": salt.hex(),
            "hash": key.hex()
        }


def verify_password(password, stored_data):
    """
    Verifica una contraseña contra el hash almacenado.

    Debes:

    1. Extraer salt y iterations del diccionario.
    2. Convertir salt de hex a bytes.
    3. Recalcular el hash con la contraseña ingresada.
    4. Comparar usando hmac.compare_digest().
    5. Retornar True o False.

    stored_data tiene esta estructura:

        {
            "algorithm": "...",
            "iterations": ...,
            "salt": "...",
            "hash": "..."
        }
    """

    # Extraer salt e iterations
    salt = bytes.fromhex(stored_data['salt'])
    iteraciones = stored_data['iterations']
    # Recalcular hash
    recalculated_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iteraciones, 32).hex()
    # Comparar con compare_digest
    return hmac.compare_digest(recalculated_hash, stored_data["hash"])

    pass



if __name__ == "__main__":

    print("=== PRUEBA AES ===")

    texto = "Hola Mundo"
    clave = get_random_bytes(16)

    texto_cifrado, nonce, tag = encrypt_aes(texto, clave)

    print("Texto cifrado:", texto_cifrado)
    print("Nonce:", nonce)
    print("Tag:", tag)

    # Cuando implementen decrypt_aes, esto debe funcionar
    texto_descifrado = decrypt_aes(texto_cifrado, nonce, tag, clave)
    print("Texto descifrado:", texto_descifrado)


    print("\n=== PRUEBA HASH ===")

    password = "Password123!"

    # Cuando implementen hash_password:
    pwd_data = hash_password(password)
    print("Hash generado:", pwd_data)

    # Cuando implementen verify_password:
    print("Verificación correcta:",
           verify_password("Password123!", pwd_data))