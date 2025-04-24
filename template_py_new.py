import os
from typing import Callable, List, Dict
from Crypto.Hash import SHA256

# les utilitaires (ameliorer close_words car les closes words ne sont pas seulement ceux sans le premier ou dernier caractere)

def normalize(word: str) -> str:
    return word.lower()

def close_words(word: str) -> List[str]:
    return [word, word[:-1], word[1:]]

# la fonction chiffrement

def encrypt_data(data: bytes, encrypt_function: Callable[[bytes], bytes]) -> bytes:
    return encrypt_function(data)

def hash_data(data: bytes) -> bytes:
    h = SHA256.new()
    h.update(data)
    return h.digest()

# génération de clefs (pour l'instant, on ne fait que renvoyer des clefs nulles)

def generate_key(length: int) -> bytes:
    return os.urandom(length)

#  Phase II: Database Preparation (Bob's side) 

def prepare_database(fields: List[str], encrypt_function: Callable[[bytes], bytes]) -> Dict[str, List[bytes]]:
    """
    Bob hashes, encrypts and re-hashes fields to prepare the database.
    """
    database = {}
    for field in fields:
        norm_field = normalize(field)
        variants = close_words(norm_field)
        encrypted_variants = []
        for variant in variants:
            hashed = hash_data(variant.encode())
            encrypted = encrypt_data(hashed, encrypt_function)
            encrypted_variants.append(encrypted)
        database[norm_field] = encrypted_variants
    return database

# === Phase III: Request Preparation (Alice's side) ===

def prepare_request(fields: List[str], encrypt_function: Callable[[bytes], bytes]) -> List[bytes]:
    """
    Alice formats, hashes, encrypts fields to create a query.
    """
    encrypted_requests = []
    for field in fields:
        norm_field = normalize(field)
        hashed = hash_data(norm_field.encode())
        encrypted = encrypt_data(hashed, encrypt_function)
        encrypted_requests.append(encrypted)
    return encrypted_requests



def main():
    #  des clés de chiffrement sur 32 bits 
    key_KB = generate_key(32)
    key_KAB = generate_key(32)
    key_KR = generate_key(32)

    # Mock encrypt function (to be replaced with real AES-CTR, ElGamal, etc.)
    def mock_encrypt(data: bytes) -> bytes:
        # Just return the same data for placeholder
        return data

    # Bob prepares his database
    bob_fields = ["Abc", "dEF", "GHi"]
    database = prepare_database(bob_fields, encrypt_function=mock_encrypt)
    print("Database:", database)

    # Alice prepares a query
    alice_fields = ["Abc", "GHi"]
    request = prepare_request(alice_fields, encrypt_function=mock_encrypt)
    print("Request:", request)

if __name__ == "__main__":
    main()
