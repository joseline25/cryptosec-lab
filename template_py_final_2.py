# Athenaa Protocol - Version avec support de multiples schémas de chiffrement (clé ou clé+nonce)

import os
from typing import List, Dict, Callable, Any
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# === Utilitaires ===

def normalize(word):
    return word.lower()

def close_words(word, max_distance=2):
    return [word, word[:-1], word[1:]]

def hash_data(data):
    h = SHA256.new()
    h.update(data)
    return h.digest()

# === Génération de clés ===

def keygen(length):
    return os.urandom(length)

# === Chiffrements ===

def encrypt_aes_ctr(key, nonce):
    def encrypt(data):
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(data)
    return encrypt

# Simulacre d'ElGamal : prend uniquement une clé (pas de nonce)
# (Dans une vraie implémentation, ceci ferait appel à une lib ECC comme Petlib ou Tinyec)
def encrypt_elgamal_ec(key):
    def encrypt(data):
        # Ce n'est pas un vrai ElGamal, juste pour la structure
        return b"elgamal(" + key + b")" + data  # à remplacer par vrai chiffrement
    return encrypt

# === Dictionnaire des schémas de chiffrement ===
# Chaque entrée contient : (fonction constructeur, prend_nonce)
encryption_schemes = {
    0: (encrypt_aes_ctr, True),       # AES + CTR avec nonce
    1: (encrypt_elgamal_ec, False),  # ElGamal ECC sans nonce
}

# === Application d'un schéma de chiffrement ===

def get_encrypt_fn(scheme_id, key, nonce=None):
    encryptor_fn, needs_nonce = encryption_schemes[scheme_id]
    if needs_nonce:
        if nonce is None:
            raise ValueError("Ce chiffrement requiert un nonce.")
        return encryptor_fn(key, nonce)
    else:
        return encryptor_fn(key)

# === Phases du protocole ===

def encrypt_sender(Lfields, KR, nonce_KR, scheme_id):
    res = {}
    to_send = []
    encrypt_fn = get_encrypt_fn(scheme_id, KR, nonce_KR)
    for word in Lfields:
        normed = normalize(word)
        L = []
        for variant in close_words(normed):
            hashed = hash_data(variant.encode())
            encrypted = encrypt_fn(hashed)
            L.append(encrypted)
            to_send.append(encrypted)
        res[normed] = L
    return res, to_send

def encrypt_receiver(L, KB, nonce_KB, scheme_id):
    res = []
    encrypt_fn = get_encrypt_fn(scheme_id, KB, nonce_KB)
    for it in L:
        enc = encrypt_fn(it)
        res.append(enc)
    return res

def encrypt_final(L, KAB, nonce_KAB, scheme_id):
    res = []
    encrypt_fn = get_encrypt_fn(scheme_id, KAB, nonce_KAB)
    for it in L:
        enc = encrypt_fn(it)
        h = hash_data(enc)
        res.append(h)
    return res

# === Démo ===

def main():
    scheme_id = 0 # 0 pour AES-CTR, 1 pour ElGamal simulé

    KR = keygen(32)
    nonce_KR = os.urandom(8) if encryption_schemes[scheme_id][1] else None

    KB = keygen(32)
    nonce_KB = os.urandom(8) if encryption_schemes[scheme_id][1] else None

    KAB = keygen(32)
    nonce_KAB = os.urandom(8) if encryption_schemes[scheme_id][1] else None

    Lfields = ["Abc", "dEF", "GHi"]

    res, to_send = encrypt_sender(Lfields, KR, nonce_KR, scheme_id)
    print("encrypt sender:", res)

    to_finalize = encrypt_receiver(to_send, KB, nonce_KB, scheme_id)
    print("encrypt receiver:", to_finalize)

    result = encrypt_final(to_finalize, KAB, nonce_KAB, scheme_id)
    print("Final hash/encrypted to S1:", result)

if __name__ == "__main__":
    main()
