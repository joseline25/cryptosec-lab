
import os
import secrets
from typing import List, Dict
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from ecdsa import SECP256k1, numbertheory

# Utility functions
def normalize(word):
    return word.lower()

def close_words(word, max_distance=2):
    return [word, word[:-1], word[1:]]

def hash_data(data):
    h = SHA256.new()
    h.update(data)
    return h.digest()

def serialize_point(P):
    return P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')

# AES + CTR mode encryption
def encrypt_aes_ctr(key, nonce):
    def encrypt(data):
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(data)
    return encrypt

# ECC ElGamal encryption
curve = SECP256k1
G = curve.generator
order = G.order()

def hash_to_point(data: bytes):
    h = SHA256.new()
    h.update(data)
    e = int.from_bytes(h.digest(), 'big') % order
    return e * G

def encrypt_elgamal_ec(key: int, nonce: bytes):
    def encrypt(data: bytes):
        Hm = hash_to_point(data)
        r = secrets.randbelow(order - 1) + 1
        C1 = r * G
        C2 = r * Hm
        return (C1, C2)
    return encrypt

# Encryption schemes
encryption_schemes = {
    0: encrypt_aes_ctr,
    1: encrypt_elgamal_ec
}

# Phase II: Sender encryption
def encrypt_sender(Lfields, KR, nonce_KR, scheme_id):
    res = {}
    to_send = []
    encrypt_fn = encryption_schemes[scheme_id](KR, nonce_KR)
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

# Phase III: Receiver encryption
def encrypt_receiver(L, KB, nonce_KB, scheme_id):
    res = []
    encrypt_fn = encryption_schemes[scheme_id](KB, nonce_KB)
    for it in L:
        if isinstance(it, tuple):
            bytes_input = serialize_point(it[0]) + serialize_point(it[1])
        else:
            bytes_input = it
        enc = encrypt_fn(bytes_input)
        res.append(enc)
    return res

# Phase III A to S1: Final encryption
def encrypt_final(L, KAB, nonce_KAB, scheme_id):
    res = []
    encrypt_fn = encryption_schemes[scheme_id](KAB, nonce_KAB)
    for it in L:
        if isinstance(it, tuple):
            bytes_input = serialize_point(it[0]) + serialize_point(it[1])
        else:
            bytes_input = it
        enc = encrypt_fn(bytes_input)
        h = hash_data(enc if isinstance(enc, bytes) else str(enc).encode())
        res.append(h)
    return res

# Main simulation
def main():
    scheme_id = 1 # ECC ElGamal

    # Key generation
    key_KR = secrets.randbelow(order - 1) + 1
    nonce_KR = os.urandom(8)
    print("Key K_R:", key_KR)
    print("Nonce K_R:", nonce_KR)

    key_KB = secrets.randbelow(order - 1) + 1
    nonce_KB = os.urandom(8)

    key_KAB = secrets.randbelow(order - 1) + 1
    nonce_KAB = os.urandom(8)

    # Alice to Bob/S2
    Lfields = ["Abc", "dEF", "GHi"]
    res, to_send = encrypt_sender(Lfields, key_KR, nonce_KR, scheme_id)
    print("encrypt sender:", res)

    # Bob/S2 to Alice
    to_finalize = encrypt_receiver(to_send, key_KB, nonce_KB, scheme_id)
    print("encrypt receiver:", to_finalize)

    # Alice to S1
    result = encrypt_final(to_finalize, key_KAB, nonce_KAB, scheme_id)
    print("Final hash/encrypted to S1:", result)

if __name__ == "__main__":
    main()