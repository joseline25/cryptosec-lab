

import os
from typing import List, Dict, Callable
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# utilities

def normalize(word):
    return word.lower()

def close_words(word, max_distance=2):
	return [word, word[:-1], word[1:]]


def hash_data(data):
    h = SHA256.new()
    h.update(data)
    return h.digest()

# Phase I: Generation of Cryptographic Keys

def keygen(length):
    return os.urandom(length) 

#Aes +CTR 

def encrypt_aes_ctr(key, nonce):
    def encrypt(data):
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(data)
    return encrypt


# algos de chiffrement indexés
encryption_schemes = {       
    0: encrypt_aes_ctr       # AES + CTR
    # 1: encrypt_elgamal_ec  
}

# Phase II: Database Preparation 

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

# Phase III 

def encrypt_receiver(L, KB, nonce_KB, scheme_id):
    res = []
    encrypt_fn = encryption_schemes[scheme_id](KB, nonce_KB)
    for it in L:
        enc = encrypt_fn(it)
        res.append(enc)
    return res

# Phase III A to S1

def encrypt_final(L, KAB, nonce_KAB, scheme_id):
    res = []
    encrypt_fn = encryption_schemes[scheme_id](KAB, nonce_KAB)
    for it in L:
        enc = encrypt_fn(it)
        h = hash_data(enc)
        res.append(h)
    return res

# === Main simulation ===

def main():
    scheme_id = 0  

    # key generation 
    key_KR = keygen(32)
    nonce_KR = os.urandom(8)
    print("Key K_R:", key_KR)
    print("Nonce K_R:", nonce_KR)
    key_KB = keygen(32)
    nonce_KB = os.urandom(8)

    key_KAB = keygen(32)
    nonce_KAB = os.urandom(8)

    # Alice to Bob/S2
    Lfields = ["Abc", "dEF", "GHi"]
    res, to_send = encrypt_sender(Lfields, key_KR, nonce_KR, scheme_id)
    print("encrypt sender:", res)

    # Bob/S2 to Alice
    to_finalize = encrypt_receiver(to_send, key_KB, nonce_KB, scheme_id)
    print(" encrypt receiver:", to_finalize)

    # Alice to S1
    result = encrypt_final(to_finalize, key_KAB, nonce_KAB, scheme_id)
    print("Final hash/encrypted to S1:", result)

if __name__ == "__main__":
    main()
