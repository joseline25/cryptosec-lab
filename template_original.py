#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def normalize(word):
	return word.lower()

def close_words(word, max_distance=2):
	return [word, word[:-1], word[1:]]

def encrypt_sender(Lfields, key, nonce, max_distance):
	"""
	Alice -> Bob / S2: enc(H(w)) for each close word for each field
	"""
	res = {}
	to_send = []
	for word in Lfields:
		normed = normalize(word)
		L = []
		for it in close_words(normed, max_distance):
			h = SHA256.new(it)
			cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
			enc = cipher.encrypt(h.digest())
			L.append(enc)
			to_send.append(enc)
		res[normed] = L
	return res, to_send

def encrypt_receiver(L, key, nonce):
	"""
	Bob/S2 -> Alice: enc(it) for each encrypted element it
	"""
	res = []
	for it in L:
		cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
		enc = cipher.encrypt(it)
		res.append(enc)
	return res

def encrypt_final(L, key, nonce):
	"""
	Alice -> S1: H(enc(it)) for each it received from Bob/S2
	"""
	res = []
	for it in L:
		cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
		enc = cipher.encrypt(it)
		h = SHA256.new(enc)
		res.append(h.digest())
	return res

def main():
	key = b'\x00'*32
	nonce = b'\x00'*8
	Lfields = [b'Abc', b'dEF', b'GHi']

	res, to_send = encrypt_sender(Lfields, key, nonce, 0)
	print(res)
	print(to_send)

	key2 = b'\x01'*32
	nonce2 = b'\x01'*8
	to_finalize = encrypt_receiver(to_send, key2, nonce2)
	print(to_finalize)

	key3 = b'\x02'*32
	nonce3 = b'\x02'*8
	result = encrypt_final(to_finalize, key3, nonce3)
	print(result)

if __name__ == '__main__':
	main()