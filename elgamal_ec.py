import secrets
from hashlib import sha256
from ecdsa import SECP256k1, ellipticcurve, numbertheory

# Setup
curve = SECP256k1
G = curve.generator
order = G.order()

def hash_to_point(m: str):
    h = sha256(m.encode()).digest()
    e = int.from_bytes(h, 'big') % order
    return e * G  # H(m).P

# Alice's side
m = "secret_message"
H_m_P = hash_to_point(m)

r = secrets.randbelow(order - 1) + 1  # r ∈ [1, order-1]
C1 = r * G
C2 = r * H_m_P  # msg_A

# Bob's key
b = secrets.randbelow(order - 1) + 1
msg_B = b * C2

# Alice retrieves final result
r_inv = numbertheory.inverse_mod(r, order)
final = r_inv * msg_B  # Should be b * H(m) * P

# Output
print("C1 =", C1)
print("C2 (msg_A) =", C2)
print("msg_B =", msg_B)
print("Final =", final)
