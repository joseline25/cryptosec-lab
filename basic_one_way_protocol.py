import hashlib
import random

from math import gcd
# fonctions de hachage

def H1(value: str) -> int:
    # Hash -> int mod p
    return int(hashlib.sha256(value.encode()).hexdigest(), 16)

def H2(value: int) -> str:
    # Second hash, output string
    return hashlib.sha256(str(value).encode()).hexdigest()

# paramètres 
p = 2**256 - 189  # un grand nombre premier fictif
q = p - 1         # ordre du groupe

assert p % 4 == 3, "p doit être congru à 3 modulo 4"

# phase serveur
def server_preprocess(X, alpha):
    t_x_list = []
    for x in X:
        hx = H1(x) % q
        hx_alpha = pow(hx, alpha, p)
        t_x = H2(hx_alpha)
        t_x_list.append(t_x)
    return t_x_list

# phase client
def client_prepare(Y):
    beta_list = []
    a_list = []
    for y in Y:
        #beta = random.randint(2, q - 1)
        # Choisir un beta tel que gcd(beta, q) == 1
        while True:
            beta = random.randint(2, q - 1)
            if gcd(beta, q) == 1:
                break
        beta_list.append(beta)
        hy = H1(y) % q
        a = pow(hy, beta, p)
        a_list.append((a, beta))
    return a_list

# envoit au serveur
def server_apply_alpha(a_list, alpha):
    return [pow(a, alpha, p) for (a, _) in a_list]


# Retour client + déblinding

def client_finalize(received, beta_list, Y):
    ty_list = []
    for i in range(len(received)):
        a_alpha = received[i]
        beta_inv = pow(beta_list[i], -1, q)  # beta^{-1} mod q
        final = pow(a_alpha, beta_inv, p)
        ty = H2(final)
        ty_list.append((Y[i], ty))
    return ty_list

# Comparaison avec serveur
def compute_intersection(ty_list, t_x_list):
    return [y for (y, ty) in ty_list if ty in t_x_list]

server_set = ['alice@example.com', 'bob@example.com', 'charlie@example.com']
client_set = ['dave@example.com', 'bob@example.com', 'zoe@example.com']

alpha = random.randint(2, q - 1)
t_x = server_preprocess(server_set, alpha)

a_list = client_prepare(client_set)
a_values_only = [a for (a, _) in a_list]
received = server_apply_alpha(a_list, alpha)

beta_list = [b for (_, b) in a_list]
ty_list = client_finalize(received, beta_list, client_set)

intersection = compute_intersection(ty_list, t_x)
print("Intersection:", intersection)
