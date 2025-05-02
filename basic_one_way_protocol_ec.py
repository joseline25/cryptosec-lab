import secrets
from Crypto.Hash import SHA256
from ecpy.curves import Curve, Point

# Initialisation courbe elliptique
curve = Curve.get_curve('Ed25519')
G = curve.generator
order = curve.order

# Fonctions de hachage vers scalaire ou point EC
def hash_to_scalar(data: str) -> int:
    h = SHA256.new()
    h.update(data.encode())
    return int.from_bytes(h.digest(), 'big') % order

def hash_to_point(data: str) -> Point:
    scalar = hash_to_scalar(data)
    return scalar * G

# Sérialisation + H2
def point_to_hash(P: Point) -> str:
    x_bytes = P.x.to_bytes(32, 'big')
    y_bytes = P.y.to_bytes(32, 'big')
    data = x_bytes + y_bytes
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()

# Générateur de scalaires aléatoires
def generate_scalar() -> int:
    return secrets.randbelow(order - 1) + 1

# Phase serveur (offline)
def ec_server_preprocess(X, alpha):
    return [point_to_hash(alpha * hash_to_point(x)) for x in X]

# Phase client (préparation)
def ec_client_prepare(Y):
    beta_list = []
    a_points = []
    for y in Y:
        beta = generate_scalar()
        P = hash_to_point(y)
        a = beta * P
        a_points.append((a, beta))
    return a_points

# Serveur applique α
def ec_server_apply_alpha(a_points, alpha):
    return [alpha * a for (a, _) in a_points]

# Client retire β, hash le point
def ec_client_finalize(received_points, beta_list, Y):
    results = []
    for i in range(len(received_points)):
        beta_inv = pow(beta_list[i], -1, order)
        final_point = beta_inv * received_points[i]
        results.append((Y[i], point_to_hash(final_point)))
    return results

# Comparaison
def ec_compute_intersection(ty_list, t_x_list):
    return [y for (y, ty) in ty_list if ty in t_x_list]

# Données de test
if __name__ == "__main__":
    server_set = ['alice@example.com', 'bob@example.com', 'charlie@example.com', 'dave@example.com']
    client_set = ['dave@example.com', 'bob@example.com', 'zoe@example.com']

    alpha = generate_scalar()
    t_x = ec_server_preprocess(server_set, alpha)

    a_points = ec_client_prepare(client_set)
    beta_list = [b for (_, b) in a_points]
    received = ec_server_apply_alpha(a_points, alpha)
    ty_list = ec_client_finalize(received, beta_list, client_set)

    intersection = ec_compute_intersection(ty_list, t_x)
    print("Intersection:", intersection)
