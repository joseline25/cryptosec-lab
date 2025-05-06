import secrets
from Crypto.Hash import SHA256
from ecpy.curves import Curve, Point
from cuckoofilter import CuckooFilter

# Setup EC
curve = Curve.get_curve('Ed25519')
G = curve.generator
order = curve.order

# Hash to scalar / point
def hash_to_scalar(data: str) -> int:
    h = SHA256.new()
    h.update(data.encode())
    return int.from_bytes(h.digest(), 'big') % order

def hash_to_point(data: str) -> Point:
    return hash_to_scalar(data) * G

def point_to_bytes(P: Point) -> bytes:
    x_bytes = P.x.to_bytes(32, 'big')
    y_bytes = P.y.to_bytes(32, 'big')
    return x_bytes + y_bytes

def point_to_digest(P: Point) -> bytes:
    return SHA256.new(point_to_bytes(P)).digest()

def generate_scalar() -> int:
    return secrets.randbelow(order - 1) + 1

#  Serveur : encode et insère dans Cuckoo Filter, cette opération peut être faite une seule fois
def server_prepare_cf(X, alpha, capacity=1000):
    #cf = CuckooFilter(capacity=capacity, bucket_size=4, fingerprint_size=16)
    cf = CuckooFilter(capacity=capacity)
    for x in X:
        P = hash_to_point(x)
        Px = alpha * P
        digest = point_to_digest(Px)
        cf.insert(digest)
    return cf

#  Client : préparation de sa requête
def client_prepare(Y):
    beta_list = []
    blinded = []
    for y in Y:
        beta = generate_scalar()
        P = hash_to_point(y)
        a = beta * P
        beta_list.append(beta)
        blinded.append((a, beta))
    return blinded

#  Serveur applique alpha
def server_apply_alpha(blinded, alpha):
    return [alpha * a for (a, _) in blinded]

# Client : retire beta et teste dans CF
def client_check_cf(received, beta_list, Y, cf):
    intersection = []
    for i in range(len(received)):
        beta_inv = pow(beta_list[i], -1, order)
        final_point = beta_inv * received[i]
        digest = point_to_digest(final_point)
        if digest in cf:
            intersection.append(Y[i])
    return intersection

#  Mise à jour dynamique du CF
def update_cf(cf, z_set, alpha, mode="insert", threshold=0.95):
    updated_elements = []
    for z in z_set:
        P = hash_to_point(z)
        P_enc = alpha * P
        digest = point_to_digest(P_enc)
        updated_elements.append(digest)

    if mode == "insert":
        if cf.load() > threshold:
            print("⚠️ CF trop plein. Rebuild...")
            new_cf = CuckooFilter(capacity=cf.size * 2)
            for d in list(cf):  # réinsérer anciens éléments
                new_cf.insert(d)
            for d in updated_elements:
                new_cf.insert(d)
            return new_cf
        else:
            for d in updated_elements:
                cf.insert(d)
            return cf

    elif mode == "delete":
        for d in updated_elements:
            cf.delete(d)
        return cf

    else:
        raise ValueError("Mode must be 'insert' or 'delete'")


#  Test
if __name__ == "__main__":
    server_set = ['alice@example.com', 'bob@example.com', 'charlie@example.com']
    client_set = ['dave@example.com', 'bob@example.com', 'zoe@example.com']

    alpha = generate_scalar()
    cf = server_prepare_cf(server_set, alpha, capacity=100)

    blinded = client_prepare(client_set)
    beta_list = [b for (_, b) in blinded]
    received = server_apply_alpha(blinded, alpha)

    intersection = client_check_cf(received, beta_list, client_set, cf)
    print("Intersection:", intersection)
    # Mise à jour dynamique
    to_insert = ['newuser@example.com']
    to_delete = ['charlie@example.com']

    cf = update_cf(cf, to_insert, alpha, mode="insert")
    cf = update_cf(cf, to_delete, alpha, mode="delete")

