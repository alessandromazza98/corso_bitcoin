import secrets
from hashlib import sha256
from ECDSA import multiply, add
from Keys import ser_public_key_schnorr
from Tools import bytes_from_int, int_from_bytes

# -------------------------
# Elliptic Curve Parameters
# -------------------------
# y² = x³ + ax + b

a = 0
b = 7

# prime field
p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1

# number of points on the curve we can hit ("order")
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# generator point (the starting point on the curve used for all calculations)
G = 55066263022277343669578718895168534326250603453777594175500187360389116729240,\
    32670510020758816978083085130507043184471273380659243275938904335757337482424

NUM_BYTES_32 = 32


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Tag Hash function performs sha256(sha256(tag) + sha256(tag) + input_data)"""
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + data).digest()


def lift_x(x: int):
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return x, y if y & 1 == 0 else p - y


def sign_schnorr(private_key: int, msg: bytes, k=None) -> bytes:
    """Sign a message with a priv key using Schnorr algorithm"""
    P = multiply(private_key)
    if not P[1] % 2 == 0:
        private_key = n - private_key
    if k is None:
        k = secrets.randbelow(n)
    R = multiply(k)
    if not R[1] % 2 == 0:
        k = n - k
    e = int_from_bytes(tagged_hash("BIP0340/challenge", ser_public_key_schnorr(R)\
                                   + ser_public_key_schnorr(P) + msg))
    sig = ser_public_key_schnorr(R) + bytes_from_int((k + e * private_key) % n, NUM_BYTES_32)
    return sig


def verify_schnorr(public_key: bytes, msg: bytes, sig: bytes):
    """Verify a signature in relation of a message and a public key using Schnorr algorithm"""
    R_ser256_bytes, s = sig
    P = lift_x(int_from_bytes(public_key))
    e = int_from_bytes(tagged_hash("BIP0340/challenge", R_ser256_bytes + public_key + msg)) % n
    s_int = int_from_bytes(s)
    R = add(multiply(s_int), multiply(n - e, P))
    if not R[1] % 2 == 0:
        return False
    r_int = int_from_bytes(R_ser256_bytes)
    if R[0] != r_int:
        return False
    return True
