# module for CSPRNG
import secrets
from Tools import int_from_bytes, bytes_from_int

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


def inverse(numero, primo=p):
    """Inverse operation in mod p"""
    return pow(numero, -1, primo)


def double(P):
    """Add a point P to itself"""
    px, py = P
    s = ((3 * px ** 2 + a) * inverse(2 * py)) % p
    px_double = (s ** 2 - 2 * px) % p
    py_double = (s * (px - px_double) - py) % p
    return px_double, py_double


def add(P1, P2):
    """Add two points together"""
    p1x, p1y = P1
    p2x, p2y = P2
    # If p1 == p2 -> double(p1)
    if p1x == p2x and p1y == p2y:
        return double((p1x, p1y))
    s = ((p1y - p2y) * inverse(p1x - p2x)) % p
    px_add = (s ** 2 - p1x - p2x) % p
    py_add = (s * (p1x - px_add) - p1y) % p
    return px_add, py_add


def multiply(k, point=G):
    """Use double and add operations to quickly multiply a point by an integer value"""
    # create a copy of initial point
    current = point
    # convert integer into binary representation
    binary_k = str(bin(k)[2:])  # [:2] to cut '0b' that python adds in the beginning
    # double & add algorithm for fast multiplication
    for i in range(1, len(binary_k)):  # start from binary_k[1] in order to avoid first element
        # 0 -> double
        current = double(current)
        # 1 -> & add
        if binary_k[i] == "1":
            current = add(current, point)
    return current


def sign(private_key: int, msg: bytes, k=None):
    """Sign a message with a priv key"""
    # generate k if not given
    if k is None:
        k = secrets.randbelow(n)
    # generate point R = kG
    Rx, Ry = multiply(k)
    # generate the signature (r,s)
    r = Rx % n  # r is the coordinate_x mod n
    s = (inverse(k, n) * (int_from_bytes(msg) + private_key * r)) % n
    # choose the "low-s" value of s
    if s > n // 2:
        s = n - s
    return bytes_from_int(r, NUM_BYTES_32), bytes_from_int(s, NUM_BYTES_32)


def verify(public_key: bytes, msg: bytes, sig: (bytes, bytes)) -> bool:
    """Verify a signature in relation of a message and a public key"""
    r, s = sig
    # generate the two parts of the final equation
    first_addend = multiply(inverse(int_from_bytes(s), n) * int_from_bytes(msg))
    second_addend = multiply(inverse(int_from_bytes(s), n) * int_from_bytes(r), int_from_bytes(public_key))
    # add the two points generated before in order to get R
    Rx, _ = add(first_addend, second_addend)
    return Rx == r
