import hashlib
from hashlib import sha256

# Definisco alcune costanti
NUM_BYTES_32 = 32


def bytes_from_int_reversed(x: int, num_byte: int) -> bytes:
    """Transform an int input into its (num_byte)-byte representation and then reverse byte order"""
    return reverse_byte_order(x.to_bytes(num_byte, byteorder="big"))


def int_from_bytes(b: bytes) -> int:
    """Transform a byte input into its int representation"""
    return int.from_bytes(b, byteorder="big")


def bytes_from_int(x: int, num_byte: int) -> bytes:
    """Transform an int input into its byte representation"""
    return x.to_bytes(num_byte, byteorder="big")


def reverse_byte_order(b: bytes) -> bytes:
    """Reverse byte order"""
    return b[::-1]


def compact_size(data: bytes) -> bytes:
    """Return the compact size of the data, that is a byte representing an integer"""
    len_data = len(data)
    len_data_bytes = bytes_from_int(len_data, NUM_BYTES_32)
    if len_data < 252:
        return len_data_bytes[-1:]
    elif len_data < 65535:
        return b'\xfd' + len_data_bytes[-2:]
    elif len_data < 4294967295:
        return b'\xfe' + len_data_bytes[-4:]
    elif len_data < 18446744073709551615:
        return b'\xff' + len_data_bytes[-8:]


def sha256_2(data: bytes) -> bytes:
    """sha256^2(data)"""
    return sha256(sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """ripemd160(sha256(data))"""
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256(data).digest())
    return ripemd160.digest()


def DER_encoding(signature: (bytes, bytes)) -> bytes:
    """Return the DER-encode of the signature"""
    r, s = signature
    compound_object = b'\x30'
    int_type = b'\x02'
    # Delete all leading zeros from r and s
    r = r.lstrip(b'\x00')
    s = s.lstrip(b'\x00')
    # If r_bytes and s_bytes starts with a 1, add a b'\x00'
    if r[0] & 0x80:
        r = b'\x00' + r
    if s[0] & 0x80:
        s = b'\x00' + s
    result = int_type + compact_size(r) + r + int_type + compact_size(s) + s
    total_lenght = compact_size(result)
    return compound_object + total_lenght + result


if __name__ == '__main__':
    print("ciao")