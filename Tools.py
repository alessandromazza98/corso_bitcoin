from hashlib import sha256


def int_from_bytes(b: bytes) -> int:
    """Transform a byte input into its int representation"""
    return int.from_bytes(b, byteorder="big")


def bytes_from_int(x: int) -> bytes:
    """Transform an int input into its byte representation"""
    return x.to_bytes(32, byteorder="big")


def reverse_byte_order(b: bytes) -> bytes:
    """Reverse byte order"""
    return b[::-1]


def compact_size(data: bytes) -> bytes:
    """Return the compact size of the data, that is a byte representing an integer"""
    len_data = len(data)
    len_data_bytes = bytes_from_int(len_data)
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


if __name__ == '__main__':
    print("hello")
    