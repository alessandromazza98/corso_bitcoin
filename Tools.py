# --------
# Transform a byte input into its int representation
# --------
def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


# --------
# Transform an int input into its byte representation
# --------
def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")


# --------
# Reverse byte order
# --------
def reverse_byte_order(b: bytes) -> bytes:
    return b[::-1]


def len_encoding(data: bytes) -> bytes:
    len_bytes = bytes_from_int(len(data))
    if len_bytes < b'\xfc':
        return len_bytes[-1:]
    elif len_bytes < b'\xff\xff':
        return b'\xfd' + len_bytes[-2:]
    elif len_bytes < b'\xff\xff\xff\xff':

