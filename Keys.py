from Tools import bytes_from_int

def ser_public_key(public_key: (int, int), compressed=True) -> bytes:
    """Serialize the public key from its coordinates"""
    px, py = public_key
    if compressed:
        if py % 2 == 0:
            return b'\x02' + bytes_from_int(px)
        else:
            return b'\x03' + bytes_from_int(px)
    else:
        return b'\x04' + bytes_from_int(px) + bytes_from_int(py)


def ser_public_key_compressed(public_key: (int, int)) -> bytes:
    """Serialize the public key in compressed form from its coordinates"""
    return ser_public_key(public_key, True)


def ser_public_key_uncompressed(public_key: (int, int)) -> bytes:
    """Serialize the public key in uncompressed form from its coordinates"""
    return ser_public_key(public_key, False)

