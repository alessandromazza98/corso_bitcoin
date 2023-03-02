from Tools import bytes_from_int

# Definisco alcune costanti
NUM_BYTE_32 = 32

def ser_public_key_ECDSA(public_key: (int, int), compressed=True) -> bytes:
    """Serialize the public key from its coordinates"""
    px, py = public_key
    if compressed:
        if py % 2 == 0:
            return b'\x02' + bytes_from_int(px, NUM_BYTE_32)
        else:
            return b'\x03' + bytes_from_int(px, NUM_BYTE_32)
    else:
        return b'\x04' + bytes_from_int(px, NUM_BYTE_32) + bytes_from_int(py, NUM_BYTE_32)


def ser_public_key_compressed(public_key: (int, int)) -> bytes:
    """Serialize the public key in compressed form from its coordinates"""
    return ser_public_key_ECDSA(public_key, True)


def ser_public_key_uncompressed(public_key: (int, int)) -> bytes:
    """Serialize the public key in uncompressed form from its coordinates"""
    return ser_public_key_ECDSA(public_key, False)


def ser_public_key_schnorr(public_key: (int, int)) -> bytes:
    """Serialize the public key in schnorr format from its coordinates"""
    return bytes_from_int(public_key[0], NUM_BYTE_32)
