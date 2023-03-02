from Tools import hash160, compact_size, bytes_from_int, sha256


# Definisco alcune costanti
NUM_BYTE_1 = 1

def create_locking_script_P2PKH(public_key: bytes) -> bytes:
    """Create P2PKH locking script from public key"""
    dup = b'\x76'
    hash_160 = b'\xa9'
    pk_hash = hash160(public_key)
    pk_hash_length = compact_size(pk_hash)
    equalverify = b'\x88'
    checksig = b'\xac'
    return dup + hash_160 + pk_hash_length + pk_hash + equalverify + checksig


def create_locking_script_P2SH(script: bytes) -> bytes:
    """Create P2SH locking script from script"""
    hash_160 = b'\xa9'
    script_hash = hash160(script)
    script_hash_length = compact_size(script_hash)
    equal = b'\x87'
    return hash_160 + script_hash_length + script_hash + equal


def create_redeem_script_multisig(public_keys: [bytes], m: int, n: int) -> bytes:
    """Create a redeem multi-signature script m-of-n from public keys, m and n"""
    OP_M = bytes_from_int(m + 0x50, NUM_BYTE_1)
    OP_N = bytes_from_int(n + 0x50, NUM_BYTE_1)
    keys = [compact_size(public_key) + public_key for public_key in public_keys]
    keys = b''.join(keys)
    OP_CHECKMULTISIG = b'\xae'
    return OP_M + keys + OP_N + OP_CHECKMULTISIG


def create_locking_script_P2WPKH(public_key: bytes) -> bytes:
    """Create P2WPKH locking script from public key"""
    version = b'\x00'
    public_key_hash160 = hash160(public_key)
    return version + compact_size(public_key_hash160) + public_key_hash160



def create_locking_script_P2WSH(script: bytes) -> bytes:
    """Create P2WSH locking script from script"""
    version = b'\x00'
    script_hash = sha256(script).digest()
    return version + compact_size(script_hash) + script_hash


def create_locking_script_P2TR(public_key: bytes) -> bytes:
    """Create P2TR locking script from public key"""
    version = b'\x51'
    return version + compact_size(public_key) + public_key
