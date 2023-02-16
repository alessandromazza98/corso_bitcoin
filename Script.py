from Tools import hash160, compact_size


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
