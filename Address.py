from base58 import b58encode_check
from Tools import hash160


def generate_address_legacy(data: bytes, version_prefix: bytes) -> bytes:
    """Generate legacy address from public key"""
    return b58encode_check(version_prefix + hash160(data))


def generate_address_P2PKH(public_key: bytes) -> bytes:
    """Generate P2PKH address from public key"""
    return generate_address_legacy(public_key, b'\x00')


def generate_address_P2SH(script: bytes) -> bytes:
    """Generate P2SH address from script"""
    return generate_address_legacy(script, b'\x05')


def generate_address_P2PKH_testnet(public_key: bytes) -> bytes:
    """Generate P2PKH address for testnet from public key"""
    return generate_address_legacy(public_key, b'\x6F')


def generate_address_P2SH_testnet(script: bytes) -> bytes:
    """Generate P2SH address for testnet from script"""
    return generate_address_legacy(script, b'\xC4')
