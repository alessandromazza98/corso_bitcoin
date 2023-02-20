from base58 import b58encode_check
from Tools import hash160
from bech32ref import encode


def generate_address_legacy(data: bytes, version_prefix: bytes) -> str:
    """Generate legacy address from public key or script"""
    return b58encode_check(version_prefix + hash160(data)).decode()


def generate_address_P2PKH(public_key: bytes) -> str:
    """Generate P2PKH address from public key"""
    return generate_address_legacy(public_key, b'\x00')


def generate_address_P2SH(script: bytes) -> str:
    """Generate P2SH address from script"""
    return generate_address_legacy(script, b'\x05')


def generate_address_P2PKH_testnet(public_key: bytes) -> str:
    """Generate P2PKH address for testnet from public key"""
    return generate_address_legacy(public_key, b'\x6F')


def generate_address_P2SH_testnet(script: bytes) -> str:
    """Generate P2SH address for testnet from script"""
    return generate_address_legacy(script, b'\xC4')


def generate_address_segwit(data: bytes) -> str:
    """Generate segwit address from public key or script"""
    hrp = "bc"
    witver = 0
    witprog = hash160(data)
    return encode(hrp, witver, witprog)


def generate_address_segwit_testnet(data: bytes) -> str:
    """Generate segwit address for testnet from public key or script"""
    hrp = "tb"
    witver = 0
    witprog = hash160(data)
    return encode(hrp, witver, witprog)
