from base58 import b58encode_check
from Tools import bytes_from_int, hash160, int_from_bytes
from hashlib import sha512, pbkdf2_hmac
import hmac
from ECDSA import multiply
from Keys import ser_public_key_compressed


# -------------------------------------------------------------------------------------------------------- #
# Coin              Public Key          Private Key	        Address Encoding	            BIP 32 Path
# Bitcoin	        0x0488b21e - xpub	0x0488ade4 - xprv	P2PKH or P2SH	                m/44'/0'
# Bitcoin	        0x049d7cb2 - ypub	0x049d7878 - yprv	P2WPKH in P2SH	                m/49'/0'
# Bitcoin	        0x04b24746 - zpub	0x04b2430c - zprv	P2WPKH	                        m/84'/0'
# Bitcoin	        0x0295b43f - Ypub	0x0295b005 - Yprv	Multi-signature P2WSH in P2SH	-
# Bitcoin	        0x02aa7ed3 - Zpub	0x02aa7a99 - Zprv	Multi-signature P2WSH	        -
# Bitcoin Testnet	0x043587cf - tpub	0x04358394 - tprv	P2PKH or P2SH	                m/44'/1'
# Bitcoin Testnet	0x044a5262 - upub	0x044a4e28 - uprv	P2WPKH in P2SH	                m/49'/1'
# Bitcoin Testnet	0x045f1cf6 - vpub	0x045f18bc - vprv	P2WPKH	                        m/84'/1'
# Bitcoin Testnet	0x024289ef - Upub	0x024285b5 - Uprv	Multi-signature P2WSH in P2SH	-
# Bitcoin Testnet	0x02575483 - Vpub	0x02575048 - Vprv	Multi-signature P2WSH	        -
# -------------------------------------------------------------------------------------------------------- #


# Definisco alcune costanti
NUM_BYTE_1 = 1
NUM_BYTE_4 = 4
NUM_BYTE_32 = 32
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337


def mnemonic_to_seed(words: str, passphrase="") -> bytes:
    """From a mnemonic generates a 512 bit seed following BIP-39"""
    iterations = 2048
    passphrase = "mnemonic" + passphrase
    return pbkdf2_hmac('sha512', words.encode("utf-8"), passphrase.encode("utf-8"), iterations)


def fingerprint(pub_key: bytes) -> bytes:
    """Create a fingerprint of the serialized pub_key in input (starts w/ 02 or 03)"""
    return hash160(pub_key)[:4]


# Serialization of extended priv keys (priv key + chain code)
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data
def ser_extended_priv_keys(priv_key: int, chain_code: bytes, index: int, level=0, parent_pub_key=b'\x00',
                           master_key='False', mainnet='True') -> bytes:
    """Serialize an extended private key (priv key + chain code)"""
    if mainnet == 'True':
        version_byte = b'\x04\x88\xAD\xE4'
    else:
        version_byte = b'\x04\x35\x83\x94'
    depth = bytes_from_int(level, NUM_BYTE_1)
    if master_key == 'True':
        finger_print = b'\x00\x00\x00\x00'
    else:
        finger_print = fingerprint(parent_pub_key)
    child_number = bytes_from_int(index, NUM_BYTE_4)
    key = version_byte + depth + finger_print + child_number + chain_code + b'\x00' + bytes_from_int(priv_key, NUM_BYTE_32)
    return b58encode_check(key)


# Serialization of extended pub keys (pub key + chain code)
# 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
# 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
# 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
# 4 bytes: child number. (0x00000000 if master key)
# 32 bytes: the chain code
# 33 bytes: the public key or private key data
def ser_extended_pub_keys(pub_key: bytes, chain_code: bytes, index: int, level=0, parent_ser_pub_key=b'\x00',
                          master_key='False', mainnet='True') -> bytes:
    """Serialize an extended public key (public key + chain code)"""
    if mainnet == 'True':
        version_byte = b'\x04\x88\xB2\x1E'
    else:
        version_byte = b'\x04\x35\x87\xCF'
    depth = bytes_from_int(level, NUM_BYTE_1)
    if master_key == 'True':
        finger_print = b'\x00\x00\x00\x00'
    else:
        finger_print = fingerprint(parent_ser_pub_key)
    child_number = bytes_from_int(index, NUM_BYTE_4)
    key = version_byte + depth + finger_print + child_number + chain_code + pub_key
    return b58encode_check(key)


def master_key_generation(seed: bytes) -> (int, bytes):
    """Generate extended master key (not serialized) from seed"""
    salt = "Bitcoin seed"
    a = hmac.new(salt.encode(), seed, sha512).digest()
    aL = a[0:32]
    aR = a[32:]
    master_priv_key = int_from_bytes(aL)
    master_chain_code = aR
    return master_priv_key, master_chain_code


def CKDpriv(xpriv: (int, bytes), index: int) -> (int, bytes):
    """Generate a child extended private key from the parent extended private key (not serialized)"""
    k_par, c_par = xpriv
    # check if it's hardened derivation (index >= 2**31)
    if index >= 2 ** 31:
        h = hmac.new(c_par, b'\x00' + bytes_from_int(k_par, NUM_BYTE_32) + bytes_from_int(index, NUM_BYTE_4), sha512).digest()
    else:
        h = hmac.new(c_par, ser_public_key_compressed(multiply(k_par)) + bytes_from_int(index, 4), sha512).digest()
    hL = h[0:32]
    hR = h[32:]
    k_i = (int_from_bytes(hL) + k_par) % n
    c_i = hR
    if int_from_bytes(hL) >= n or k_i == 0:
        return IOError("ERRORE, NON è VALIDO!")
    xpriv_child = k_i, c_i
    return xpriv_child


def CKDpub(xpub: (bytes, bytes), index: int) -> (bytes, bytes):
    """Generate a child extended public key from the parent extended public key (not serialized).

    It is only defined for non-hardened child keys."""
    K_par, c_par = xpub
    # Check if i ≥ 2**31, return error if it's true
    if index >= 2 ** 31:
        return IOError("CKDpub è definita solo per non-hardened keys")
    h = hmac.new(c_par, ser_public_key_compressed(K_par) + bytes_from_int(index, NUM_BYTE_4))
    hL = h[0:32]
    hR = h[32:]
    K_i = ser_public_key_compressed(multiply(int_from_bytes(hL)) + K_par)
    c_i = hR
    if int_from_bytes(hL) >= n:
        return IOError("ERRORE, NON è VALIDO!")
    xpub_child = K_i, c_i
    return xpub_child


if __name__ == '__main__':
    # Execute some tests
    seed_hex = "000102030405060708090a0b0c0d0e0f"

    k_master, c_master = master_key_generation(bytes.fromhex(seed_hex))
    K_master = ser_public_key_compressed(multiply(k_master))

    xpriv_m = ser_extended_priv_keys(k_master, c_master, 0, master_key='True')
    xpub_m = ser_extended_pub_keys(K_master, c_master, 0, 0, master_key='True')
    print(xpriv_m.decode())
    print(xpub_m.decode())

    xpriv_m_0h_1_2h = CKDpriv(CKDpriv(CKDpriv((k_master, c_master), 2 ** 31), 1), 2 ** 31 + 2)
    k_m_0h_1_2h, c_m_0h_1_2h = xpriv_m_0h_1_2h
    K_m_0h_1_2h = ser_public_key_compressed(multiply(k_m_0h_1_2h))

    k_m_0h_1_2h_2, c_m_0h_1_2h_2 = CKDpriv(xpriv_m_0h_1_2h, 2)

    xpriv_ser_m_0h_1_2h = ser_extended_priv_keys(k_m_0h_1_2h_2, c_m_0h_1_2h_2, 2, 4, K_m_0h_1_2h)
    print(xpriv_ser_m_0h_1_2h.decode())
