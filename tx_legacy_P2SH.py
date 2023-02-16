from ECDSA import multiply, sign
from Keys import ser_public_key_compressed
from Address import generate_address_P2SH_testnet, generate_address_P2PKH_testnet
from Tools import compact_size, reverse_byte_order, bytes_from_int_reversed, bytes_from_int, sha256_2, DER_encoding
from Script import create_redeem_script_multisig, create_locking_script_P2SH, create_locking_script_P2PKH

# -------------------------------------------------------------- #
#
# Obiettivo: creare tx P2SH da zero!
#
# Faccio una transazione che invia i fondi all'address
# dell'esempio P2PKH!
#
# Nel particolare sarà una transazione multifirma 2-di-2
#
# my_address_P2SH -> my_address_P2PKH
#
# -------------------------------------------------------------- #

# Definisco alcune costanti
NUM_BYTES_4 = 4
NUM_BYTES_8 = 8
OP_0 = b'\x00'

# Seleziono una chiave privata k1
k1 = 75282383716026770851796771414193474962426130999119568701422782830663027711070
# Genero la chiave pubblica corrispondente
K1 = multiply(k1)
# La serializzo nella sua forma compressa
K1_ser = ser_public_key_compressed(K1)

# Seleziono una chiave privata k2
k2 = 75282383716026770851796771414193474962426130999119568701422782830663027711082
# Genero la chiave pubblica corrispondente
K2 = multiply(k2)
# La serializzo nella sua forma compressa
K2_ser = ser_public_key_compressed(K2)

# Creo il redeem script multi-firma 2-di-2
redeem_script = create_redeem_script_multisig([K1_ser, K2_ser], 2, 2)

# Genero l'address di ricezione P2SH multi-firma 2-di-2 relativo al redeem script precedente
address = generate_address_P2SH_testnet(redeem_script) # 2MxQ2b48ceW3wanqx4WpVPmKujCQ8v4Tsex

# Seleziono una chiave privata k_dest, per la ricezione dei fondi
k_dest = 75282383716026770851796771414193474962426130999119568701422782830663027711072
# Genero la chiave pubblica corrispondente
K_dest = multiply(k_dest)
# La serializzo nella sua forma compressa
K_dest_ser = ser_public_key_compressed(K_dest)
# Genero l'address di ricezione P2PKH collegato a questa coppia di chiavi crittografiche
address_dest = generate_address_P2PKH_testnet(K_dest_ser)  # my1gegEiLdsJcZ3oNsDKjNVDT1fRjDtqmY

# -------------------------------------------------------------- #
#
# Adesso mando dei bitcoin su questo address in modo da poterli
# successivamente andare a spendere, creando da zero la tx
# di spesa. Fhorte!
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("012ae7ccd6b3e7da5b5c824dc25a2bd16d09ab57590f4552e840ddc24e1015fe")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(1, NUM_BYTES_4)

# Dati della tx che sto per inviare
input_count = bytes_from_int(1)[-1:]
version = bytes_from_int_reversed(1, NUM_BYTES_4)
amount = bytes_from_int_reversed(1285900, NUM_BYTES_8) # 1285900 sats
sequence = bytes.fromhex("ffffffff")
output_count = bytes_from_int(1)[-1:]
locking_script_P2PKH = create_locking_script_P2PKH(K_dest_ser)
len_locking_script_P2PKH = compact_size(locking_script_P2PKH)
locktime = bytes_from_int_reversed(0, NUM_BYTES_4)
sig_hash = bytes_from_int_reversed(1, NUM_BYTES_4)
sig_hash_type = bytes_from_int(1)[-1:]

# ------------------------------------------------------------------------------ #
#
# Ora devo firmare la transazione. Preparo il messaggio che va firmato
#
# Sostituisco al posto dell'unlocking script il locking script della transazione
# che viene referenziata dall'input, che in questo caso, essendo una transazione
# circolare, coincide con il locking script di questa stessa transazione
#
# ------------------------------------------------------------------------------ #
tx_to_be_signed = version + input_count + txid_reverse + vout + compact_size(redeem_script) + redeem_script + sequence\
                  + output_count + amount + len_locking_script_P2PKH + locking_script_P2PKH + locktime + sig_hash

# Faccio l'hash del messaggio
tx_hash = sha256_2(tx_to_be_signed)

# Firmo il messaggio con la chiave privata k1, impostando un valore fisso del nonce pari a 100
signature1 = sign(private_key=k1, msg=tx_hash, k=100)

# Codifico la firma seguendo lo standard DER e la concateno al sig_hash_type
signature1_der_encoded = DER_encoding(signature1)
signature1_der_encoded = signature1_der_encoded + sig_hash_type

# Firmo il messaggio con la chiave privata k2, impostando un valore fisso del nonce pari a 100
signature2 = sign(private_key=k2, msg=tx_hash, k=100)

# Codifico la firma seguendo lo standard DER e la concateno al sig_hash_type
signature2_der_encoded = DER_encoding(signature2)
signature2_der_encoded = signature2_der_encoded + sig_hash_type

# A questo punto posso creare il corretto unlocking script per la transazione
unlocking_script = OP_0 + compact_size(signature1_der_encoded) + signature1_der_encoded\
                   + compact_size(signature2_der_encoded) + signature2_der_encoded\
                   + compact_size(redeem_script) + redeem_script
len_unlocking_script = compact_size(unlocking_script)

# ------------------------------------------------------------------------------ #
#
# A questo punto ho tutti gli elementi per poter costruire la mia transazione!
#
# ------------------------------------------------------------------------------ #

tx_signed = version + input_count + txid_reverse + vout + len_unlocking_script + unlocking_script + sequence\
            + output_count + amount + len_locking_script_P2PKH + locking_script_P2PKH + locktime

print(tx_signed.hex())

# tx SPENT!
