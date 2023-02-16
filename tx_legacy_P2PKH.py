from ECDSA import multiply, sign
from Keys import ser_public_key_compressed
from Address import generate_address_P2PKH_testnet
from Tools import compact_size, reverse_byte_order, bytes_from_int_reversed, bytes_from_int, sha256_2, DER_encoding
from Script import create_locking_script_P2PKH


# -------------------------------------------------------------- #
#
# Obiettivo: creare tx P2PKH da zero!
#
# Faccio una transazione che invia i fondi a me stesso, circolare
# my_address -> my_address
#
# -------------------------------------------------------------- #


# Definisco alcune costanti
NUM_BYTES_4 = 4
NUM_BYTES_8 = 8

# Seleziono una chiave privata k, numero intero fra 0 e n-1, dove n è l'ordine della curva ellittica
k = 75282383716026770851796771414193474962426130999119568701422782830663027711072
# Genero la chiave pubblica corrispondente
K = multiply(k)
# La serializzo nella sua forma compressa
K_ser = ser_public_key_compressed(K)
# Genero l'address di ricezione P2PKH collegato a questa coppia di chiavi crittografiche
address = generate_address_P2PKH_testnet(K_ser)  # my1gegEiLdsJcZ3oNsDKjNVDT1fRjDtqmY

# -------------------------------------------------------------- #
#
# Adesso mando dei bitcoin su questo address in modo da poterli
# successivamente andare a spendere, creando da zero la tx
# di spesa. Fhorte!
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("f31a652c120f3059a21a992c47440692790c6fb018bf7337a333c3b65bbaac43")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(1, NUM_BYTES_4)
locking_script = create_locking_script_P2PKH(K_ser)
len_locking_script = compact_size(locking_script)

# Dati della tx che sto per inviare
input_count = bytes_from_int(1)[-1:]
version = bytes_from_int_reversed(1, NUM_BYTES_4)
amount = bytes_from_int_reversed(10700, NUM_BYTES_8) # 10700 sats
sequence = bytes.fromhex("ffffffff")
output_count = bytes_from_int(1)[-1:]
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
tx_to_be_signed = version + input_count + txid_reverse + vout + len_locking_script + locking_script + sequence\
                  + output_count + amount + len_locking_script + locking_script + locktime + sig_hash

# Faccio l'hash del messaggio
tx_hash = sha256_2(tx_to_be_signed)

# Firmo il messaggio con la chiave privata k, impostando un valore fisso del nonce pari a 100
signature = sign(private_key=k, msg=tx_hash, k=100)

# Codifico la firma seguendo lo standard DER e la concateno al sig_hash_type
signature_der_encoded = DER_encoding(signature)
signature_der_encoded = signature_der_encoded + sig_hash_type

# A questo punto posso creare il corretto unlocking script per la transazione
unlocking_script = compact_size(signature_der_encoded) + signature_der_encoded + compact_size(K_ser) + K_ser
len_unlocking_script = compact_size(unlocking_script)


# ------------------------------------------------------------------------------ #
#
# A questo punto ho tutti gli elementi per poter costruire la mia transazione!
#
# ------------------------------------------------------------------------------ #

tx_signed = version + input_count + txid_reverse + vout + len_unlocking_script + unlocking_script + sequence\
            + output_count + amount + len_locking_script + locking_script + locktime

print(tx_signed.hex())

# tx SPENT!
