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

# -------------------------------------------------------------- #
#
# La struttura di una transazione bitcoin
#
# -version: 4 bytes [∞]
# -input count: variabile (compact size), solitamente 1 byte
# -inputs:  {
#             -txid: 32 bytes [∞]
#             -vout: 4 bytes [∞]
#             -unlocking script size: variabile (compact size)
#             -unlocking script: variabile
#             -sequence: 4 bytes [∞]
#           }
# -output count: variabile (compact size), solitamente 1 byte
# -outputs: {
#             -value: 8 bytes [∞]
#             -locking script size: variabile (compact size)
#             -locking script: variabile
#           }
# -locktime: 4 bytes [∞]
#
# [∞] -> notazione little endian
# ESEMPIO: 100 (big endian) <-> 001 (little endian)
# ESEMPIO: a2 43 f1 (big endian) <-> f1 43 a2 (little endian)
#
# NB: 1 byte viene rappresentato con due cifre in esadecimale!
#
# -------------------------------------------------------------- #


# Definisco alcune costanti
NUM_BYTES_1 = 1
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
# Dalla tx con cui ricevo i bitcoin devo prendere
# le seguenti informazioni: di fatto l'UTXO
#
# -txid
# -vout
# -locking script
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("e81c6a989848bb6f86be4ebbae4892741125c548c5f80a0b6f89597219ac3c3c")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(1, NUM_BYTES_4)
locking_script_input = bytes.fromhex("76a914bfe9245401f8296878931281b14236e352bc443388ac")
len_locking_script_input = compact_size(locking_script_input)

# -------------------------------------------------------------- #
#
# Adesso devo comporre i campi della mia tx. Nel particolare
# devo stabilire:
#
# -version
# -input count
# -output count
# -locktime
#
# Per ogni input devo stabilire:
#
# -sequence
# -sighash
#
# E per ogni output che creo devo stabilire:
#
# -amount
# -locking script
#
# -------------------------------------------------------------- #

# Dati della tx che sto per inviare
version = bytes_from_int_reversed(1, NUM_BYTES_4)
input_count = bytes_from_int(1, NUM_BYTES_1)
output_count = bytes_from_int(1, NUM_BYTES_1)
locktime = bytes_from_int_reversed(0, NUM_BYTES_4)

# Dati relativi a input #0
sequence = reverse_byte_order(bytes.fromhex("ffffffff"))
sig_hash = bytes_from_int_reversed(1, NUM_BYTES_4)
sig_hash_type = bytes_from_int(1, NUM_BYTES_1)

# Dati relativi a UTXO #0
amount = bytes_from_int_reversed(1092000, NUM_BYTES_8) # 1092000 sats
locking_script_dest = create_locking_script_P2PKH(K_ser)
len_locking_script_dest = compact_size(locking_script_dest)

# ------------------------------------------------------------------------------ #
#
# Ora devo firmare la transazione. Preparo il messaggio che va firmato
#
# Sostituisco al posto dell'unlocking script il locking script della transazione
# che viene referenziata dall'input, che in questo caso, essendo una transazione
# circolare, coincide con il locking script di questa stessa transazione
#
# ------------------------------------------------------------------------------ #
tx_to_be_signed = version + input_count + txid_reverse + vout + len_locking_script_input + locking_script_input + sequence \
                  + output_count + amount + len_locking_script_dest + locking_script_dest + locktime + sig_hash

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

tx_signed = version + input_count + txid_reverse + vout + len_unlocking_script + unlocking_script + sequence \
            + output_count + amount + len_locking_script_dest + locking_script_dest + locktime

print(tx_signed.hex())

# tx SPENT!

print("version: " + version.hex())
print("input count: " + input_count.hex())
print("txid reversed: " + txid_reverse.hex())
print("vout: " + vout.hex())
print("len unlocking script: " + len_unlocking_script.hex())
print("unlocking script: " + unlocking_script.hex())
print("sequence: " + sequence.hex())
print("output count: " + output_count.hex())
print("amount: " + amount.hex())
print("len locking script: " + len_locking_script_dest.hex())
print("locking script: " + locking_script_dest.hex())
print("locktime: " + locktime.hex())


print()
print("signature size: " + compact_size(signature_der_encoded).hex())
print("signature: " + signature_der_encoded.hex())
print("len public key: " + compact_size(K_ser).hex())
print("public key: " + K_ser.hex())
