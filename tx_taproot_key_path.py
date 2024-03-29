from ECDSA import multiply
from Keys import ser_public_key_schnorr
from Address import generate_address_P2TR_testnet
from Schnorr import tagged_hash, sign_schnorr
from Tools import compact_size, reverse_byte_order, bytes_from_int_reversed, bytes_from_int, sha256
from Script import create_locking_script_P2TR, create_locking_script_P2PKH

# -------------------------------------------------------------- #
#
# Obiettivo: creare tx P2TR key path spend da zero!
#
# Faccio una transazione che invia i fondi a me stesso, circolare
# my_address -> my_address
#
# -------------------------------------------------------------- #

# -------------------------------------------------------------- #
#
# La struttura di una transazione bitcoin segwit
#
# -version: 4 bytes [∞]
# -marker: 1 byte
# -flag: 1 byte
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
# -witness: variabile
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
K_ser = ser_public_key_schnorr(K)
# Genero l'address di ricezione P2TR collegato a questa coppia di chiavi crittografiche
address = generate_address_P2TR_testnet(K_ser)  # tb1pgm4lk5h9yzm5zjpezve78hffmwgt70pj7g03kpau9lpdf6lwjxvs64wgl2

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
# -amount received
# -locking script
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("2e97ff3116e6d97a61aa5e27c1ac0903d1b1d3582c8d1bf2f16ee23ebe1daa35")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(0, NUM_BYTES_4)
amount_received = bytes_from_int_reversed(6000, NUM_BYTES_8) # 6000 sats
locking_script_input = create_locking_script_P2TR(K_ser)
len_locking_script_input = compact_size(locking_script_input)

# -------------------------------------------------------------- #
#
# Adesso devo comporre i campi della mia tx. Nel particolare
# devo stabilire:
#
# -marker
# -flag
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
marker = b'\x00'
flag = b'\x01'
version = bytes_from_int_reversed(1, NUM_BYTES_4)
input_count = bytes_from_int(1, NUM_BYTES_1)
output_count = bytes_from_int(1, NUM_BYTES_1)
locktime = bytes_from_int_reversed(0, NUM_BYTES_4)

# Dati relativi a input #0
sequence = reverse_byte_order(bytes.fromhex("ffffffff"))
sig_hash = bytes_from_int_reversed(0, NUM_BYTES_4) # SIGHASH_ALL_TAPROOT 00
sig_hash_type = bytes_from_int(0, NUM_BYTES_1)

# Dati relativi a UTXO #0
amount_to_send = bytes_from_int_reversed(5500, NUM_BYTES_8) # 5500 sats
locking_script_dest = create_locking_script_P2TR(K_ser)
len_locking_script_dest = compact_size(locking_script_dest)

# ------------------------------------------------------------------------------ #
#
# Ora devo firmare la transazione. Preparo il messaggio che va firmato
#
# Il messaggio che viene firmato nelle transazioni segwit è stato nuovamente
# modificato attraverso il BIP-341/342. Nelle linee di codice che seguono,
# definisco tutto ciò che mi serve per costruire il messaggio che andrà firmato.
#
# ------------------------------------------------------------------------------ #

hash_type = sig_hash_type

# sha_prevouts (32) = SHA256(serialization of all input outpoints)
sha_prevouts = sha256(txid_reverse + vout).digest()

# sha_amounts (32): the SHA256 of the serialization of all spent output amounts
sha_amounts = sha256(amount_received).digest()

# sha_scriptpubkeys (32): the SHA256 of all spent outputs' scriptPubKeys, serialized as script inside CTxOut
sha_scriptpubkeys = sha256(len_locking_script_input + locking_script_input).digest()

# sha_sequences (32): the SHA256 of the serialization of all input nSequence.
sha_sequences = sha256(sequence).digest()

# sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
sha_outputs = sha256(amount_to_send + len_locking_script_dest + locking_script_dest).digest()

# spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0 if no annex is present,
# or 1 otherwise (the original witness stack has two or more witness elements,
# and the first byte of the last element is 0x50)
spend_type = bytes.fromhex("00") # key path -> ext_flag = 0

# input_index (4) [∞]: index of this input in the transaction input vector. Index of the first input is 0
input_index = bytes_from_int_reversed(0, NUM_BYTES_4)

tx_to_be_signed = b'\x00' + hash_type + version + locktime + sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences\
    + sha_outputs + spend_type + input_index  # first element is b'\x00' which is epoch 0

# ------------------------------------------------------------------------------ #
#
# Ora posso procedere con la firma del messaggio creato precedentemente.
#
# ------------------------------------------------------------------------------ #

# Faccio l'hash del messaggio
tx_hash = tagged_hash("TapSighash", tx_to_be_signed)

# Firmo il messaggio con la chiave privata k, impostando un valore fisso del nonce pari a 100
signature = sign_schnorr(private_key=k, msg=tx_hash, k=100)

# Schnorr non utilizza l'encoding DER della firma
# Visto che ho usato SIGHASH_ALL, non devo aggiungere alcun byte extra alla firma

# ------------------------------------------------------------------------------ #
#
# Ora devo procedere con la creazione del campo witness della transazione.
#
# Per ogni input è necessario aggiungere un campo witness
#
# Tale witness è composta nel seguente modo:
# -witness_count: compact_size #byte per descrivere il numero di elementi presenti
# + per ogni elemento presente:
# -compact_size #bytes da cui è composto l'elemento
# -elemento rappresentato in bytes
#
# Nel nostro caso abbiamo solo 1 input:
# -witness_count = 1
# -firma
#
# ------------------------------------------------------------------------------ #

witness_count = b'\x01'  # signature_der_encoded and public_key

witness = witness_count + compact_size(signature) + signature

# ------------------------------------------------------------------------------ #
#
# A questo punto ho tutti gli elementi per poter costruire la mia transazione!
#
# ------------------------------------------------------------------------------ #

tx_signed = version + marker + flag + input_count + txid_reverse + vout + b'\x00' + sequence\
    + output_count + amount_to_send + len_locking_script_dest + locking_script_dest + witness + locktime

print(tx_signed.hex())

# tx SPENT!

print()
print("version: " + version.hex())
print("marker: " + marker.hex())
print("flag: " + flag.hex())
print("input count: " + input_count.hex())
print("txid reversed: " + txid_reverse.hex())
print("vout: " + vout.hex())
print("len unlocking script: 00")
print("sequence: " + sequence.hex())
print("output count: " + output_count.hex())
print("amount: " + amount_to_send.hex())
print("len locking script: " + len_locking_script_dest.hex())
print("locking script: " + locking_script_dest.hex())
print("witness1 : " + witness.hex())
print("locktime: " + locktime.hex())


print()
print("witness count: " + witness_count.hex())
print("signature size: " + compact_size(signature).hex())
print("signature: " + signature.hex())