from ECDSA import multiply, sign
from Keys import ser_public_key_compressed
from Address import generate_address_P2PKH_testnet, generate_address_P2SH_testnet
from Tools import compact_size, reverse_byte_order, bytes_from_int_reversed, bytes_from_int, sha256_2, DER_encoding
from Script import create_redeem_script_multisig, create_locking_script_P2PKH, create_locking_script_P2WSH

# -------------------------------------------------------------- #
#
# Obiettivo: creare tx P2SH_P2WSH da zero!
#
# Faccio una transazione che invia i fondi all'address
# dell'esempio P2PKH!
#
# Nel particolare sarà una transazione multifirma 2-di-2
#
# my_address_P2SH_P2WSH -> my_address_P2PKH
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

# Creo il witness script multi-firma 2-di-2
witness_script = create_redeem_script_multisig([K1_ser, K2_ser], 2, 2)

# Creo il redeem script P2WSH
redeem_script = create_locking_script_P2WSH(witness_script)

# Genero l'address di ricezione P2SH-P2WSH
address = generate_address_P2SH_testnet(redeem_script) # 2MzFcC5atqiVFcdEsFKmfY2jmpXWujLgXVz

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
# Dalla tx con cui ricevo i bitcoin devo prendere
# le seguenti informazioni: di fatto l'UTXO
#
# -txid
# -vout
# -amount received
#
# In questo caso ho già calcolato il redeem script e non ho
# bisogno di prendere il locking script presente nella UTXO
# che mi ha inviato i bitcoin
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("452d8ddee4d678f166e12be0432a9358e56376a13ddcfd4890b072022619ce48")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(1, NUM_BYTES_4)
amount_received = bytes_from_int_reversed(6251, NUM_BYTES_8) # 6251 sats

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
sig_hash = bytes_from_int_reversed(1, NUM_BYTES_4)
sig_hash_type = bytes_from_int(1, NUM_BYTES_1)

# Dati relativi a UTXO #0
amount_to_send = bytes_from_int_reversed(5500, NUM_BYTES_8) # 5500 sats
locking_script_P2PKH = create_locking_script_P2PKH(K_dest_ser)
len_locking_script_P2PKH = compact_size(locking_script_P2PKH)

# ------------------------------------------------------------------------------ #
#
# Ora devo firmare la transazione. Preparo il messaggio che va firmato
#
# Il messaggio che viene firmato nelle transazioni segwit è stato completamente
# modificato attraverso il BIP-143. Nelle linee di codice che seguono, definisco
# tutto ciò che mi serve per costruire il messaggio che andrà firmato.
#
# ------------------------------------------------------------------------------ #

# scriptCode of the input
scriptCode = witness_script
scriptCode = compact_size(scriptCode) + scriptCode

# hashPrevouts = hash256^2(txid_reverse + vout of all inputs)
hashPrevouts = sha256_2(txid_reverse + vout)

# hashSequence =  hash256^2(sequence of all inputs)
hashSequence = sha256_2(sequence)

# hashOutputs =  hash256^2(outputs_amount + len_locking script + locking_script of all outputs)
hashOutputs = sha256_2(amount_to_send + len_locking_script_P2PKH + locking_script_P2PKH)

# outpoint = txid_reverse + vout of the input I am signing
outpoint = txid_reverse + vout

tx_to_be_signed = version + hashPrevouts + hashSequence + outpoint + scriptCode + amount_received\
                  + sequence + hashOutputs + locktime + sig_hash

# ------------------------------------------------------------------------------ #
#
# Ora posso procedere con la firma del messaggio creato precedentemente.
#
# ------------------------------------------------------------------------------ #

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
unlocking_script = compact_size(redeem_script) + redeem_script
len_unlocking_script = compact_size(unlocking_script)

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
# -witness_count = 4
# -OP_0
# -firma1
# -firma2
# -witness script
#
# ------------------------------------------------------------------------------ #

witness_count = b'\x04'

witness = witness_count + OP_0\
          + compact_size(signature1_der_encoded) + signature1_der_encoded\
          + compact_size(signature2_der_encoded) + signature2_der_encoded\
          + compact_size(witness_script) + witness_script

# ------------------------------------------------------------------------------ #
#
# A questo punto ho tutti gli elementi per poter costruire la mia transazione!
#
# ------------------------------------------------------------------------------ #

tx_signed = version + marker + flag + input_count + txid_reverse + vout + len_unlocking_script + unlocking_script\
            + sequence + output_count + amount_to_send + len_locking_script_P2PKH + locking_script_P2PKH\
            + witness + locktime

print(tx_signed.hex())

# tx SPENT!

print()
print("version: " + version.hex())
print("marker: " + marker.hex())
print("flag: " + flag.hex())
print("input count: " + input_count.hex())
print("txid reversed: " + txid_reverse.hex())
print("vout: " + vout.hex())
print("len unlocking script: " + len_unlocking_script.hex())
print("unlocking script: " + unlocking_script.hex())
print("sequence: " + sequence.hex())
print("output count: " + output_count.hex())
print("amount: " + amount_to_send.hex())
print("len locking script: " + len_locking_script_P2PKH.hex())
print("locking script: " + locking_script_P2PKH.hex())
print("witness1: " + witness.hex())
print("locktime: " + locktime.hex())

print()
print("witness count: " + witness_count.hex())
print("OP_0: " + OP_0.hex())
print("signature size 1: " + compact_size(signature1_der_encoded).hex())
print("signature 1: " + signature1_der_encoded.hex())
print("signature size 2: " + compact_size(signature2_der_encoded).hex())
print("signature 2: " + signature2_der_encoded.hex())
print("len redeem script: " + compact_size(redeem_script).hex())
print("redeem script: " + redeem_script.hex())
