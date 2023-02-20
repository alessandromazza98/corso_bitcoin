from ECDSA import multiply
from Keys import ser_public_key_schnorr
from Address import generate_address_P2TR_testnet
from Schnorr import tagged_hash, sign_schnorr
from Tools import compact_size, reverse_byte_order, bytes_from_int_reversed, bytes_from_int, sha256
from Script import create_locking_script_P2TR

# -------------------------------------------------------------- #
#
# Obiettivo: creare tx P2TR key path spend da zero!
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
K_ser = ser_public_key_schnorr(K)
# Genero l'address di ricezione P2TR collegato a questa coppia di chiavi crittografiche
address = generate_address_P2TR_testnet(K_ser)  # tb1pgm4lk5h9yzm5zjpezve78hffmwgt70pj7g03kpau9lpdf6lwjxvs64wgl2

# -------------------------------------------------------------- #
#
# Adesso mando dei bitcoin su questo address in modo da poterli
# successivamente andare a spendere, creando da zero la tx
# di spesa. Fhorte!
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("1810aa57b7852c3e145801bec7ca668994c902b99e7f3e16c140c25b1675eb85")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(1, NUM_BYTES_4)
amount_received = bytes_from_int_reversed(5438, NUM_BYTES_8) # 5438 sats
locking_script_input = create_locking_script_P2TR(K_ser)
len_locking_script_input = compact_size(locking_script_input)

# Dati della tx che sto per inviare
marker = b'\x00'
flag = b'\x01'
input_count = bytes_from_int(1)[-1:]
version = bytes_from_int_reversed(1, NUM_BYTES_4)
amount_to_send = bytes_from_int_reversed(5300, NUM_BYTES_8) # 5300 sats
sequence = bytes.fromhex("ffffffff")
output_count = bytes_from_int(1)[-1:]
locking_script_dest = create_locking_script_P2TR(K_ser)
len_locking_script_dest = compact_size(locking_script_dest)
locktime = bytes_from_int_reversed(0, NUM_BYTES_4)
sig_hash = bytes_from_int_reversed(0, NUM_BYTES_4) # SIGHASH_ALL_TAPROOT 00
sig_hash_type = bytes_from_int(0)[-1:]

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
spend_type = bytes.fromhex("00")

# input_index (4): index of this input in the transaction input vector. Index of the first input is 0
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
# Per ogni elemento presente:
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
