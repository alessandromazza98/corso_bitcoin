from ECDSA import multiply, sign
from Keys import ser_public_key_compressed
from Address import generate_address_P2WPKH_testnet
from Tools import compact_size, reverse_byte_order, bytes_from_int_reversed, bytes_from_int, sha256_2, DER_encoding
from Script import create_locking_script_P2PKH, create_locking_script_P2WPKH


# -------------------------------------------------------------- #
#
# Obiettivo: creare tx P2WPKH da zero!
#
# Faccio una transazione che invia i fondi a me stesso, circolare
# my_address -> my_address
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
# Genero l'address di ricezione P2WPKH collegato a questa coppia di chiavi crittografiche
address = generate_address_P2WPKH_testnet(K_ser)  # tb1qhl5jg4qplq5ks7ynz2qmzs3kudftc3pnnm4e67

# -------------------------------------------------------------- #
#
# Adesso mando dei bitcoin su questo address in modo da poterli
# successivamente andare a spendere, creando da zero la tx
# di spesa. Fhorte!
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("923e4b22fd49d3f29f069ad36f754ce9e09e891bb58a8d907c6ea354d73fbf55")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(1, NUM_BYTES_4)
amount_received = bytes_from_int_reversed(1783107, NUM_BYTES_8) # 1783107 sats

# Dati della tx che sto per inviare
marker = b'\x00'
flag = b'\x01'
input_count = bytes_from_int(1, NUM_BYTES_1)
version = bytes_from_int_reversed(1, NUM_BYTES_4)
amount_to_send = bytes_from_int_reversed(1782000, NUM_BYTES_8) # 1782000 sats
sequence = bytes.fromhex("ffffffff")
output_count = bytes_from_int(1, NUM_BYTES_1)
locking_script = create_locking_script_P2WPKH(K_ser)
len_locking_script = compact_size(locking_script)
locktime = bytes_from_int_reversed(0, NUM_BYTES_4)
sig_hash = bytes_from_int_reversed(1, NUM_BYTES_4)
sig_hash_type = bytes_from_int(1, NUM_BYTES_1)

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
scriptCode = create_locking_script_P2PKH(K_ser)
scriptCode = compact_size(scriptCode) + scriptCode

# hashPrevouts = hash256^2(txid_reverse + vout of all inputs)
hashPrevouts = sha256_2(txid_reverse + vout)

# hashSequence =  hash256^2(sequence of all inputs)
hashSequence = sha256_2(sequence)

# hashOutputs =  hash256^2(outputs_amount + len_locking script + locking_script of all outputs)
hashOutputs = sha256_2(amount_to_send + len_locking_script + locking_script)

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

# Firmo il messaggio con la chiave privata k, impostando un valore fisso del nonce pari a 100
signature = sign(private_key=k, msg=tx_hash, k=100)

# Codifico la firma seguendo lo standard DER e la concateno al sig_hash_type
signature_der_encoded = DER_encoding(signature)
signature_der_encoded = signature_der_encoded + sig_hash_type

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
# -witness_count = 2
# -firma
# -chiave pubblica
#
# ------------------------------------------------------------------------------ #

witness_count = b'\x02'  # signature_der_encoded and public_key

witness = witness_count + compact_size(signature_der_encoded) + signature_der_encoded\
          + compact_size(K_ser) + K_ser

# ------------------------------------------------------------------------------ #
#
# A questo punto ho tutti gli elementi per poter costruire la mia transazione!
#
# ------------------------------------------------------------------------------ #

tx_signed = version + marker + flag + input_count + txid_reverse + vout + b'\x00' + sequence\
    + output_count + amount_to_send + len_locking_script + locking_script + witness + locktime

print(tx_signed.hex())

# tx SPENT!
