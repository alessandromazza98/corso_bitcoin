from ECDSA import multiply, add
from Keys import ser_public_key_schnorr
from Address import generate_address_P2TR_testnet
from Schnorr import tagged_hash, sign_schnorr
from Tools import compact_size, reverse_byte_order, bytes_from_int_reversed, bytes_from_int, sha256, int_from_bytes
from Script import create_locking_script_P2TR

# -------------------------------------------------------------- #
#
# Obiettivo: creare tx P2TR tapscript path spend da zero!
#
# Faccio una transazione che invia i fondi all'address
# dell'esempio P2TR key path spend!
# my_address_P2TR_tapscript -> my_address_P2TR_key
#
#                 taptweak(P|s1s2s3)
#                           |
#                           |
#                         s1s2s3
#                           |
#                           |
#                     --------------
#                    |              |
#                   s1s2            s3
#                    |
#                ---------
#               |         |
#               s1        s2
#
# -------------------------------------------------------------- #


# Definisco alcune costanti
NUM_BYTES_4 = 4
NUM_BYTES_8 = 8
LEAF_VER = b'\xc0'
OP_CHECKSIG = bytes.fromhex("ac")
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# -------------------------------------------------------------- #
#
# Generazione delle chiavi crittografiche necessarie per la
# creazione di questa transazione
#
# -------------------------------------------------------------- #

# internal private and public key
d = 18968816317819169306095104891728354025797295648084455976845396390496379316944
P = multiply(d)
if P[1] % 2 != 0:
    d = n - d
    P = multiply(d)
P_ser = ser_public_key_schnorr(P)

# s1
k1 = 78931426514357468882601520915645133116503184441831846482294115903507660427950
P1 = multiply(k1)
if P1[1] % 2 != 0:
    k1 = n - k1
    P1 = multiply(k1)
P1_ser = ser_public_key_schnorr(P1)
s1 = compact_size(P1_ser) + P1_ser + OP_CHECKSIG
tapleaf_s1 = tagged_hash("TapLeaf", LEAF_VER + compact_size(s1) + s1)

# s2
k2 = 53223457762164509281563914254149592059900713682793766747801624337469509007268
P2 = multiply(k2)
if P2[1] % 2 != 0:
    k2 = n - k2
    P2 = multiply(k2)
P2_ser = ser_public_key_schnorr(P2)
s2 = compact_size(P2_ser) + P2_ser + OP_CHECKSIG
tapleaf_s2 = tagged_hash("TapLeaf", LEAF_VER + compact_size(s2) + s2)

# s3
k3 = 48034867036800174573932088253129938072033279788016841632941291149515077395801
P3 = multiply(k3)
if P3[1] % 2 != 0:
    k3 = n - k3
    P3 = multiply(k3)
P3_ser = ser_public_key_schnorr(P3)
s3 = compact_size(P3_ser) + P3_ser + OP_CHECKSIG
tapleaf_s3 = tagged_hash("TapLeaf", LEAF_VER + compact_size(s3) + s3)

tapbranch_s1s2 = tagged_hash("TapBranch", b''.join(sorted([tapleaf_s1, tapleaf_s2])))

tapbranch_s1s2s3 = tagged_hash("TapBranch", b''.join(sorted([tapbranch_s1s2, tapleaf_s3])))

# tap tweak t
t = tagged_hash("TapTweak", P_ser + tapbranch_s1s2s3)
t = int_from_bytes(t)

# taproot pubkey Q = P + tG
Q = add(P, multiply(t))
Q_ser = ser_public_key_schnorr(Q)

address_tapscript = generate_address_P2TR_testnet(Q_ser) # tb1p4mxklg32p85ukf9qrgep3lkhuqhu9lj5qwcnatec2c0gma2790rqgutkdg

# -------------------------------------------------------------- #
#
# ADDRESS di DESTINAZIONE della mia transazione
#
# -------------------------------------------------------------- #

# Seleziono una chiave privata k, numero intero fra 0 e n-1, dove n è l'ordine della curva ellittica
k_dest = 75282383716026770851796771414193474962426130999119568701422782830663027711072
# Genero la chiave pubblica corrispondente
K_dest = multiply(k_dest)
# La serializzo nella sua forma compressa
K_dest_ser = ser_public_key_schnorr(K_dest)
# Genero l'address di ricezione P2TR collegato a questa coppia di chiavi crittografiche
address_dest = generate_address_P2TR_testnet(K_dest_ser)  # tb1pgm4lk5h9yzm5zjpezve78hffmwgt70pj7g03kpau9lpdf6lwjxvs64wgl2

# -------------------------------------------------------------- #
#
# Adesso mando dei bitcoin su questo address in modo da poterli
# successivamente andare a spendere, creando da zero la tx
# di spesa. Fhorte!
#
# -------------------------------------------------------------- #

# Dati delle tx con cui ho ricevuto i sats
txid = bytes.fromhex("1a7ee5854b190b91e0d2dc8951266365bc724bcada1e829164f3b299e032fac6")
txid_reverse = reverse_byte_order(txid)
vout = bytes_from_int_reversed(0, NUM_BYTES_4)
amount_received = bytes_from_int_reversed(5189, NUM_BYTES_8) # 5189 sats
locking_script_input = create_locking_script_P2TR(Q_ser)
len_locking_script_input = compact_size(locking_script_input)

# Dati della tx che sto per inviare
marker = b'\x00'
flag = b'\x01'
input_count = bytes_from_int(1)[-1:]
version = bytes_from_int_reversed(1, NUM_BYTES_4)
amount_to_send = bytes_from_int_reversed(5000, NUM_BYTES_8) # 5000 sats
sequence = bytes.fromhex("ffffffff")
output_count = bytes_from_int(1)[-1:]
locking_script_dest = create_locking_script_P2TR(K_dest_ser)
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
# Tapscript path spend con s1!
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
spend_type = bytes.fromhex("02") # script path -> ext_flag = 1

# input_index (4): index of this input in the transaction input vector. Index of the first input is 0
input_index = bytes_from_int_reversed(0, NUM_BYTES_4)

# We use SCRIPT PATH, so we have to add
# 1. tapleaf_hash of the script I am using to spend this UTXO
# 2. b'\x00' which is key_version, representing the current version of public keys in the
#            tapscript signature opcode execution
# 3. codesep_pos = the opcode position of the last executed OP_CODESEPARATOR before the currently executed
#                  signature opcode, with the value in little endian (or 0xffffffff if none executed).
scrip_path_used = tapleaf_s1 + b'\x00' + bytes.fromhex("ffffffff")

tx_to_be_signed = b'\x00' + hash_type + version + locktime + sha_prevouts + sha_amounts + sha_scriptpubkeys\
                  + sha_sequences + sha_outputs + spend_type + input_index\
                  + scrip_path_used # first element is b'\x00' which is epoch 0

# ------------------------------------------------------------------------------ #
#
# Ora posso procedere con la firma del messaggio creato precedentemente.
#
# ------------------------------------------------------------------------------ #

# Faccio l'hash del messaggio
tx_hash = tagged_hash("TapSighash", tx_to_be_signed)

# Firmo il messaggio con la chiave privata k, impostando un valore fisso del nonce pari a 100
signature = sign_schnorr(private_key=k1, msg=tx_hash, k=100)

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
# -witness_count = 3
# -[Stack element(s) satisfying TapScript_S1]
# -[TapScript_S1]
# -[Controlblock c]
#
# ------------------------------------------------------------------------------ #

witness_count = b'\x03'  # signature_der_encoded and public_key

# parity bit
if Q[1] % 2 != 0:
    parity_bit = b'\x01'
else:
    parity_bit = b'\x00'

# control block:
# Its first byte stores the leaf version (#3) (top 7 bits) and the sign bit (#6) (bottom bit).
# The next 32 bytes store the (X coordinate only, because x-only key) of the internal public key (#4)
# Every block of 32 bytes after that encodes a component of the Merkle path (#5) connecting the leaf
# to the root (and then, the tweak), going in bottom-up direction.
control_block = bytes([LEAF_VER[0] + parity_bit[0]]) + P_ser + tapleaf_s2 + tapleaf_s3

witness = witness_count\
          + compact_size(signature) + signature\
          + compact_size(s1) + s1\
          + compact_size(control_block) + control_block

# ------------------------------------------------------------------------------ #
#
# A questo punto ho tutti gli elementi per poter costruire la mia transazione!
#
# ------------------------------------------------------------------------------ #

tx_signed = version + marker + flag + input_count + txid_reverse + vout + b'\x00' + sequence\
    + output_count + amount_to_send + len_locking_script_dest + locking_script_dest + witness + locktime

print(tx_signed.hex())

# tx SPENT!
