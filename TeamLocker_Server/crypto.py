import pysodium
import binascii
import base64
from protobufs.Libsodium_pb2 import LibsodiumItem


def generate_auth_key(username, password):
    # We encode then decode the username here so that it is in the system's default encoding just in case this isn't
    # set to UTF-8.  This is because pysodium's crypto_hash_sha512() function will decode the string using the system's
    # default encoding rather than just taking in a byte array for some reason.
    salt = pysodium.crypto_hash_sha512(username.encode("UTF-8").decode())[:32]

    OPSLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
    MEMLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

    # TODO: Magic number 64?
    auth_key = pysodium.crypto_pwhash_scryptsalsa208sha256(64, password.encode("UTF-8"), salt, OPSLIMIT, MEMLIMIT)

    packed_auth_key = LibsodiumItem()
    packed_auth_key.data = auth_key
    packed_auth_key.ops_limit = OPSLIMIT
    packed_auth_key.mem_limit = MEMLIMIT

    return packed_auth_key.SerializeToString()


def generate_auth_key_hash(packed_auth_key):
    auth_key = unpack_libsodium_item(packed_auth_key)

    auth_key_hash = pysodium.crypto_pwhash_scryptsalsa208sha256_str(auth_key.data, auth_key.ops_limit,
                                                                    auth_key.mem_limit)

    return auth_key_hash


def verify_auth_key(stored_auth_key_hash, supplied_auth_key):
    try:
        pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify(stored_auth_key_hash, supplied_auth_key)
        return True
    except ValueError:
        return False


def generate_keypair():
    return pysodium.crypto_box_keypair()


def derive_key(password):
    salt = pysodium.randombytes(pysodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
    key = derive_key_with_salt(password, salt)
    return key, salt


def derive_key_with_salt(password, salt):
    OPSLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
    MEMLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

    # TODO: Magic number 64?
    key = pysodium.crypto_pwhash_scryptsalsa208sha256(64, password, salt, OPSLIMIT, MEMLIMIT)
    return key


def shared_key_encrypt(data, key):
    nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)

    cyphertext = pysodium.crypto_secretbox(data, nonce, key)

    packed_cyphertext = LibsodiumItem()
    packed_cyphertext.data = cyphertext
    packed_cyphertext.nonce = nonce

    return packed_cyphertext.SerializeToString()


def shared_key_decrypt(packed_cyphertext, key):
    obj = unpack_libsodium_item(packed_cyphertext)
    nonce = obj.nonce
    cyphertext = obj.data

    result = pysodium.crypto_secretbox_open(cyphertext, nonce, key)

    return result


def unpack_libsodium_item(packed_libsodium_item):
    obj = LibsodiumItem()
    obj.ParseFromString(packed_libsodium_item)
    return obj
