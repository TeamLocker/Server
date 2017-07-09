import pysodium
import binascii
from protobufs.Libsodium_pb2 import LibsodiumItem


def generate_auth_key(username, password):
    # We encode then decode the username here so that it is in the system's default encoding just in case this isn't
    # set to UTF-8.  This is because pysodium's crypto_hash_sha512() function will decode the string using the system's
    # default encoding rather than just taking in a byte array for some reason.
    salt = pysodium.crypto_hash_sha512(username.encode("UTF-8").decode())[:32]

    OPSLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
    MEMLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

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

    packed_auth_key_hash = LibsodiumItem()
    packed_auth_key_hash.data = auth_key_hash
    packed_auth_key_hash.ops_limit = auth_key.ops_limit
    packed_auth_key_hash.mem_limit = auth_key.mem_limit

    return packed_auth_key_hash.SerializeToString()


def verify_auth_key(stored_auth_key_hash, supplied_auth_key):
    return pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify(unpack_libsodium_item(stored_auth_key_hash).data,
                                                                  unpack_libsodium_item(supplied_auth_key).data)


def unpack_libsodium_item(packed_libsodium_item):
    obj = LibsodiumItem()
    obj.ParseFromString(packed_libsodium_item)
    return obj
