import pysodium
import binascii


def generate_auth_key(username, password):
    # We encode then decode the username here so that it is in the system's default encoding just in case this isn't
    # set to UTF-8.  This is because pysodium's crypto_hash_sha512() function will decode the string using the system's
    # default encoding rather than just taking in a byte array for some reason.
    salt = pysodium.crypto_hash_sha512(username.encode("UTF-8").decode())[:32]

    OPSLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
    MEMLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

    auth_key = pysodium.crypto_pwhash_scryptsalsa208sha256(64, password.encode("UTF-8"), salt, OPSLIMIT, MEMLIMIT)
    return binascii.hexlify(auth_key).decode("UTF-8")


def generate_auth_key_hash(auth_key):
    OPSLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
    MEMLIMIT = pysodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE

    auth_key_hash = pysodium.crypto_pwhash_scryptsalsa208sha256_str(auth_key, OPSLIMIT, MEMLIMIT)

    return auth_key_hash


def verify_auth_key(stored_auth_key_hash, supplied_auth_key):
    return pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify(stored_auth_key_hash, supplied_auth_key)
