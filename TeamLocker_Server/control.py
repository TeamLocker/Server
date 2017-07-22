import sys
import config
import crypto
import models
from getpass import getpass


def main():
    global commands
    commands = {
        "create_schema": command_create_schema,
        "add_user": command_add_user
    }

    if len(sys.argv) < 2:
        print_usage()
        return

    command_handler = commands.get(sys.argv[1])
    if not command_handler:
        print_usage()
        return
    command_handler()


def print_usage():
    print("Available Commands: " + ", ".join(commands.keys()))


def init_db():
    models.init(config.connection_string)


def read_input_yn(message):
    value = ""
    while value not in ["y", "n"]:
        value = input(message).lower()
    return value == "y"


def read_input_nonempty(message, password=False):
    value = ""
    while not value.strip():
        if password:
            value = getpass(message)
        else:
            value = input(message)
    return value


def command_create_schema():
    print("Creating schema...")
    init_db()
    models.create_all()
    print("Done!")


def command_add_user():
    print("You are about to add a user using the server control utility. Adding users in this way is not recommended "
          "as the user's raw password will be temporarily handled by the server. The recommended way to add users is "
          "through the desktop client. This method should only be used when there are no administrator users available "
          "in order to use the desktop client.\n")
    read_input_yn("Are you sure you want to continue? (y/n): ")

    full_name = read_input_nonempty("Full Name: ")
    username = read_input_nonempty("Username: ")
    match = False
    password = None
    while not match:
        password = read_input_nonempty("Password: ", password=True)
        if password == read_input_nonempty("Password (Confirm): ", password=True):
            match = True
        else:
            print("Passwords do not match!")
    is_admin = read_input_yn("Is this user an administrator? (y/n): ")

    print("Creating user...")
    auth_key_hash = crypto.generate_auth_key_hash(crypto.generate_auth_key(username, password))

    public_key, private_key = crypto.generate_keypair()
    key, kdf_salt = crypto.derive_key(password)
    encrypted_private_key = crypto.shared_key_encrypt(private_key, key)

    init_db()

    user = models.User()
    user.username = username
    user.full_name = full_name
    user.auth_key_hash = auth_key_hash
    user.encrypted_private_key = encrypted_private_key
    user.public_key = public_key
    user.kdf_salt = kdf_salt
    user.is_admin = is_admin

    models.db_session.add(user)
    models.db_session.commit()


if __name__ == "__main__":
    main()