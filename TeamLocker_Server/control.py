import sys
import models
import config
import crypto
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
    return value


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
          "in order to use the desktop client. It is therefore strongly recommended that the user changes their "
          "password after logging into an account that was created using this utility.\n")
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



if __name__ == "__main__":
    main()