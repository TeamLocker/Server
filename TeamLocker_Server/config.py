import configparser
import os

config = configparser.ConfigParser()
with open(os.path.join(os.path.dirname(__file__), "config.ini")) as f:
    config.read_file(f)

connection_string = "postgresql://{}:{}@{}:{}/{}".format(
    config.get("Database", "username"),
    config.get("Database", "password"),
    config.get("Database", "host"),
    config.get("Database", "port"),
    config.get("Database", "database")
)