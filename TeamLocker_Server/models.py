from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, ForeignKey, Binary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship

db_session = scoped_session(sessionmaker())
Base = declarative_base()
Base.query = db_session.query_property()


def create_all():
    Base.metadata.create_all()


def init(connection_string):
    engine = create_engine(connection_string)
    Base.metadata.bind(engine)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    auth_key_hash = Column(String)
    encrypted_private_key = Column(Binary)
    encrypted_private_key_nonce = Column(Binary)
    public_key = Column(Binary)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    folder_id = Column(Integer, ForeignKey("folders.id"))
    read = Column(Boolean)
    write = Column(Boolean)


class EncryptedAccountDataItem(Base):
    __tablename__ = "encrypted_account_data"

    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey("accounts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    permission_id = Column(Integer, ForeignKey("permissions.id"))
    encrypted_metadata = Column(Binary)
    encrypted_password = Column(Binary)


class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True)
    folder_id = Column(Integer, ForeignKey("folders.id"))


class Folder(Base):
    __tablename__ = "folders"

    id = Column(Integer, primary_key=True)
    name = Column(String)
