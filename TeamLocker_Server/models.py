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
    Base.metadata.bind = engine


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    auth_key_hash = Column(String)
    encrypted_private_key = Column(Binary)
    public_key = Column(Binary)
    kdf_salt = Column(Binary)
    encrypted_account_data_items = relationship("EncryptedAccountDataItem", back_populates="user")
    permissions = relationship("Permission", back_populates="user")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    folder_id = Column(Integer, ForeignKey("folders.id"))
    read = Column(Boolean)
    write = Column(Boolean)
    folder = relationship("Folder", back_populates="permissions")
    user = relationship("User", back_populates="permissions")
    encrypted_account_data_items = relationship("EncryptedAccountDataItem", back_populates="permission")


class EncryptedAccountDataItem(Base):
    __tablename__ = "encrypted_account_data"

    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey("accounts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    permission_id = Column(Integer, ForeignKey("permissions.id"))
    encrypted_metadata = Column(Binary)
    encrypted_password = Column(Binary)
    user = relationship("User", back_populates="encrypted_account_data_items")
    account = relationship("Account", back_populates="encrypted_account_data_items")
    permission = relationship("Permission", back_populates="encrypted_account_data_items")


class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True)
    folder_id = Column(Integer, ForeignKey("folders.id"))
    encrypted_account_data_items = relationship("EncryptedAccountDataItem", back_populates="account")
    folder = relationship("Folder", back_populates="accounts")


class Folder(Base):
    __tablename__ = "folders"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    accounts = relationship("Account", back_populates="folder")
    permissions = relationship("Permission", back_populates="folder")
