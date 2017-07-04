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