# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protobufs/Objects.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from protobufs import Libsodium_pb2 as protobufs_dot_Libsodium__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='protobufs/Objects.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x17protobufs/Objects.proto\x1a\x19protobufs/Libsodium.proto\"\xc7\x01\n\x04User\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x10\n\x08username\x18\x02 \x01(\t\x12\x11\n\tfull_name\x18\x03 \x01(\t\x12\x10\n\x08\x61uth_key\x18\x04 \x01(\x0c\x12\x15\n\rauth_key_hash\x18\x05 \x01(\x0c\x12-\n\x15\x65ncrypted_private_key\x18\x06 \x01(\x0b\x32\x0e.LibsodiumItem\x12\x12\n\npublic_key\x18\x07 \x01(\x0c\x12\x10\n\x08kdf_salt\x18\x08 \x01(\x0c\x12\x10\n\x08is_admin\x18\t \x01(\x08\"\"\n\x06\x46older\x12\n\n\x02id\x18\x01 \x01(\x05\x12\x0c\n\x04name\x18\x02 \x01(\t\"C\n\x0f\x41\x63\x63ountMetadata\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x10\n\x08username\x18\x02 \x01(\t\x12\x10\n\x08\x63omments\x18\x03 \x01(\t\"K\n\x07\x41\x63\x63ount\x12\n\n\x02id\x18\x01 \x01(\x05\x12\"\n\x08metadata\x18\x02 \x01(\x0b\x32\x10.AccountMetadata\x12\x10\n\x08password\x18\x03 \x01(\tB,\n*me.camerongray.teamlocker.client.protobufsb\x06proto3')
  ,
  dependencies=[protobufs_dot_Libsodium__pb2.DESCRIPTOR,])




_USER = _descriptor.Descriptor(
  name='User',
  full_name='User',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='User.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='username', full_name='User.username', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='full_name', full_name='User.full_name', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='auth_key', full_name='User.auth_key', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='auth_key_hash', full_name='User.auth_key_hash', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='encrypted_private_key', full_name='User.encrypted_private_key', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='public_key', full_name='User.public_key', index=6,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='kdf_salt', full_name='User.kdf_salt', index=7,
      number=8, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='is_admin', full_name='User.is_admin', index=8,
      number=9, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=55,
  serialized_end=254,
)


_FOLDER = _descriptor.Descriptor(
  name='Folder',
  full_name='Folder',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='Folder.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='name', full_name='Folder.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=256,
  serialized_end=290,
)


_ACCOUNTMETADATA = _descriptor.Descriptor(
  name='AccountMetadata',
  full_name='AccountMetadata',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='AccountMetadata.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='username', full_name='AccountMetadata.username', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='comments', full_name='AccountMetadata.comments', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=292,
  serialized_end=359,
)


_ACCOUNT = _descriptor.Descriptor(
  name='Account',
  full_name='Account',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='Account.id', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='metadata', full_name='Account.metadata', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='password', full_name='Account.password', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=361,
  serialized_end=436,
)

_USER.fields_by_name['encrypted_private_key'].message_type = protobufs_dot_Libsodium__pb2._LIBSODIUMITEM
_ACCOUNT.fields_by_name['metadata'].message_type = _ACCOUNTMETADATA
DESCRIPTOR.message_types_by_name['User'] = _USER
DESCRIPTOR.message_types_by_name['Folder'] = _FOLDER
DESCRIPTOR.message_types_by_name['AccountMetadata'] = _ACCOUNTMETADATA
DESCRIPTOR.message_types_by_name['Account'] = _ACCOUNT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

User = _reflection.GeneratedProtocolMessageType('User', (_message.Message,), dict(
  DESCRIPTOR = _USER,
  __module__ = 'protobufs.Objects_pb2'
  # @@protoc_insertion_point(class_scope:User)
  ))
_sym_db.RegisterMessage(User)

Folder = _reflection.GeneratedProtocolMessageType('Folder', (_message.Message,), dict(
  DESCRIPTOR = _FOLDER,
  __module__ = 'protobufs.Objects_pb2'
  # @@protoc_insertion_point(class_scope:Folder)
  ))
_sym_db.RegisterMessage(Folder)

AccountMetadata = _reflection.GeneratedProtocolMessageType('AccountMetadata', (_message.Message,), dict(
  DESCRIPTOR = _ACCOUNTMETADATA,
  __module__ = 'protobufs.Objects_pb2'
  # @@protoc_insertion_point(class_scope:AccountMetadata)
  ))
_sym_db.RegisterMessage(AccountMetadata)

Account = _reflection.GeneratedProtocolMessageType('Account', (_message.Message,), dict(
  DESCRIPTOR = _ACCOUNT,
  __module__ = 'protobufs.Objects_pb2'
  # @@protoc_insertion_point(class_scope:Account)
  ))
_sym_db.RegisterMessage(Account)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n*me.camerongray.teamlocker.client.protobufs'))
# @@protoc_insertion_point(module_scope)
