# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: Libsodium.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='Libsodium.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x0fLibsodium.proto\"R\n\rLibsodiumItem\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\x12\r\n\x05nonce\x18\x02 \x01(\x0c\x12\x11\n\tops_limit\x18\x03 \x01(\x03\x12\x11\n\tmem_limit\x18\x04 \x01(\x03\x42,\n*me.camerongray.teamlocker.client.protobufsb\x06proto3')
)




_LIBSODIUMITEM = _descriptor.Descriptor(
  name='LibsodiumItem',
  full_name='LibsodiumItem',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='data', full_name='LibsodiumItem.data', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='LibsodiumItem.nonce', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ops_limit', full_name='LibsodiumItem.ops_limit', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='mem_limit', full_name='LibsodiumItem.mem_limit', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
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
  serialized_start=19,
  serialized_end=101,
)

DESCRIPTOR.message_types_by_name['LibsodiumItem'] = _LIBSODIUMITEM
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

LibsodiumItem = _reflection.GeneratedProtocolMessageType('LibsodiumItem', (_message.Message,), dict(
  DESCRIPTOR = _LIBSODIUMITEM,
  __module__ = 'Libsodium_pb2'
  # @@protoc_insertion_point(class_scope:LibsodiumItem)
  ))
_sym_db.RegisterMessage(LibsodiumItem)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n*me.camerongray.teamlocker.client.protobufs'))
# @@protoc_insertion_point(module_scope)