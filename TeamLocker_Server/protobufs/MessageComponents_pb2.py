# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: MessageComponents.proto

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
  name='MessageComponents.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x17MessageComponents.proto\"3\n\x0fOperationResult\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\tB,\n*me.camerongray.teamlocker.client.protobufsb\x06proto3')
)




_OPERATIONRESULT = _descriptor.Descriptor(
  name='OperationResult',
  full_name='OperationResult',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='success', full_name='OperationResult.success', index=0,
      number=1, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='message', full_name='OperationResult.message', index=1,
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
  serialized_start=27,
  serialized_end=78,
)

DESCRIPTOR.message_types_by_name['OperationResult'] = _OPERATIONRESULT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

OperationResult = _reflection.GeneratedProtocolMessageType('OperationResult', (_message.Message,), dict(
  DESCRIPTOR = _OPERATIONRESULT,
  __module__ = 'MessageComponents_pb2'
  # @@protoc_insertion_point(class_scope:OperationResult)
  ))
_sym_db.RegisterMessage(OperationResult)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n*me.camerongray.teamlocker.client.protobufs'))
# @@protoc_insertion_point(module_scope)