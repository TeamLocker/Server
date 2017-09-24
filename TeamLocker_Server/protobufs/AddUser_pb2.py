# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protobufs/AddUser.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from protobufs import MessageComponents_pb2 as protobufs_dot_MessageComponents__pb2
from protobufs import Objects_pb2 as protobufs_dot_Objects__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='protobufs/AddUser.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x17protobufs/AddUser.proto\x1a!protobufs/MessageComponents.proto\x1a\x17protobufs/Objects.proto\"%\n\x0e\x41\x64\x64UserRequest\x12\x13\n\x04user\x18\x01 \x01(\x0b\x32\x05.User\"H\n\x0f\x41\x64\x64UserResponse\x12 \n\x06result\x18\x01 \x01(\x0b\x32\x10.OperationResult\x12\x13\n\x04user\x18\x02 \x01(\x0b\x32\x05.UserB,\n*me.camerongray.teamlocker.client.protobufsb\x06proto3')
  ,
  dependencies=[protobufs_dot_MessageComponents__pb2.DESCRIPTOR,protobufs_dot_Objects__pb2.DESCRIPTOR,])




_ADDUSERREQUEST = _descriptor.Descriptor(
  name='AddUserRequest',
  full_name='AddUserRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='user', full_name='AddUserRequest.user', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=87,
  serialized_end=124,
)


_ADDUSERRESPONSE = _descriptor.Descriptor(
  name='AddUserResponse',
  full_name='AddUserResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='result', full_name='AddUserResponse.result', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='user', full_name='AddUserResponse.user', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=126,
  serialized_end=198,
)

_ADDUSERREQUEST.fields_by_name['user'].message_type = protobufs_dot_Objects__pb2._USER
_ADDUSERRESPONSE.fields_by_name['result'].message_type = protobufs_dot_MessageComponents__pb2._OPERATIONRESULT
_ADDUSERRESPONSE.fields_by_name['user'].message_type = protobufs_dot_Objects__pb2._USER
DESCRIPTOR.message_types_by_name['AddUserRequest'] = _ADDUSERREQUEST
DESCRIPTOR.message_types_by_name['AddUserResponse'] = _ADDUSERRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

AddUserRequest = _reflection.GeneratedProtocolMessageType('AddUserRequest', (_message.Message,), dict(
  DESCRIPTOR = _ADDUSERREQUEST,
  __module__ = 'protobufs.AddUser_pb2'
  # @@protoc_insertion_point(class_scope:AddUserRequest)
  ))
_sym_db.RegisterMessage(AddUserRequest)

AddUserResponse = _reflection.GeneratedProtocolMessageType('AddUserResponse', (_message.Message,), dict(
  DESCRIPTOR = _ADDUSERRESPONSE,
  __module__ = 'protobufs.AddUser_pb2'
  # @@protoc_insertion_point(class_scope:AddUserResponse)
  ))
_sym_db.RegisterMessage(AddUserResponse)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('\n*me.camerongray.teamlocker.client.protobufs'))
# @@protoc_insertion_point(module_scope)
