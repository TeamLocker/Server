import base64

import models
import config
import crypto
from flask import Flask, abort, request

import validation
from protobufs.AddFolder_pb2 import AddFolderRequest, AddFolderResponse
from protobufs.GetUser_pb2 import GetUserResponse
from protobufs.MessageComponents_pb2 import OperationResult
from protobufs.Libsodium_pb2 import LibsodiumItem
from protobufs.AddUser_pb2 import *

app = Flask(__name__)


@app.before_request
def check_auth():
    if not request.authorization:
        abort(401)

    user = models.User.query.filter(models.User.username == request.authorization.username).first()
    request.authenticated_user = user

    if not user:
        # TODO: Hash something here to prevent timing attacks?
        abort(401)

    packed_auth_key = base64.b64decode(request.authorization.password)
    auth_key = crypto.unpack_libsodium_item(packed_auth_key).data

    if not crypto.verify_auth_key(user.auth_key_hash, auth_key):
        abort(401)


@app.route("/ping", methods=["GET"])
def ping():
    return "pong"


@app.route("/users/<user_id>/", methods=["GET"])
def get_users(user_id):
    if user_id == "self":
        user = request.authenticated_user
    else:
        user = models.User.get(user_id)
        if not user:
            abort(404)  # TODO: Return a protobuf with an error message?

    response = GetUserResponse()
    response.result.success = True
    response.user.id = user.id
    response.user.username = user.username
    response.user.full_name = user.full_name
    response.user.encrypted_private_key.ParseFromString(user.encrypted_private_key)
    response.user.public_key = user.public_key
    response.user.kdf_salt = user.kdf_salt
    response.user.is_admin = user.is_admin

    return response.SerializeToString()


# TODO: Ensure username uniqueness checking works!
@app.route("/users/", methods=["PUT"])
def put_user():
    if not request.authenticated_user.is_admin:
        return validation.get_not_admin_response(AddUserResponse)

    body = AddUserRequest()
    body.ParseFromString(request.data)

    try:
        validation.validate_username(body.user.username)
        validation.validate_nonempty("Full Name", body.user.full_name)
    except validation.ValidationException as ex:
        response = AddUserResponse()
        response.result.success = False
        response.result.message = str(ex)
        return response.SerializeToString(), 400

    user = models.User()
    user.username = body.user.username
    user.full_name = body.user.full_name
    user.is_admin = body.user.is_admin
    user.kdf_salt = body.user.kdf_salt
    user.encrypted_private_key = body.user.encrypted_private_key.SerializeToString()
    user.public_key = body.user.public_key
    user.auth_key_hash = crypto.generate_auth_key_hash(body.user.auth_key)

    models.db_session.add(user)
    models.db_session.commit()

    response = AddUserResponse()
    response.result.success = True
    response.user.id = user.id
    response.user.username = user.username
    response.user.full_name = user.full_name
    response.user.is_admin = user.is_admin
    response.user.kdf_salt = user.kdf_salt
    response.user.encrypted_private_key.data = body.user.encrypted_private_key.data
    response.user.encrypted_private_key.ops_limit = body.user.encrypted_private_key.ops_limit
    response.user.encrypted_private_key.mem_limit = body.user.encrypted_private_key.mem_limit
    response.user.public_key = user.public_key
    response.user.auth_key_hash = user.auth_key_hash

    return response.SerializeToString()


@app.route("/folders/", methods=["PUT"])
def put_folder():
    body = AddFolderRequest()
    body.ParseFromString(request.data)

    try:
        validation.validate_nonempty("Folder Name", body.folder.name)
    except validation.ValidationException as ex:
        response = AddFolderResponse()
        response.result.success = False
        response.result.message = str(ex)
        return response.SerializeToString(), 400

    folder = models.Folder()
    folder.name = body.folder.name

    models.db_session.add(folder)
    models.db_session.commit()

    response = AddFolderResponse()
    response.result.success = True
    response.folder.id = folder.id
    response.folder.name = folder.name

    return response.SerializeToString()


if __name__ == "__main__":
    models.init(config.connection_string)

    app.run(host="127.0.0.1", port=4048, debug=True)
