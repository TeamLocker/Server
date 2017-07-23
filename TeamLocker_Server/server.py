import base64

import models
import config
import crypto
from flask import Flask, abort, request
from protobufs.GetUser_pb2 import GetUserResponse
from protobufs.MessageComponents_pb2 import OperationResult

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
    response.user.auth_key_hash = user.auth_key_hash
    response.user.encrypted_private_key = user.encrypted_private_key
    response.user.public_key = user.public_key
    response.user.kdf_salt = user.kdf_salt
    response.user.is_admin = user.is_admin

    return response.SerializeToString()


if __name__ == "__main__":
    models.init(config.connection_string)

    app.run(host="127.0.0.1", port=4048, debug=True)
