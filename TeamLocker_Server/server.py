import base64

import models
import config
import crypto
from flask import Flask, abort, request

app = Flask(__name__)


@app.before_request
def check_auth():
    if not request.authorization:
        abort(401)

    user = models.User.query.filter(models.User.username == request.authorization.username).first()

    if not user:
        # TODO: Hash something here to prevent timing attacks?
        abort(401)

    packed_auth_key = base64.b64decode(request.authorization.password)
    auth_key = crypto.unpack_libsodium_item(packed_auth_key).data

    if not crypto.verify_auth_key(user.auth_key_hash, auth_key):
        abort(401)


@app.route("/ping", methods=["GET"])
def ping():
    return "Foo"

if __name__ == "__main__":
    models.init(config.connection_string)

    app.run(host="127.0.0.1", port=4048, debug=True)
