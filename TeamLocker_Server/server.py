import models
import config
from flask import Flask, abort, request

app = Flask(__name__)


@app.before_request
def check_auth():
    username = "test"
    auth_key = ("d556e5819973e8f850507b2fc93c28878dfecbb4dbe064be6535a037c29c933d8bceaff233488e9bcc533e1660dce29878ab08"
                "54cb8b645fb9bd6e4008e85fee")

    if not (request.authorization and request.authorization.username == username and
            request.authorization.password == auth_key):
        abort(401)


@app.route("/ping", methods=["GET"])
def ping():
    return "Foo"

if __name__ == "__main__":
    models.init(config.connection_string)

    # app.run(host="127.0.0.1", port=4048, debug=True)
