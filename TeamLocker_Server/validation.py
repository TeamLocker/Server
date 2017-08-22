from protobufs.MessageComponents_pb2 import OperationResult


def validate_nonempty(field_name, to_validate):
    if not to_validate.strip():
        raise ValidationException("{} cannot be empty".format(field_name))


# TODO: Improve username validation
def validate_username(to_validate):
    return validate_nonempty("Username", to_validate)


class ValidationException(Exception):
    pass


def get_not_admin_response(ResultProtobuf):
    response = ResultProtobuf()
    response.result.success = False
    response.result.message = "You must be an administrator to perform this action"
    return response.SerializeToString(), 403
