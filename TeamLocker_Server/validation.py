def validate_nonempty(field_name, to_validate):
    if not to_validate.strip():
        raise ValidationException("{} cannot be empty".format(field_name))


# TODO: Improve username validation
def validate_username(to_validate):
    return validate_nonempty("Username", to_validate)


class ValidationException(Exception):
    pass