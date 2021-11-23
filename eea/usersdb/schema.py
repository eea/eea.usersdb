import colander
from string import ascii_lowercase, digits

INVALID_PHONE_MESSAGE = (
    "Invalid telephone number. It must be written "
    "using international notation, starting with \"+\"."
)
INVALID_URL = "Invalid URL. It must begin with \"http://\" or \"https://\"."
_phone_validator = colander.Regex(r'^\+[\d ]+$', msg=INVALID_PHONE_MESSAGE)
_url_validator = colander.Regex(r'^http[s]?\://', msg=INVALID_URL)


class UserInfoSchema(colander.MappingSchema):
    """
    Schema for Eionet LDAP user information. Can be used by front-end tools
    to verify data before sending it to `eea.usersdb`. The `eea.usersdb`
    library does very little validation of its own.
    """

    first_name = colander.SchemaNode(
        colander.String(), description='First name')
    last_name = colander.SchemaNode(
        colander.String(), description='Last name')
    job_title = colander.SchemaNode(
        colander.String(), missing='', description='Job title')
    email = colander.SchemaNode(
        colander.String(), validator=colander.Email(), description='eMail')
    url = colander.SchemaNode(
        colander.String(), missing='', validator=_url_validator,
        description='URL')
    postal_address = colander.SchemaNode(
        colander.String(), missing='', description='Postal address')
    phone = colander.SchemaNode(
        colander.String(), missing='', validator=_phone_validator,
        description='Telephone number')
    mobile = colander.SchemaNode(
        colander.String(), missing='', validator=_phone_validator,
        description='Mobile telephone number')
    fax = colander.SchemaNode(
        colander.String(), missing='', validator=_phone_validator,
        description='Fax number')
    organisation = colander.SchemaNode(
        colander.String(), missing='', description='Organisation')


user_info_schema = UserInfoSchema()

# These can be used in register/create user forms:
INVALID_USERNAME = ("Invalid username. It must contain only digits, lowercase "
                    "letters and/or _ (underscore).")
_uid_node = colander.SchemaNode(colander.String(), name='id',
                                description="User ID")
_uid_node.validator = colander.Regex(r'^[a-z0-9_]+$', msg=INVALID_USERNAME)
_password_node = colander.SchemaNode(colander.String(), name='password',
                                     description="Login password")
