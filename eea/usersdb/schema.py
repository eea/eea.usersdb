import colander
import phonenumbers

INVALID_PHONE_MESSAGES = (
    ("Invalid telephone number. It must be written "
     "using international notation, starting with \"+\"."),
    ("This does not appear to be a valid phone number given the "
     "country / area code provided. If you second check and believe "
     "the number is correct, please contact HelpDesk.")
)
INVALID_EMAIL = "Invalid email format"

NUMBER_FORMAT = phonenumbers.PhoneNumberFormat.INTERNATIONAL


class PhoneNumber(colander.String):
    """PhoneNumber type for colander Node"""

    def serialize(self, node, appstruct):
        if appstruct is colander.null or not appstruct:
            return colander.null
        return appstruct

    def deserialize(self, node, cstruct):
        try:
            number = phonenumbers.parse(cstruct)
        except Exception:
            return cstruct
        else:
            return phonenumbers.format_number(number, NUMBER_FORMAT)

    def cstruct_children(self):
        return []


def _phone_validator(node, value):
    """Check if provided number is possible number"""
    if not value:
        return
    try:
        number = phonenumbers.parse(value)
    except Exception:
        raise colander.Invalid(node, INVALID_PHONE_MESSAGES[0])
    else:
        if not phonenumbers.is_possible_number(number):
            raise colander.Invalid(node, INVALID_PHONE_MESSAGES[1])

INVALID_URL = "Invalid URL. It must begin with \"http://\" or \"https://\"."


class UserInfoSchema(colander.MappingSchema):
    """
    Schema for Eionet LDAP user information. Can be used by front-end tools
    to verify data before sending it to `eea.usersdb`. The `eea.usersdb`
    library does very little validation of its own.
    """

    first_name = colander.SchemaNode(colander.String())
    last_name = colander.SchemaNode(colander.String())
    full_name_native = colander.SchemaNode(colander.String(), missing='')
    destinationIndicator = colander.SchemaNode(colander.String(), missing='')
    job_title = colander.SchemaNode(colander.String(), missing='')
    email = colander.SchemaNode(colander.String())
    url = colander.SchemaNode(colander.String(), missing='')
    postal_address = colander.SchemaNode(colander.String(), missing='')
    phone = colander.SchemaNode(PhoneNumber(), missing='')
    mobile = colander.SchemaNode(PhoneNumber(), missing='')
    fax = colander.SchemaNode(PhoneNumber(), missing='')
    organisation = colander.SchemaNode(colander.String(), missing='')
    department = colander.SchemaNode(colander.String(), missing='')

_url_validator = colander.Regex(r'^http[s]?\://', msg=INVALID_URL)
UserInfoSchema.phone.validator = _phone_validator
UserInfoSchema.mobile.validator = _phone_validator
UserInfoSchema.fax.validator = _phone_validator
# max length for domain name labels is 63 characters per RFC 1034
UserInfoSchema.email.validator = colander.Regex(
    r"(?:^|\s)[-a-z-A-Z0-9_.']+@(?:[-a-z-A-Z0-9]+\.)+[a-z-A-Z]{2,63}(?:\s|$)",
    msg=INVALID_EMAIL)
UserInfoSchema.url.validator = _url_validator


_description_map = {
    'first_name': "First name",
    'last_name': "Last name",
    'full_name_native': "Full name (native language)",
    'job_title': "Job title",
    'email': "E-mail",
    'url': "URL",
    'postal_address': "Postal address",
    'phone': "Telephone number",
    'mobile': "Mobile telephone number",
    'fax': "Fax number",
    'organisation': "Organisation",
    'department': "Department",
    'destinationIndicator': "Reason to create the account",
}

for name, description in _description_map.iteritems():
    getattr(UserInfoSchema, name).description = description

user_info_schema = UserInfoSchema()

# These can be used in register/create user forms:
INVALID_USERNAME = ("Invalid username. It must contain only digits, lowercase "
                    "letters and/or _ (underscore).")
_uid_node = colander.SchemaNode(colander.String(), name='id',
                                description="User ID")
_uid_node.validator = colander.Regex(r'^[a-z0-9_]+$', msg=INVALID_USERNAME)
_password_node = colander.SchemaNode(colander.String(), name='password',
                                     description="Login password")
