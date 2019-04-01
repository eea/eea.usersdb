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

INVALID_STRING_ENCODING = ('%s must be written in latin characters')


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

    def cstruct_children(self, *args):
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


def _latin_validator(node, value):
    """Check if provided string is written with latin-based characters"""
    if not value:
        return
    for letter in value:
        for index in range(1, 11):
            try:
                letter.encode('latin%s' % index)
            except UnicodeEncodeError:
                pass
            else:
                break
        else:
            raise colander.Invalid(node,
                                   INVALID_STRING_ENCODING % node.description)
            return

INVALID_URL = "Invalid URL. It must begin with \"http://\" or \"https://\"."

# max length for domain name labels is 63 characters per RFC 1034
_url_validator = colander.Regex(r'^http[s]?\://', msg=INVALID_URL)
_email_validator = colander.Regex(
    r"(?:^|\s)[-a-z-A-Z0-9_.']+@(?:[-a-z-A-Z0-9]+\.)+[a-z-A-Z]{2,63}(?:\s|$)",
    msg=INVALID_EMAIL)


class UserInfoSchema(colander.MappingSchema):
    """
    Schema for Eionet LDAP user information. Can be used by front-end tools
    to verify data before sending it to `eea.usersdb`. The `eea.usersdb`
    library does very little validation of its own.
    """

    first_name = colander.SchemaNode(
        colander.String(), validator=_latin_validator,
        description='First name')
    last_name = colander.SchemaNode(
        colander.String(), validator=_latin_validator, description='Last name')
    full_name_native = colander.SchemaNode(
        colander.String(), missing='', validator=_latin_validator,
        description='Full name (native language)')
    search_helper = colander.SchemaNode(
        colander.String(), missing='', description='ASCII search helper')
    reasonToCreate = colander.SchemaNode(
        colander.String(), description='Reason to create the account')
    job_title = colander.SchemaNode(
        colander.String(), missing='', description='Job title')
    email = colander.SchemaNode(
        colander.String(), validator=_email_validator, description='E-mail')
    url = colander.SchemaNode(
        colander.String(), missing='', validator=_url_validator,
        description='URL')
    postal_address = colander.SchemaNode(
        colander.String(), missing='', description='Postal address')
    phone = colander.SchemaNode(
        PhoneNumber(), validator=_phone_validator,
        description='Telephone number')
    mobile = colander.SchemaNode(
        PhoneNumber(), missing='', validator=_phone_validator,
        description='Mobile telephone number')
    fax = colander.SchemaNode(
        PhoneNumber(), missing='', validator=_phone_validator,
        description='Fax number')
    organisation = colander.SchemaNode(
        colander.String(), description='Organisation')
    department = colander.SchemaNode(
        colander.String(), missing='', description='Department')

user_info_schema = UserInfoSchema()

# These can be used in register/create user forms:
INVALID_USERNAME = ("Invalid username. It must contain only digits, lowercase "
                    "letters and/or _ (underscore).")
_uid_node = colander.SchemaNode(colander.String(), name='id',
                                description="User ID")
_uid_node.validator = colander.Regex(r'^[a-z0-9_]+$', msg=INVALID_USERNAME)
_password_node = colander.SchemaNode(colander.String(), name='password',
                                     description="Login password")
