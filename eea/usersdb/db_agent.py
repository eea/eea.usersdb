import logging
from string import ascii_lowercase, digits
from _backport import wraps
import re
import ldap, ldap.filter

log = logging.getLogger(__name__)


# sometimes used as a placeholder for admins/owners - CIRCA stuff I think..
EIONET_ADMIN_UID = 'circle'

LDAP_TIMEOUT = 10

EIONET_USER_SCHEMA = {
    'first_name': 'givenName',
    'last_name': 'sn',
    'full_name': 'cn',
    'job_title': 'title',
    'email': 'mail',
    'phone': 'telephoneNumber',
    'mobile': 'mobile',
    'organisation': 'o',
    'postal_address': 'postalAddress',
    'fax': 'facsimileTelephoneNumber',
    'url': 'labeledURI',
}

EIONET_ORG_SCHEMA = {
    'name': 'o',
    'phone': 'telephoneNumber',
    'fax': 'facsimileTelephoneNumber',
    'url': 'labeledURI',
    'postal_address': 'postalAddress',
    'street': 'street',
    'po_box': 'postOfficeBox',
    'postal_code': 'postalCode',
    'country': 'st',
    'locality': 'l',
}

ACCEPTED_SEARCH_FIELDS = {
    'uid': {
        'label': 'UID',
        'ldap_filter': '(uid=*%s*)',
    },
    'cn': {
        'label': 'Full name',
        'ldap_filter': '(cn=*%s*)',
    },
    'givenName': {
        'label': 'First name',
        'ldap_filter': '(givenName=*%s*)',
    },
    'sn': {
        'label': 'Last name',
        'ldap_filter': '(sn=*%s*)',
    },
    'mail': {
        'label': 'Email address',
        'ldap_filter': '(mail=*%s*)',
    },
}

VALID_PERMITTEDSENDER = lambda x:x in ('owners', 'members', 'anyone') or '@'in x

class InvalidPermittedSender(Exception): pass

class RoleNotFound(Exception): pass

class UserNotFound(Exception): pass

class NameAlreadyExists(Exception): pass

class OrgRenameError(Exception): pass

editable_user_fields = sorted(set(EIONET_USER_SCHEMA) - set(['full_name']))
editable_org_fields = list(EIONET_ORG_SCHEMA) # TODO + ['organisation_links']

def log_ldap_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ldap.LDAPError:
            log.exception("Uncaught exception from LDAP")
            raise
    return wrapper

class UsersDB(object):
    user_schema = EIONET_USER_SCHEMA
    org_schema = EIONET_ORG_SCHEMA

    def __init__(self, **config):
        self.conn = self.connect(config['ldap_server'])
        self._encoding = config.get('encoding', 'utf-8')
        self._user_rdn = config.get('users_rdn', 'uid')
        self._user_dn_suffix = config.get('users_dn',
                                          "ou=Users,o=EIONET,l=Europe")
        self._org_dn_suffix = config.get('orgs_dn',
                                         "ou=Organisations,o=EIONET,l=Europe")
        self._role_dn_suffix = config.get('roles_dn',
                                          "ou=Roles,o=EIONET,l=Europe")
        self._bound = False

    @log_ldap_exceptions
    def connect(self, server):
        conn = ldap.initialize('ldap://' + server)
        conn.protocol_version = ldap.VERSION3
        conn.timeout = LDAP_TIMEOUT
        return conn

    def _role_dn(self, role_id):
        if role_id is None:
            id_bits = []
        else:
            id_bits = role_id.split('-')

        dn_start = ''
        for c in range(len(id_bits), 0, -1):
            dn_start += 'cn=%s,' % '-'.join(id_bits[:c])
        return dn_start + self._role_dn_suffix

    def _role_id(self, role_dn):
        if role_dn == self._role_dn_suffix:
            return None
        assert role_dn.endswith(',' + self._role_dn_suffix)
        role_dn_start = role_dn[ : - (len(self._role_dn_suffix) + 1)]
        dn_bits = role_dn_start.split(',')
        dn_bits.reverse()

        current_bit = None
        for bit in dn_bits:
            assert bit.startswith('cn=')
            bit = bit[len('cn='):]
            if current_bit is None:
                assert '-' not in bit
            else:
                assert bit.startswith(current_bit+'-')
                assert '-' not in bit[len(current_bit)+1:]
            current_bit = bit

        return current_bit

    def _ancestor_roles_dn(self, role_dn):
        """
        Given a subrole dn, returns a list of all ancestors. First is
        the given subrole, then the ancestors, with last element the top-most
        one.

        Example usage::
            >>> self._ancestor_roles_dn("cn=eionet-nfp,cn=eionet,ou=Roles,o=EIONET,l=Europe")
            ['cn=eionet-nfp,ou=Roles,o=EIONET,l=Europe', 'cn=eionet,ou=Roles,o=EIONET,l=Europe']

        """
        assert role_dn.endswith(',' + self._role_dn_suffix), "Invalid Role DN"
        role_dn_start = role_dn[ : - (len(self._role_dn_suffix) + 1)]
        dn_bits = role_dn_start.split(',')
        dn_bits.reverse()

        ancestors = []
        accumulator = self._role_dn_suffix
        current_bit = None
        for bit in dn_bits:
            assert bit.startswith('cn=')
            accumulator = bit + "," + accumulator
            ancestors.insert(0, accumulator)

        return ancestors

    def _user_dn(self, user_id, rdn_value=None):
        """
        When constructing a new user DN in a non-uid RDN scheme (e.g. infoMAP)
        we also need the value to concat to base dn; that is the only case
        when rdn_value is required and used

        """
        assert ',' not in user_id
        if self._user_rdn == 'uid':
            return 'uid=%s,%s' % (user_id, self._user_dn_suffix)
        else:
            # custom RDN branch
            result = self.conn.search_s(self._user_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=("(uid=%s)" % user_id))
            if len(result) > 1:
                raise AssertionError("Duplicate user with uid %s" % user_id)
            elif not result:
                # non-existing user, creating DN
                dn = "%s=%s,%s" % (self._user_rdn, rdn_value,
                                   self._user_dn_suffix)
            else:
                dn, attr = result[0]
            return dn

    def _user_id(self, user_dn, attr={}):
        """
        Get uid from dn.

        @param attr not needed by EIONET schema (where rdn is uid),
        hack for info-rac
        """
        assert user_dn.endswith(',' + self._user_dn_suffix)

        if user_dn.startswith('uid='):
            user_id = user_dn[len('uid=') : - (len(self._user_dn_suffix) + 1)]
        elif 'uid' in attr:
            # e.g. infoMAP LDAP, attr-s already fetched and passed here
            user_id = attr['uid'][-1]
        else:
            # e.g. infoMAP LDAP, we need to fetch uid attribute of user
            result = self.conn.search_s(user_dn, ldap.SCOPE_BASE,
                                        attrlist=('uid',))
            assert len(result) == 1, "Not found dn: %s" % user_dn
            dn, attr = result[0]
            user_id = attr['uid'][-1]

        assert ',' not in user_id
        return user_id

    def _org_dn(self, org_id):
        if org_id is None:
            return self._org_dn_suffix
        else:
            assert ',' not in org_id
            return 'cn=' + org_id + ',' + self._org_dn_suffix

    def _org_id(self, org_dn):
        assert org_dn.endswith(',' + self._org_dn_suffix)
        assert org_dn.startswith('cn=')
        org_id = org_dn[len('cn=') : - (len(self._org_dn_suffix) + 1)]
        assert ',' not in org_id
        return org_id

    def _unpack_user_info(self, dn, attr):
        out = {'dn': dn, 'id': self._user_id(dn, attr)}
        for name, ldap_name in self.user_schema.iteritems():
            if ldap_name in attr:
                # some have more, e.g. multiple orgs in "o" property, use join
                out[name] = ', '.join(attr[ldap_name]).decode(self._encoding)
            else:
                out[name] = u""

        return out

    def _unpack_org_info(self, dn, attr):
        out = {'dn': dn, 'id': self._org_id(dn)}
        for name, ldap_name in self.org_schema.iteritems():
            if ldap_name in attr:
                out[name] = attr[ldap_name][0].decode(self._encoding)
            else:
                out[name] = u""
        return out

    @log_ldap_exceptions
    def role_names_in_role(self, role_id):
        """
        Returns a mapping of `sub_role_id` to `description` for subroles
        of `role_id`.
        """

        query_dn = self._role_dn(role_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_ONELEVEL,
                        filterstr='(objectClass=groupOfUniqueNames)',
                        attrlist=('description',))

        out = {}
        for dn, attr in result:
            values = attr.get('description', [''])
            out[self._role_id(dn)] = values[0].decode(self._encoding)
        return out

    @log_ldap_exceptions
    def filter_roles(self, pattern, prefix_dn=None,
                     filterstr='(objectClass=groupOfUniqueNames)', attrlist=()):
        """
        Returns all roles matching `pattern`.
        We can use `prefix_dn` to restrict searching pool and/or filterstr
        Returns list of tuples, with role_id and attrs in `attrlist`

        """
        query_dn = self._role_dn_suffix
        if prefix_dn:
            query_dn = prefix_dn + ',' + query_dn
        result = self.conn.search_s(query_dn, ldap.SCOPE_SUBTREE,
                        filterstr=filterstr, attrlist=attrlist)

        pattern = pattern.lower()
        for ch in pattern:
            if ch not in ascii_lowercase + '-*':
                return set()

        if not pattern:
            return set()

        pattern = pattern.replace('-', r'\b\-\b').replace('*', r'.*')
        pattern = r'\b' + pattern + r'\b'
        compiled_pattern = re.compile(pattern)

        out = []
        in_out = set()
        for dn, attr in result:
            role_id = self._role_id(dn)
            if role_id is None:
                continue

            if compiled_pattern.search(role_id.lower()) is not None:
                if role_id not in in_out:
                    out.append((role_id, attr))
                    in_out.add(role_id)

        return out

    def _query(self, dn):
        return self.conn.search_s(dn, ldap.SCOPE_BASE)[0][1]

    @log_ldap_exceptions
    def members_in_role_and_subroles(self, role_id):
        """
        Returns a dictionary with 'user' and 'org' as keys, and lists of
        `user_id` or `org_id` as values - direct AND descending members
        of role `role_id`.

        """

        query_dn = self._role_dn(role_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                        filterstr='(objectClass=groupOfUniqueNames)',
                        attrlist=('uniqueMember',))

        out = {'users': [], 'orgs': []}
        for dn, attr in result:
            for member_dn in attr.get('uniqueMember', []):
                if not member_dn:
                    # ignore blank member DNs
                    continue
                if member_dn.endswith(self._org_dn_suffix):
                    out['orgs'].append(self._org_id(member_dn))
                elif member_dn.endswith(self._user_dn_suffix):
                    out['users'].append(self._user_id(member_dn))
                # else ignore the record

        return out

    @log_ldap_exceptions
    def members_in_role(self, role_id):
        """
        Returns a dictionary with 'user' and 'org' as keys, and lists of
        `user_id` or `org_id` as values - direct members of role `role_id`.
        """

        query_dn = self._role_dn(role_id)

        def member_tuples_from_result(result):
            out = set()
            for dn, attr in result:
                for member_dn in attr.get('uniqueMember', []):
                    if not member_dn:
                        # ignore blank member DNs
                        continue
                    if member_dn.endswith(self._org_dn_suffix):
                        out.add( ('orgs', self._org_id(member_dn)) )
                    elif member_dn.endswith(self._user_dn_suffix):
                        out.add( ('users', self._user_id(member_dn)) )
                    # else ignore the record
            return out

        # first, get all user ids in this role
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                        filterstr='(objectClass=groupOfUniqueNames)',
                        attrlist=('uniqueMember',))
        all_members = member_tuples_from_result(result)

        # then get all user ids in sub-roles
        result = self.conn.search_s(query_dn, ldap.SCOPE_ONELEVEL,
                        filterstr='(objectClass=groupOfUniqueNames)',
                        attrlist=('uniqueMember',))
        members_in_sub_roles = member_tuples_from_result(result)

        # and return only users that are *not* in sub-roles
        out = {'users': [], 'orgs': []}
        for member_type, member_id in (all_members - members_in_sub_roles):
            out[member_type].append(member_id)
        return out

    @log_ldap_exceptions
    def user_info(self, user_id):
        """ Returns a dictionary of user information for user `user_id`.  """
        query_dn = self._user_dn(user_id)
        try:
            result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                        filterstr='(objectClass=organizationalPerson)')
        except ldap.NO_SUCH_OBJECT:
            raise UserNotFound("User '%s' does not exist" % user_id)

        assert len(result) == 1
        dn, attr = result[0]
        assert dn == query_dn

        user_info = self._unpack_user_info(dn, attr)
        #user_info['organisation_links'] = self._search_user_in_orgs(user_id)

        return user_info

    @log_ldap_exceptions
    def org_info(self, org_id):
        """
        Returns a dictionary of organisation information for `org_id`.
        """

        query_dn = self._org_dn(org_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE)

        assert len(result) == 1
        dn, attr = result[0]
        assert dn == query_dn
        return self._unpack_org_info(dn, attr)

    @log_ldap_exceptions
    def role_info(self, role_id):
        """
        Returns a dictionary describing the role `role_id`.
        """

        query_dn = self._role_dn(role_id)
        try:
            result = self.conn.search_s(query_dn, ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT:
            raise RoleNotFound("Role %r does not exist" % role_id)

        assert len(result) == 1
        dn, attr = result[0]
        assert dn.lower() == query_dn.lower().strip()
        description = attr.get('description', [""])[0].decode(self._encoding)
        return {'description': description,
                'owner': attr.get('owner', []),
                'permittedSender': attr.get('permittedSender', []),
                'permittedPerson': attr.get('permittedPerson', [])}

    @log_ldap_exceptions
    def perform_bind(self, bind_dn, bind_pw):
        try:
            result = self.conn.simple_bind_s(bind_dn, bind_pw)
        except (ldap.INVALID_CREDENTIALS,
                ldap.UNWILLING_TO_PERFORM):
            raise ValueError("Authentication failure")
        assert result[:2] == (ldap.RES_BIND, [])
        self._bound = True

    @log_ldap_exceptions
    def bind_user(self, user_id, user_pw):
        return self.perform_bind(self._user_dn(user_id), user_pw)

    @log_ldap_exceptions
    def existing_usernames(self, usernames):
        """
        Given a list of usernames, returns a generator that iterates
        the usernames already registered.

        """
        query = "(|" + ''.join(["(uid=%s)" % x for x in usernames]) + ")"
        result = self.conn.search_s(self._user_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query, attrlist=())
        for dn, attr in result:
            yield self._user_id(dn, attr)

    @log_ldap_exceptions
    def existing_emails(self, emails):
        """
        Given a list of emails, returns a generator that iterates
        the emails already registered.

        """
        query = "(|" + ''.join(["(mail=%s)" % x for x in emails]) + ")"
        result = self.conn.search_s(self._user_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query, attrlist=('mail',))
        for dn, attr in result:
            yield attr['mail'][0]

    @log_ldap_exceptions
    def create_user(self, new_user_id, user_info):
        """ Create a new user with attributes from `user_info` """
        assert self._bound, "call `perform_bind` before `create_user`"
        log.info("Creating user %r", new_user_id)
        assert type(new_user_id) is str
        for ch in new_user_id:
            assert ch in ascii_lowercase + digits + '_'
        self._update_full_name(user_info)

        attrs = [
            ('objectClass', ['top', 'person', 'organizationalPerson',
                             'inetOrgPerson']),
            ('uid', [new_user_id]),
        ]
        attr_dict = {'uid': new_user_id}

        for name, value in sorted(user_info.iteritems()):
            if value == "":
                continue
            attrs.append( (self.user_schema[name], [value.encode('utf-8')]) )
            # for custom RDN branch
            attr_dict[attrs[-1][0]] = attrs[-1][1][0]

        try:
            if self._user_rdn == 'uid':
                result = self.conn.add_s(self._user_dn(new_user_id), attrs)
            else: # custom RDN branch
                result = self.conn.add_s(self._user_dn(new_user_id,
                               rdn_value=attr_dict[self._user_rdn]), attrs)

        except ldap.ALREADY_EXISTS:
            raise NameAlreadyExists("User %r already exists" % new_user_id)
        assert result == (ldap.RES_ADD, [])

    @log_ldap_exceptions
    def set_user_password(self, user_id, old_pw, new_pw):
        user_info = self.user_info(user_id) # checks that user exists
        log.info("Changing password for user %r", user_id)
        try:
            result = self.conn.passwd_s(self._user_dn(user_id), old_pw, new_pw)
        except ldap.UNWILLING_TO_PERFORM:
            raise ValueError("Authentication failure")
        # ugly hack for backwards compat
        assert result[:2] in ((ldap.RES_EXTENDED, []), (None, None))

    def _update_full_name(self, user_info):
        full_name = '%s %s' % (user_info.get('first_name', u""),
                               user_info.get('last_name', u""))
        user_info['full_name'] = full_name.strip()

    def _user_info_diff(self, user_id, old_info, new_info, existing_orgs):
        def pack(value):
            return [value.encode(self._encoding)]

        # normalize user_info dictionaries
        old_info = dict(old_info)
        new_info = dict(new_info)
        self._update_full_name(new_info)

        # compute delta
        modify_statements = []
        def do(*args):
            modify_statements.append(args)

        for name in editable_user_fields + ['full_name']:
            old_value = old_info.get(name, u"")
            new_value = new_info.get(name, u"")
            ldap_name = self.user_schema[name]

            if old_value == new_value == '':
                pass

            elif old_value == '':
                do(ldap.MOD_ADD, ldap_name, pack(new_value))

            elif new_value == '':
                do(ldap.MOD_DELETE, ldap_name, [])

            elif old_value != new_value:
                do(ldap.MOD_REPLACE, ldap_name, pack(new_value))

#        add_to_orgs = set(new_org_ids) - set(existing_orgs)
#        remove_from_orgs = set(existing_orgs) - set(new_org_ids)

        # compose output for ldap calls
        out = {}
        user_dn = self._user_dn(user_id)
        if modify_statements:
            out[user_dn] = modify_statements

# adding/removing oneself from organizations is disabled until CIRCA is
# phased out
#        for org_id in add_to_orgs:
#            out[self._org_dn(org_id)] = [
#                (ldap.MOD_ADD, 'uniqueMember', [user_dn]),
#            ]
#        for org_id in remove_from_orgs:
#            out[self._org_dn(org_id)] = [
#                (ldap.MOD_DELETE, 'uniqueMember', [user_dn]),
#            ]

        return out

    @log_ldap_exceptions
    def set_user_info(self, user_id, new_info):
        old_info = self.user_info(user_id)
        existing_orgs = self._search_user_in_orgs(user_id)
        diff = self._user_info_diff(user_id, old_info, new_info, existing_orgs)
        if not diff:
            return

        log.info("Modifying info for user %r", user_id)
        for dn, modify_statements in diff.iteritems():
            result = self.conn.modify_s(dn, tuple(modify_statements))
            assert result == (ldap.RES_MODIFY, [])

    def _org_info_diff(self, org_id, old_info, new_info):
        def pack(value):
            return [value.encode(self._encoding)]

        for name in self.org_schema:
            old_value = old_info.get(name, u"")
            new_value = new_info.get(name, u"")
            ldap_name = self.org_schema[name]

            if old_value == new_value == '':
                pass

            elif old_value == '':
                yield (ldap.MOD_ADD, ldap_name, pack(new_value))

            elif new_value == '':
                yield (ldap.MOD_DELETE, ldap_name, [])

            elif old_value != new_value:
                yield (ldap.MOD_REPLACE, ldap_name, pack(new_value))

    @log_ldap_exceptions
    def user_organisations(self, user_id):
        """ return organisations the user belongs to """
        filter_tmpl = '(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))'
        user_dn = self._user_dn(user_id)
        filterstr = ldap.filter.filter_format(filter_tmpl, (user_dn,))
        result = self.conn.search_s(self._org_dn(None), ldap.SCOPE_SUBTREE,
                                    filterstr=filterstr, attrlist=())
        for dn, attr in result:
            yield dn

    def roles_permittedPerson(self, user_id):
        """ return roles where user is added as permittedPerson """
        filter_tmpl = '(&(objectClass=mailListGroup)(permittedPerson=%s))'
        user_dn = self._user_dn(user_id)
        filterstr = ldap.filter.filter_format(filter_tmpl, (user_dn,))
        result = self.conn.search_s(self._role_dn(None), ldap.SCOPE_SUBTREE,
                                    filterstr=filterstr, attrlist=())
        for dn, attr in result:
            yield dn

    def roles_owner(self, user_id):
        """ return roles where user is owner """
        filter_tmpl = '(&(objectClass=groupOfUniqueNames)(owner=%s))'
        user_dn = self._user_dn(user_id)
        filterstr = ldap.filter.filter_format(filter_tmpl, (user_dn,))
        result = self.conn.search_s(self._role_dn(None), ldap.SCOPE_SUBTREE,
                                    filterstr=filterstr, attrlist=())
        for dn, attr in result:
            yield dn

    @log_ldap_exceptions
    def delete_user(self, user_id):
        """
        Remove user from LDAP, altogether with references:
         - roles, organisations, owner/permittedPerson in roles

        """
        assert self._bound, "call `perform_bind` before `delete_user`"
        organisations = self.user_organisations(user_id)
        for org in organisations:
            self.remove_from_org(self._org_id(org), [user_id])
        roles = self.list_member_roles("user", user_id)
        for role in roles:
            self.remove_from_role(role, "user", user_id)
        roles_p = self.roles_permittedPerson(user_id)
        for role in roles_p:
            self.remove_permittedPerson(self._role_id(role), user_id)
        roles_owner = self.roles_owner(user_id)
        for role in roles_owner:
            self.remove_role_owner(self._role_id(role), user_id)

        log.info("Deleting user %r", user_id)
        result = self.conn.delete_s(self._user_dn(user_id))
        assert result[:2] == (ldap.RES_DELETE, [])

    @log_ldap_exceptions
    def create_org(self, org_id, org_info):
        """ Create a new organisation with attributes from `org_info` """
        assert self._bound, "call `perform_bind` before `create_org`"
        log.info("Creating organisation %r", org_id)
        assert type(org_id) is str
        for ch in org_id:
            assert ch in ascii_lowercase + '_'

        attrs = [
            ('cn', [org_id]),
            ('objectClass', ['top', 'groupOfUniqueNames',
                             'organizationGroup', 'labeledURIObject']),
            ('uniqueMember', ['']),
        ]

        for name, value in sorted(org_info.iteritems()):
            if value == "":
                continue
            attrs.append( (self.org_schema[name], [value.encode('utf-8')]) )

        result = self.conn.add_s(self._org_dn(org_id), attrs)
        assert result == (ldap.RES_ADD, [])

    @log_ldap_exceptions
    def set_org_info(self, org_id, new_info):
        assert self._bound, "call `perform_bind` before `set_org_info`"
        log.info("Changing organisation information for %r to %r",
                 org_id, new_info)
        old_info = self.org_info(org_id)
        changes = tuple(self._org_info_diff(org_id, old_info, new_info))
        if not changes:
            return
        org_dn = self._org_dn(org_id)
        result = self.conn.modify_s(org_dn, changes)
        assert result == (ldap.RES_MODIFY, [])

    @log_ldap_exceptions
    def members_in_org(self, org_id):
        query_dn = self._org_dn(org_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                                    attrlist=('uniqueMember',))
        assert len(result) == 1
        dn, attr = result[0]
        return [self._user_id(dn) for dn in attr['uniqueMember'] if dn != '']

    @log_ldap_exceptions
    def add_to_org(self, org_id, user_id_list):
        assert self._bound, "call `perform_bind` before `add_to_org`"
        log.info("Adding users %r to organisation %r", user_id_list, org_id)

        user_dn_list = [self._user_dn(user_id) for user_id in user_id_list]
        changes = ( (ldap.MOD_ADD, 'uniqueMember', user_dn_list), )

        if not self.members_in_org(org_id):
            # we are removing all members; add placeholder value
            changes += ((ldap.MOD_DELETE, 'uniqueMember', ['']),)

        result = self.conn.modify_s(self._org_dn(org_id), changes)
        assert result == (ldap.RES_MODIFY, [])

    @log_ldap_exceptions
    def remove_from_org(self, org_id, user_id_list):
        assert self._bound, "call `perform_bind` before `remove_from_org`"
        log.info("Removing users %r from organisation %r",
                 user_id_list, org_id)

        user_dn_list = [self._user_dn(user_id) for user_id in user_id_list]
        changes = ( (ldap.MOD_DELETE, 'uniqueMember', user_dn_list), )

        if not (set(self.members_in_org(org_id)) - set(user_id_list)):
            # we are removing all members; add placeholder value
            changes = ((ldap.MOD_ADD, 'uniqueMember', ['']),) + changes

        result = self.conn.modify_s(self._org_dn(org_id), changes)
        assert result == (ldap.RES_MODIFY, [])

    @log_ldap_exceptions
    def rename_org(self, org_id, new_org_id):
        assert self._bound, "call `perform_bind` before `rename_org`"
        log.info("Renaming organisation %r to %r", org_id, new_org_id)

        org_dn = self._org_dn(org_id)
        new_org_dn = self._org_dn(new_org_id)

        try:
            result = self.conn.rename_s(org_dn, new_org_dn.split(',')[0])
        except ldap.ALREADY_EXISTS:
            raise NameAlreadyExists("Organisation %r already exists" %
                                    new_org_id)
        assert result[:2] == (ldap.RES_MODRDN, [])

        try:
            fil = ldap.filter.filter_format('(uniqueMember=%s)',(org_dn,))
            result = self.conn.search_s(self._role_dn_suffix,
                                        ldap.SCOPE_SUBTREE,
                                            filterstr=fil, attrlist=())
            for role_dn, attr in result:
                mod_result = self.conn.modify_s(role_dn, (
                    (ldap.MOD_DELETE, 'uniqueMember', [org_dn]),
                    (ldap.MOD_ADD, 'uniqueMember', [new_org_dn]),
                ))
                assert mod_result == (ldap.RES_MODIFY, [])
        except:
            msg = ("Error while updating references to organisation "
                   "from %r to %r" % (org_dn, new_org_dn))
            log.exception(msg)
            raise OrgRenameError(msg)

    @log_ldap_exceptions
    def delete_org(self, org_id):
        """ Delete the organisation `org_id` """
        assert self._bound, "call `perform_bind` before `delete_org`"
        log.info("Deleting organisation %r", org_id)
        result = self.conn.delete_s(self._org_dn(org_id))
        assert result[:2] == (ldap.RES_DELETE, [])

    @log_ldap_exceptions
    def create_role(self, role_id, description):
        """
        Create the specified role.
        """

        assert self._bound, "call `perform_bind` before `create_role`"
        log.info("Creating role %r", role_id)
        owner_dn = self._user_dn(EIONET_ADMIN_UID)

        attrs = [
            ('cn', [role_id]),
            ('objectClass', ['top', 'groupOfUniqueNames', 'mailListGroup']),
            ('ou', [role_id.split('-')[-1]]),
            ('uniqueMember', ['']),
            ('owner', [owner_dn]),
            ('permittedSender', ['owners'])
        ]
        if description:
            attrs.append(('description', [description.encode(self._encoding)]))

        role_dn = self._role_dn(role_id)

        try:
            result = self.conn.add_s(role_dn, attrs)
        except ldap.NO_SUCH_OBJECT:
            raise ValueError("Parent DN missing (trying to create %r)"
                             % role_dn)
        except ldap.ALREADY_EXISTS:
            raise ValueError("DN already exists (trying to create %r)"
                             % role_dn)

        assert result == (ldap.RES_ADD, [])

    @log_ldap_exceptions
    def set_role_description(self, role_id, description):
        """
        Sets role description (or name) to `description`
        `description` must be unicode or ascii bytes

        """
        assert self._bound, "call `perform_bind` before `set_role_description`"
        log.info("Set description %r for role %r", description, role_id)
        role_dn = self._role_dn(role_id)
        description_bytes = description.encode(self._encoding)
        try:
            result = self.conn.modify_s(role_dn, (
                (ldap.MOD_REPLACE, 'description', [description_bytes]),
            ))
        except ldap.NO_SUCH_ATTRIBUTE:
            result = self.conn.modify_s(role_dn, (
                (ldap.MOD_ADD, 'description', [description_bytes]),
            ))

    def _sub_roles(self, role_id):
        role_dn = self._role_dn(role_id)
        result = self.conn.search_s(role_dn, ldap.SCOPE_SUBTREE,
                        filterstr='(objectClass=groupOfUniqueNames)',
                        attrlist=())

        sub_roles = []
        for dn, attr in result:
            sub_roles.append(dn)
        sub_roles.sort()
        sub_roles.reverse()

        return sub_roles

    def is_subrole(self, subrole_id, role_id):
        return subrole_id.startswith(role_id)

    @log_ldap_exceptions
    def delete_role(self, role_id):
        assert self._bound, "call `perform_bind` before `delete_role`"
        for dn in self._sub_roles(role_id):
            log.info("Deleting role %r", role_id)
            result = self.conn.delete_s(dn)
            assert result[:2] == (ldap.RES_DELETE, [])

    def raw_ldap_search(self, *args, **kwargs):
        return self.conn.search_s(*args, **kwargs)

    @log_ldap_exceptions
    def search_user_by_email(self, email):
        query = email.encode(self._encoding)
        pattern = '(&(objectClass=person)(mail=%s))'
        query_filter = ldap.filter.filter_format(pattern, (query,))

        result = self.conn.search_s(self._user_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query_filter)

        return [self._unpack_user_info(dn, attr) for (dn, attr) in result]

    @log_ldap_exceptions
    def search_user(self, name, lookup=['all']):
        query = name.lower().encode(self._encoding)
        lookup_filters = []
        query_arguments = []

        if lookup and 'all' not in lookup:
            for field in lookup:
                if field in ACCEPTED_SEARCH_FIELDS.keys():
                    lookup_filters.append(ACCEPTED_SEARCH_FIELDS[field]['ldap_filter'])
                    query_arguments.append(query)
        else:
            for field in ACCEPTED_SEARCH_FIELDS:
                lookup_filters.append(ACCEPTED_SEARCH_FIELDS[field]['ldap_filter'])
                query_arguments.append(query)

        pattern = '(&(objectClass=person)(|%s))' % ''.join(lookup_filters)
        query_filter = ldap.filter.filter_format(pattern, tuple(query_arguments))
        result = self.conn.search_s(self._user_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query_filter)

        return [self._unpack_user_info(dn, attr) for (dn, attr) in result]

    @log_ldap_exceptions
    def search_org(self, name):
        query = name.lower().encode(self._encoding)
        pattern = '(&(objectClass=organizationGroup)(|(cn=*%s*)(o=*%s*)))'
        query_filter = ldap.filter.filter_format(pattern, (query, query))

        result = self.conn.search_s(self._org_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query_filter)

        return [self._unpack_org_info(dn, attr) for (dn, attr) in result]

    def _member_dn(self, member_type, member_id):
        if member_type == 'user':
            return self._user_dn(member_id)
        elif member_type == 'org':
            return self._org_dn(member_id)
        else:
            raise ValueError('unknown member type %r' % member_type)

    def _add_member_dn_to_single_role_dn(self, role_dn, member_dn):
        log.info("Adding uniqueMember %r to %r", member_dn, role_dn)

        result = self.conn.modify_s(role_dn, (
            (ldap.MOD_ADD, 'uniqueMember', [member_dn]),
        ))

        try:
            result = self.conn.modify_s(role_dn, (
                (ldap.MOD_DELETE, 'uniqueMember', ['']),
            ))
        except ldap.NO_SUCH_ATTRIBUTE:
            pass # so the group was not empty. that's fine.
        else:
            assert result == (ldap.RES_MODIFY, [])
            log.info("Removed placeholder uniqueMember from %r", role_dn)

    def _add_member_dn_to_role_dn(self, role_dn, member_dn):
        result = self.conn.search_s(member_dn, ldap.SCOPE_BASE, attrlist=())
        if len(result) < 1:
            raise ValueError("DN not found: %r" % member_dn)

        result = self.conn.search_s(role_dn, ldap.SCOPE_BASE, attrlist=())
        if len(result) < 1:
            raise ValueError("DN not found: %r" % role_dn)

        roles = []
        while role_dn.endswith(',' + self._role_dn_suffix):
            try:
                self._add_member_dn_to_single_role_dn(role_dn, member_dn)
            except ldap.TYPE_OR_VALUE_EXISTS:
                # the user is already a member here; we can stop.
                break
            roles.append(role_dn)
            role_dn = role_dn.split(',', 1)[1] # go up a level

        roles.reverse()
        return roles

    @log_ldap_exceptions
    def add_to_role(self, role_id, member_type, member_id):
        assert self._bound, "call `perform_bind` before `add_to_role`"
        log.info("Adding %r member %r to role %r",
                 member_type, member_id, role_id)
        member_dn = self._member_dn(member_type, member_id)
        role_dn = self._role_dn(role_id)

        role_dn_list = self._add_member_dn_to_role_dn(role_dn, member_dn)
        return map(self._role_id, role_dn_list)

    def mail_group_info(self, role_id):
        """ Returns:
        * list of user_id-s that are owners of given role_id, placeholder
          excluded
        * list of user_id-s that are permittedPerson, if any
        * permittedPerson-s, if any
        Output: {'owner': [..], 'permittedPerson': [..],
                 'permittedSender': [..]}

        """
        role_info = self.role_info(role_id)
        owner = map(self._user_id, role_info['owner'])
        if EIONET_ADMIN_UID in owner:
            owner.remove(EIONET_ADMIN_UID)
        return {'owner': owner, 'permittedSender': role_info['permittedSender'],
            'permittedPerson': map(self._user_id, role_info['permittedPerson'])}

    @log_ldap_exceptions
    def add_role_owner(self, role_id, user_id):
        """ Adds user_id as owner for role_id """
        user_info = self.user_info(user_id)
        role_info = self.role_info(role_id)
        user_dn = self._user_dn(user_id)
        role_dn = self._role_dn(role_id)
        log.info("Adding owner %r to %r", user_dn, role_dn)

        result = self.conn.modify_s(role_dn, (
            (ldap.MOD_ADD, 'owner', [user_dn]),
        ))
        try:
            result = self.conn.modify_s(role_dn, (
                (ldap.MOD_DELETE, 'owner', [self._user_dn(EIONET_ADMIN_UID)]),
            ))
        except ldap.NO_SUCH_ATTRIBUTE:
            pass # so the group didn't have circle placeholder. that's fine.
        else:
            assert result == (ldap.RES_MODIFY, [])
            log.info("Removed owner placeholder from %r", role_dn)

    @log_ldap_exceptions
    def remove_role_owner(self, role_id, user_id):
        """
        Removes user_id as owner for role_id.
        * does not check user_id for existence (useful for garbage cleanup)
        * adds circle user_dn as a placeholder if no other owners

        """
        role_info = self.role_info(role_id)
        user_dn = self._user_dn(user_id)
        role_dn = self._role_dn(role_id)
        log.info("Removing owner %r from %r", user_dn, role_dn)

        def _remove():
            self.conn.modify_s(role_dn, (
                (ldap.MOD_DELETE, 'owner', [user_dn]),
            ))

        def _add_placeholder():
            self.conn.modify_s(role_dn, (
                (ldap.MOD_ADD, 'owner', [self._user_dn(EIONET_ADMIN_UID)]),
            ))

        try:
            _remove()
        except ldap.OBJECT_CLASS_VIOLATION:
            log.info("Adding 'circle' DN placeholder as owner for %r", role_dn)
            _add_placeholder()
            _remove()

    @log_ldap_exceptions
    def add_permittedPerson(self, role_id, user_id):
        """ Adds `user_id` as permittedPerson for `role_id` """
        user_info = self.user_info(user_id)
        role_info = self.role_info(role_id)
        user_dn = self._user_dn(user_id)
        role_dn = self._role_dn(role_id)
        log.info("Adding permittedPerson %r for %r", user_dn, role_dn)

        result = self.conn.modify_s(role_dn, (
            (ldap.MOD_ADD, 'permittedPerson', [user_dn]),
        ))

    @log_ldap_exceptions
    def add_permittedSender(self, role_id, sender):
        """ Adds `sender` token to permittedSender for `role_id` """
        if not VALID_PERMITTEDSENDER(sender):
            raise InvalidPermittedSender("Invalid value for sender: %r"% sender)
        role_info = self.role_info(role_id)
        # TODO: validate `sender` token
        role_dn = self._role_dn(role_id)
        log.info("Adding permittedSender %r for %r", sender, role_dn)

        result = self.conn.modify_s(role_dn, (
            (ldap.MOD_ADD, 'permittedSender', [sender]),
        ))

    @log_ldap_exceptions
    def remove_permittedPerson(self, role_id, user_id):
        """ Removes `user_id` from permittedPerson list in `role_id` """
        role_info = self.role_info(role_id)
        user_dn = self._user_dn(user_id)
        role_dn = self._role_dn(role_id)
        log.info("Removing permittedPerson %r for %r", user_dn, role_dn)

        result = self.conn.modify_s(role_dn, (
            (ldap.MOD_DELETE, 'permittedPerson', [user_dn]),
        ))

    @log_ldap_exceptions
    def remove_permittedSender(self, role_id, sender):
        """ Remove `sender` token from permittedSender in `role_id` """
        role_info = self.role_info(role_id)
        role_dn = self._role_dn(role_id)
        log.info("Removing permittedSender %r for %r", sender, role_dn)

        result = self.conn.modify_s(role_dn, (
            (ldap.MOD_DELETE, 'permittedSender', [sender]),
        ))

    def _sub_roles_with_member(self, role_dn, member_dn):
        """
        Includes role_dn in result, searches all subroles recursively
        (scope: subtree)
        Example usage::
            >>> x = ag._sub_roles_with_member(ag._role_dn('a-b'), ag._user_dn('user_in_c'))
            >>> list(x)
            ['cn=a-b,cn=a,ou=Roles,o=EIONET,l=Europe',
             'cn=a-b-c,cn=a-b,cn=a,ou=Roles,o=EIONET,l=Europe']

        """
        filter_tmpl = '(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))'
        filterstr = ldap.filter.filter_format(filter_tmpl, (member_dn,))
        result = self.conn.search_s(role_dn, ldap.SCOPE_SUBTREE,
                                    filterstr=filterstr, attrlist=())
        for dn, attr in result:
            yield dn

    def _imediate_sub_roles_with_member(self, role_dn, member_dn):
        """
        Does not include role_dn in result, searches imediate
        (directly connected) subroles (scope: onelevel)
        Example usage::
            >>> x = ag._imediate_sub_roles_with_member(ag._role_dn('a-b'), ag._user_dn('user_in_d'))
            >>> list(x)
            ['cn=a-b-c,cn=a-b,cn=a,ou=Roles,o=EIONET,l=Europe']

        """
        filter_tmpl = '(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))'
        filterstr = ldap.filter.filter_format(filter_tmpl, (member_dn,))
        result = self.conn.search_s(role_dn, ldap.SCOPE_ONELEVEL,
                                    filterstr=filterstr, attrlist=())
        for dn, attr in result:
            yield dn

    def _remove_member_dn_from_single_role_dn(self, role_dn, member_dn):
        """ remove a single member from a single role """
        log.info("Removing uniqueMember %r from %r", member_dn, role_dn)

        def _remove():
            self.conn.modify_s(role_dn, (
                (ldap.MOD_DELETE, 'uniqueMember', [member_dn]),
            ))

        def _add_placeholder():
            self.conn.modify_s(role_dn, (
                (ldap.MOD_ADD, 'uniqueMember', ['']),
            ))

        try:
            _remove()
        except ldap.OBJECT_CLASS_VIOLATION:
            log.info("Adding placeholder uniqueMember for %r", role_dn)
            _add_placeholder()
            _remove()

    def _remove_member_dn_from_role_dn(self, role_dn, member_dn):
        """
        We need to remove user from:
        * role_dn
        * all sub-roles of role_dn
        * all ancestor roles of role_dn that do not have onelevel sub-roles
          with the user as member

        """
        result = self.conn.search_s(member_dn, ldap.SCOPE_BASE, attrlist=())
        if len(result) < 1:
            raise ValueError("DN not found: %r" % member_dn)

        result = self.conn.search_s(role_dn, ldap.SCOPE_BASE, attrlist=())
        if len(result) < 1:
            raise ValueError("DN not found: %r" % role_dn)

        roles = list(self._sub_roles_with_member(role_dn, member_dn))
        if not roles:
            raise ValueError("DN %r is not a member of %r" %
                             (member_dn, role_dn))
        roles.sort()
        roles.reverse()
        # remove from role_dn and sub-roles
        for sub_role_dn in roles:
            self._remove_member_dn_from_single_role_dn(sub_role_dn, member_dn)

        # remove from "orphan" ancestors (actually ancestors without kids)
        ancestors = list(self._ancestor_roles_dn(role_dn))[1:]
        anc_roles = []
        for rdn in ancestors:
            sublevel = self._imediate_sub_roles_with_member(rdn, member_dn)
            if not list(sublevel):
                self._remove_member_dn_from_single_role_dn(rdn, member_dn)
                anc_roles.append(rdn)
        anc_roles.sort(reverse=True)

        return list(set(roles + anc_roles))

    @log_ldap_exceptions
    def remove_from_role(self, role_id, member_type, member_id):
        """
        Remove a role member. We must remove the member from any sub-roles too
        and from ancestor roles that do not have sub-roles containing member_id.

        Since we use the `groupOfUniqueNames` and `uniqueMember` classes, we
        need to do some juggling with a blank placeholder member:
          * step 1: try to add '' as member, so the role is never empty
          * step 2: remove our member as requested
          * step 3: try to remove member '' (added above). this will only
            succeed if the role is not empty.

        """
        assert self._bound, "call `perform_bind` before `remove_from_role`"
        log.info("Removing %r member %r from role %r",
                 member_type, member_id, role_id)

        member_dn = self._member_dn(member_type, member_id)
        role_dn = self._role_dn(role_id)

        role_dn_list = self._remove_member_dn_from_role_dn(role_dn, member_dn)
        return map(self._role_id, role_dn_list)

    @log_ldap_exceptions
    def list_member_roles(self, member_type, member_id):
        """
        List the role IDs where this user/organisation is a member.
        """

        member_dn = self._member_dn(member_type, member_id)
        return [self._role_id(role_dn) for role_dn in
                self._sub_roles_with_member(self._role_dn(None), member_dn)]

    @log_ldap_exceptions
    def member_roles_info(self, member_type, member_id, attrlist=()):
        """
        Returns roles of member, but supplied with attrlist information,
        useful when rendering in views with extra info like 'description'

        """
        member_dn = self._member_dn(member_type, member_id)
        role_dn = self._role_dn(None)
        filter_tmpl = '(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))'
        filterstr = ldap.filter.filter_format(filter_tmpl, (member_dn,))
        results = self.conn.search_s(role_dn, ldap.SCOPE_SUBTREE,
                                    filterstr=filterstr, attrlist=attrlist)
        for role_dn, attrs in results:
            yield (self._role_id(role_dn), attrs)

    def _search_user_in_orgs(self, user_id):
        user_dn = self._user_dn(user_id)
        query_filter = ldap.filter.filter_format(
            '(&(objectClass=organizationGroup)(uniqueMember=%s))', (user_dn,))

        result = self.conn.search_s(self._org_dn_suffix, ldap.SCOPE_ONELEVEL,
                                    filterstr=query_filter, attrlist=())
        return [self._org_id(dn) for dn, attr in result]

    @log_ldap_exceptions
    def all_organisations(self):
        result = self.conn.search_s(self._org_dn_suffix, ldap.SCOPE_ONELEVEL,
                    filterstr='(objectClass=organizationGroup)',
                    attrlist=('o',))
        return dict( (self._org_id(dn),
                      attr.get('o', [u""])[0].decode(self._encoding))
                     for dn, attr in result )

    @log_ldap_exceptions
    def set_user_picture(self, user_id, binary_data):
        """
        Sets `binary_data` (jpeg bytes) in jpegPhoto property of user
        Call with `binary_data` None for removing picture

        """
        user_dn = self._user_dn(user_id)

        if binary_data is None:
            try:
                result = self.conn.modify_s(user_dn, (
                    (ldap.MOD_DELETE, 'jpegPhoto', None),
                ))
            except ldap.NO_SUCH_ATTRIBUTE:
                pass
            except Exception, e:
                return False
            # Implicit:
            #    succeded = True # so the group was not empty. that's fine.
            return True
        else:
            try:
                result = self.conn.modify_s(user_dn, (
                    (ldap.MOD_REPLACE, 'jpegPhoto', [binary_data]),
                ))
            except ldap.NO_SUCH_ATTRIBUTE:
                try:
                    result = self.conn.modify_s(user_dn, (
                        (ldap.MOD_ADD, 'jpegPhoto', [binary_data]),
                    ))
                except Exception:
                    return False
            return True

    def get_profile_picture(self, user_id):
        """ Return jpegPhoto str attribute if exists, None otherwise """
        query_dn = self._user_dn(user_id)
        result = self.conn.search_s(query_dn, ldap.SCOPE_BASE,
                        filterstr='(objectClass=organizationalPerson)',
                        attrlist=('jpegPhoto', ))

        assert len(result) == 1
        dn, attr = result[0]
        assert dn == query_dn
        return attr.get('jpegPhoto', (None,))[0]
