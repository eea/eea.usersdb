''' test the db agent '''
# pylint: disable=too-many-lines,too-many-public-methods
# pylint: disable=anomalous-unicode-escape-in-string
# encoding: utf-8
import unittest
from copy import deepcopy

from mock import Mock
import six
from six.moves import map
import ldap
from eea.usersdb import db_agent
from eea.usersdb.tests.mock_recorder import Recorder


class StubbedUsersDB(db_agent.UsersDB):
    ''' StubbedUsersDB '''
    def connect(self, server):
        return Mock()

    def _search_user_in_orgs(self, user_id):
        return []


class UsersDBTest(unittest.TestCase):
    ''' UsersDBTest '''
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_user_dn_conversion(self):
        ''' if uid missing, we search for user (eg. in infoMap LDAP schema)'''
        self.mock_conn.search_s.return_value = []
        user_values = {
            'usertwo': 'uid=usertwo,ou=Users,o=EIONET,l=Europe',
            'blahsdfsd': 'uid=blahsdfsd,ou=Users,o=EIONET,l=Europe',
            'x': 'uid=x,ou=Users,o=EIONET,l=Europe',
            '12': 'uid=12,ou=Users,o=EIONET,l=Europe',
            '-': 'uid=-,ou=Users,o=EIONET,l=Europe',
        }
        for user_id, user_dn in six.iteritems(user_values):
            assert self.db._user_dn(user_id) == user_dn
            assert self.db._user_id(user_dn) == user_id
        bad_user_dns = [
            'asdf',
            'uid=a,cn=xxx,ou=Users,o=EIONET,l=Europe',
            'uid=a,ou=Groups,o=EIONET,l=Europe',
            'a,ou=Users,o=EIONET,l=Europe',
        ]
        for bad_dn in bad_user_dns:
            self.assertRaises(AssertionError, self.db._user_id, bad_dn)

    def test_org_dn_conversion(self):
        ''' test_org_dn_conversion '''
        org_values = {
            'air_agency': 'cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
            'blahsdfsd': 'cn=blahsdfsd,ou=Organisations,o=EIONET,l=Europe',
            'x': 'cn=x,ou=Organisations,o=EIONET,l=Europe',
            '12': 'cn=12,ou=Organisations,o=EIONET,l=Europe',
            '-': 'cn=-,ou=Organisations,o=EIONET,l=Europe',
        }
        for org_id, org_dn in six.iteritems(org_values):
            assert self.db._org_dn(org_id) == org_dn
            assert self.db._org_id(org_dn) == org_id

    def test_role_dn_conversion(self):
        ''' test_role_dn_conversion '''
        role_values = {
            'A': 'cn=A,ou=Roles,o=EIONET,l=Europe',
            'A-B': 'cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe',
            'A-C': 'cn=A-C,cn=A,ou=Roles,o=EIONET,l=Europe',
            'eionet': 'cn=eionet,ou=Roles,o=EIONET,l=Europe',
            'eionet-nfp': 'cn=eionet-nfp,cn=eionet,ou=Roles,o=EIONET,l=Europe',
            'eionet-nfp-mc': ('cn=eionet-nfp-mc,cn=eionet-nfp,cn=eionet,'
                              'ou=Roles,o=EIONET,l=Europe'),
            'eionet-nfp-mc-nl': ('cn=eionet-nfp-mc-nl,cn=eionet-nfp-mc,'
                                 'cn=eionet-nfp,cn=eionet,'
                                 'ou=Roles,o=EIONET,l=Europe'),
            None: 'ou=Roles,o=EIONET,l=Europe',
        }
        for role_id, role_dn in six.iteritems(role_values):
            assert self.db._role_dn(role_id) == role_dn
            assert self.db._role_id(role_dn) == role_id
        bad_role_dns = [
            'asdf',
            'a,ou=Users,o=EIONET,l=Europe',
            'cn=aaa-bbb,ou=Roles,o=EIONET,l=Europe',
            'cn=aaa-bbb,cn=bbb,ou=Roles,o=EIONET,l=Europe',
            'cn=cad,cn=aaa-bbb,cn=aaa,ou=Roles,o=EIONET,l=Europe',
            'cn=cad-x-aaa-bbb,cn=aaa-bbb,cn=aaa,ou=Roles,o=EIONET,l=Europe',
        ]
        for bad_dn in bad_role_dns:
            self.assertRaises(AssertionError, self.db._role_id, bad_dn)

    def test_role_names_in_role(self):
        ''' test_role_names_in_role '''
        self.mock_conn.search_s.return_value = [
            ('cn=A,ou=Roles,o=EIONET,l=Europe',
                {'description': [b"Role [A]"]}),
            ('cn=K,ou=Roles,o=EIONET,l=Europe',
                {'description': [b"Role [K]"]})]
        assert self.db.role_names_in_role(None) == {'A': "Role [A]",
                                                    'K': "Role [K]"}
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Roles,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            attrlist=('description',),
            filterstr='(objectClass=groupOfUniqueNames)')

        self.mock_conn.search_s = Mock()
        self.mock_conn.search_s.return_value = [
            ('cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe',
             {'description': [b"Role [A B]"]}),
            ('cn=A-C,cn=A,ou=Roles,o=EIONET,l=Europe',
             {'description': [b"Role [A C]"]})]
        assert self.db.role_names_in_role('A') == {'A-B': "Role [A B]",
                                                   'A-C': "Role [A C]"}
        self.mock_conn.search_s.assert_called_once_with(
            'cn=A,ou=Roles,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            attrlist=('description',),
            filterstr='(objectClass=groupOfUniqueNames)')

        self.mock_conn.search_s = Mock()
        self.mock_conn.search_s.return_value = []
        assert self.db.role_names_in_role('A-B') == {}
        self.mock_conn.search_s.assert_called_once_with(
            'cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            attrlist=('description',),
            filterstr='(objectClass=groupOfUniqueNames)')

    def test_members_in_role(self):
        ''' test_members_in_role '''
        role_dn = self.db._role_dn
        user_dn = self.db._user_dn

        calls_list = []

        def mock_called(dn, scope, **kwargs):
            ''' mock_called '''
            assert kwargs == {'attrlist': ('uniqueMember',),
                              'filterstr': '(objectClass=groupOfUniqueNames)'}
            expected_dn, expected_scope, ret = calls_list.pop(0)
            assert dn == expected_dn
            assert scope == expected_scope
            return ret

        self.mock_conn.search_s.side_effect = mock_called

        # no local members
        calls_list[:] = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'),
                 {'uniqueMember':
                     [user_dn('userone').encode(self.db._encoding)]}),
            ]),
            (role_dn('A'), ldap.SCOPE_ONELEVEL, [
                (role_dn('A-B'),
                 {'uniqueMember':
                     [user_dn('userone').encode(self.db._encoding)]}),
            ]),
        ]
        assert self.db.members_in_role('A') == {'users': [], 'orgs': []}
        assert calls_list == [], "not all calls were made"

        # a local user
        calls_list[:] = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'),
                 {'uniqueMember':
                     [user_dn('userone').encode(self.db._encoding),
                      user_dn('usertwo').encode(self.db._encoding),
                      user_dn('userthree').encode(self.db._encoding),
                      ]}),
            ]),
            (role_dn('A'), ldap.SCOPE_ONELEVEL, [
                (role_dn('A-B'),
                 {'uniqueMember':
                     [user_dn('usertwo').encode(self.db._encoding)]}),
                (role_dn('A-C'),
                 {'uniqueMember':
                     [user_dn('userthree').encode(self.db._encoding), ]}),
            ]),
        ]
        assert self.db.members_in_role('A') == {'users': ['userone'],
                                                'orgs': []}
        assert calls_list == [], "not all calls were made"

    def test_get_user_info(self):
        ''' test_get_user_info '''
        old_attrs = {
            'givenName': [b"Joe"],
            'sn': [b"Smith"],
            'cn': [b"Joe Smith"],
            'mail': [b"jsmith@example.com"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]

        user_info = self.db.user_info('jsmith')

        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', ldap.SCOPE_BASE,
            attrlist=['*', 'uid', 'createTimestamp', 'modifyTimestamp',
                      'pwdChangedTime'],
            filterstr='(objectClass=organizationalPerson)')
        self.assertEqual(user_info['first_name'], "Joe")
        self.assertEqual(user_info['last_name'], "Smith")
        self.assertEqual(user_info['email'], "jsmith@example.com")
        self.assertEqual(user_info['full_name'], "Joe Smith")

    def test_get_user_info_missing_fields(self):
        ''' test_get_user_info_missing_fields '''
        data_dict = {
            'mail': [b"jsmith@example.com"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.db.user_info('jsmith')

        self.assertEqual(user_info['email'], "jsmith@example.com")
        self.assertEqual(user_info['url'], "")

    def test_get_user_info_extra_fields(self):
        ''' test_get_user_info_extra_fields '''
        data_dict = {
            'mail': [b"jsmith@example.com"],
            'uid': [b"jsmith"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.db.user_info('jsmith')

        for name, value in six.iteritems(user_info):
            if name == 'email':
                self.assertEqual(value, "jsmith@example.com")
            elif name in ('dn', 'id', 'uid'):
                continue
            else:
                self.assertEqual(value, "")

    def test_user_info_bad_userid(self):
        ''' test_user_info_bad_userid '''
        self.mock_conn.search_s.return_value = []
        self.assertRaises(AssertionError, self.db.user_info, 'nosuchuser')

    def test_org_info(self):
        ''' test_org_info '''
        self.mock_conn.search_s.return_value = [
            ('cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
             {'o': [b'Agency for Air Studies'],
              'labeledURI': [b'http://www.air_agency.example.com']})]
        info = self.db.org_info('air_agency')
        self.mock_conn.search_s.assert_called_once_with(
            'cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
            ldap.SCOPE_BASE)
        assert info['name'] == "Agency for Air Studies"
        assert info['url'] == "http://www.air_agency.example.com"

    def test_filter_roles(self):
        ''' test_filter_roles '''
        expected_results = {
            '': [],
            'asdf': [],
            '*': ['A', 'A-B', 'A-C',
                  'K', 'K-L', 'K-L-O',
                       'K-M', 'K-M-O',
                       'K-N', 'K-N-O', 'K-N-O-P',
                              'K-N-T',
                  'X-YADF-Z', 'X-Y-ZE'],
            'A': ['A', 'A-B', 'A-C'],
            'A-*': ['A-B', 'A-C'],
            '*-B': ['A-B'],
            'K-*': ['K-L', 'K-L-O',
                    'K-M', 'K-M-O',
                    'K-N', 'K-N-O', 'K-N-O-P',
                           'K-N-T'],
            'K-N-*': ['K-N-O', 'K-N-O-P', 'K-N-T'],
            'K-*-O': ['K-L-O', 'K-M-O', 'K-N-O', 'K-N-O-P'],
            'M': ['K-M', 'K-M-O'],
            'X-Y': ['X-Y-ZE'],
            'X-Y*': ['X-Y-ZE', 'X-YADF-Z'],
            'Z': ['X-YADF-Z'],
            'Z*': ['X-Y-ZE', 'X-YADF-Z'],
        }

        role_id_list = [None, 'A', 'A-B', 'A-C', 'K', 'K-L', 'K-L-O',
                        'K-M', 'K-M-O', 'K-N', 'K-N-O', 'K-N-O-P', 'K-N-T',
                        'X-YADF-Z', 'X-Y-ZE']
        ret = [(self.db._role_dn(role_id), {}) for role_id in role_id_list]

        for pattern, expected_ids in six.iteritems(expected_results):
            self.mock_conn.search_s = Mock(return_value=deepcopy(ret))
            result = self.db.filter_roles(pattern)
            self.mock_conn.search_s.assert_called_once_with(
                'ou=Roles,o=EIONET,l=Europe', ldap.SCOPE_SUBTREE,
                filterstr='(objectClass=groupOfUniqueNames)', attrlist=())
            result_ids = [x[0] for x in result]
            assert set(expected_ids) == set(result_ids), \
                "pattern %r: %r != %r" % (pattern, expected_ids, result)

    def test_delete_role(self):
        ''' test_delete_role '''
        roles_to_delete = ['K', 'K-L', 'K-L-O', 'K-M']
        self.db._bound = True
        self.mock_conn.search_s.return_value = [(self.db._role_dn(r), {})
                                                for r in roles_to_delete]
        self.mock_conn.delete_s.return_value = (ldap.RES_DELETE, [])
        self.db.delete_role('K')

        self.mock_conn.search_s.assert_called_once_with(
            'cn=K,ou=Roles,o=EIONET,l=Europe', ldap.SCOPE_SUBTREE,
            filterstr='(objectClass=groupOfUniqueNames)', attrlist=())

        roles_to_delete.sort()
        roles_to_delete.reverse()
        for args, kwargs in self.mock_conn.delete_s.call_args_list:
            assert kwargs == {}
            assert args == (self.db._role_dn(roles_to_delete.pop(0)),)
        assert roles_to_delete == []

    def test_search_user(self):
        ''' test_search_user '''
        self.db._unpack_user_info = Mock()
        jsmith_dn = self.db._user_dn('jsmith')
        jsmith_info = Mock()
        self.mock_conn.search_s.return_value = [(jsmith_dn, jsmith_info)]

        results = self.db.search_user(u'SM\u012bth')

        self.mock_conn.search_s.assert_called_once_with(
            self.db._user_dn_suffix, ldap.SCOPE_ONELEVEL,
            filterstr=('(&(objectClass=person)(|(uid=*smīth*)(cn=*smīth*)'
                       '(givenName=*smīth*)(sn=*smīth*)'
                       '(businessCategory=*smīth*)(displayName=*smīth*)'
                       '(mail=*smīth*)))'))
        self.db._unpack_user_info.assert_called_with(jsmith_dn, jsmith_info)
        self.assertEqual(results, [self.db._unpack_user_info.return_value])

    def test_search_user_by_email(self):
        ''' test_search_user_by_email '''
        self.db._unpack_user_info = Mock()
        jsmith_dn = self.db._user_dn('jsmith')
        jsmith_info = Mock()
        self.mock_conn.search_s.return_value = [(jsmith_dn, jsmith_info)]

        results = self.db.search_user_by_email(u'jsmith@example.com')

        self.mock_conn.search_s.assert_called_once_with(
            self.db._user_dn_suffix, ldap.SCOPE_ONELEVEL,
            filterstr=('(&(objectClass=person)(mail=jsmith@example.com))'))
        self.db._unpack_user_info.assert_called_with(jsmith_dn, jsmith_info)
        self.assertEqual(results, [self.db._unpack_user_info.return_value])

    def test_role_info(self):
        ''' test_role_info '''
        role_dn = self.db._role_dn('somerole')
        self.mock_conn.search_s.return_value = [(role_dn, {
            'description': [b'Some r\xc5\x8dle'],
            'owner': ['test_owner'],
            'permittedSender': [b'owners']
        })]
        role_info = self.db.role_info('somerole')
        self.mock_conn.search_s.assert_called_once_with(
            role_dn, ldap.SCOPE_BASE)
        self.assertEqual(role_info, {'description': "Some r\u014dle",
                                     'owner': ['test_owner'],
                                     'permittedSender': [b'owners'],
                                     'permittedPerson': [],
                                     'leaderMember': [], 'alternateLeader': [],
                                     'extendedManagement': False})

    def test_mail_group_info(self):
        ''' test_mail_group_info '''
        role_dn = self.db._role_dn('somerole')
        self.mock_conn.search_s.return_value = [(role_dn, {
            'description': [b'don\'t care'],
            'permittedSender': [b'owners'],
            'permittedPerson': [
                self.db._user_dn('john').encode(self.db._encoding)],
        })]
        mail_group_info = self.db.mail_group_info('somerole')
        self.mock_conn.search_s.assert_called_once_with(
            role_dn, ldap.SCOPE_BASE)
        self.assertEqual(mail_group_info, {'owner': [],
                                           'permittedSender': ['owners'],
                                           'permittedPerson': ['john']})

    def test_role_info_not_found(self):
        ''' test_role_info_not_found '''
        self.mock_conn.search_s.side_effect = ldap.NO_SUCH_OBJECT
        self.assertRaises(db_agent.RoleNotFound,
                          self.db.role_info, 'nosuchrole')

    def test_bind_success(self):
        ''' test_bind_success '''
        self.mock_conn.simple_bind_s.return_value = (ldap.RES_BIND, [])
        self.db.bind_user('jsmith', 'some_pw')
        self.mock_conn.simple_bind_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 'some_pw')

    def test_bind_failure(self):
        ''' test_bind_failure '''
        self.mock_conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
        self.assertRaises(ValueError, self.db.bind_user, 'jsmith', 'some_pw')
        self.mock_conn.simple_bind_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 'some_pw')

    def test_set_user_password(self):
        ''' test_set_user_password '''
        self.mock_conn.passwd_s.return_value = (ldap.RES_EXTENDED, [])
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', {})]
        self.db.set_user_password('jsmith', 'the_old_pw', 'some_new_pw')
        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 0,
            attrlist=['*', 'uid', 'createTimestamp', 'modifyTimestamp',
                      'pwdChangedTime'],
            filterstr='(objectClass=organizationalPerson)')
        self.mock_conn.passwd_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe',
            'the_old_pw', 'some_new_pw')

    def test_set_user_password_failure(self):
        ''' test_set_user_password_failure '''
        self.mock_conn.passwd_s.side_effect = ldap.UNWILLING_TO_PERFORM
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', {})]

        self.assertRaises(ValueError, self.db.set_user_password,
                          'jsmith', 'bad_old_pw', 'some_new_pw')
        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 0,
            attrlist=['*', 'uid', 'createTimestamp', 'modifyTimestamp',
                      'pwdChangedTime'],
            filterstr='(objectClass=organizationalPerson)')
        self.mock_conn.passwd_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe',
            'bad_old_pw', 'some_new_pw')


class TestCreateRole(unittest.TestCase):
    ''' TestCreateRole '''
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn
        self.db._bound = True
        self.mock_conn.add_s.return_value = (ldap.RES_ADD, [])
        self.uid = 'john_doe'
        self.db.user_info = Mock()
        self.db.user_info.return_value = {'uid': self.uid}

    def test_create(self):
        ''' test_create '''
        self.db.create_role('A-B-X', "My new test role")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=A-B-X,cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe',
            [('cn', [b'A-B-X']),
             ('objectClass', [b'top', b'groupOfUniqueNames', b'mailListGroup',
                              b'hierarchicalGroup']),
             ('ou', [b'X']),
             ('uniqueMember', [b'']),
             ('permittedSender', [b'owners', b'*@eea.europa.eu']),
             ('description', [b'My new test role']), ])

    def test_existing_role(self):
        ''' test_existing_role '''
        self.mock_conn.add_s.side_effect = ldap.NO_SUCH_OBJECT
        self.assertRaises(ValueError, self.db.create_role, 'A-C', "blah")

    def test_missing_parent(self):
        ''' test_missing_parent '''
        self.mock_conn.add_s.side_effect = ldap.ALREADY_EXISTS
        self.assertRaises(ValueError, self.db.create_role, 'A-X-Y', "blah")

    def test_empty_description(self):
        ''' test_empty_description '''
        self.db.create_role('A-B-Z', "")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=A-B-Z,cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe',
            [('cn', [b'A-B-Z']),
             ('objectClass', [b'top', b'groupOfUniqueNames', b'mailListGroup',
                              b'hierarchicalGroup']),
             ('ou', [b'Z']),
             ('uniqueMember', [b'']),
             ('permittedSender', [b'owners', b'*@eea.europa.eu']),
             ])

    def test_create_top_role(self):
        ''' test_create_top_role '''
        self.db.create_role('T', "top role")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=T,ou=Roles,o=EIONET,l=Europe',
            [('cn', [b'T']),
             ('objectClass', [b'top', b'groupOfUniqueNames', b'mailListGroup',
                              b'hierarchicalGroup']),
             ('ou', [b'T']),
             ('uniqueMember', [b'']),
             ('permittedSender', [b'owners', b'*@eea.europa.eu']),
             ('description', [b'top role']), ])

    def test_unicode(self):
        ''' test_unicode '''
        self.db.create_role('r', "Some r\u014dle")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=r,ou=Roles,o=EIONET,l=Europe',
            [('cn', [b'r']),
             ('objectClass', [b'top', b'groupOfUniqueNames', b'mailListGroup',
                              b'hierarchicalGroup']),
             ('ou', [b'r']),
             ('uniqueMember', [b'']),
             ('permittedSender', [b'owners', b'*@eea.europa.eu']),
             ('description', [b'Some r\xc5\x8dle']), ])

    def test_ancestor_roles_dn(self):
        ''' test_ancestor_roles_dn '''
        role_dn = self.db._role_dn("a-b-c-d-e")
        lst = self.db._ancestor_roles_dn(role_dn)
        self.assertEqual(list(
            map(self.db._role_dn, ["a-b-c-d-e", "a-b-c-d",
                                   "a-b-c", "a-b", "a"])), lst)


class TestAddToRole(unittest.TestCase):
    ''' TestAddToRole '''

    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn
        self.db._bound = True

    def test_missing_user(self):
        ''' test_missing_user '''
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn

        self.mock_conn.search_s.return_value = []

        self.assertRaises(ValueError, self.db._add_member_dn_to_role_dn,
                          role_dn('K-N-O'), user_dn('x'))

        self.mock_conn.search_s.assert_called_once_with(
            user_dn('x'), ldap.SCOPE_BASE, attrlist=())

    def test_missing_role(self):
        ''' test_missing_role '''
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn

        recorder = self.mock_conn.search_s.side_effect = Recorder()
        recorder.expect(user_dn('userone'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[(user_dn('userone'), {})])
        recorder.expect(role_dn('K-N-X'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[])

        self.assertRaises(ValueError, self.db._add_member_dn_to_role_dn,
                          role_dn('K-N-X'), user_dn('userone'))

        recorder.assert_end()

    def test_add(self):
        ''' test_add '''
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn

        search_recorder = self.mock_conn.search_s.side_effect = Recorder()
        search_recorder.expect(user_dn('userone'), ldap.SCOPE_BASE,
                               attrlist=(),
                               return_value=[(user_dn('userone'), {})])
        search_recorder.expect(role_dn('K-N-O'), ldap.SCOPE_BASE, attrlist=(),
                               return_value=[(role_dn('K-N-O'), {})])

        modify_recorder = self.mock_conn.modify_s.side_effect = Recorder()
        for r in 'K-N-O', 'K-N', 'K':
            dn = user_dn('userone').encode(self.db._encoding)
            modify_recorder.expect(role_dn(r),
                                   ((ldap.MOD_ADD, 'uniqueMember', [dn]),),
                                   return_value=(ldap.RES_MODIFY, []))
            modify_recorder.expect(role_dn(r),
                                   ((ldap.MOD_DELETE, 'uniqueMember', [b'']),),
                                   return_value=(ldap.RES_MODIFY, []))

        self.db._add_member_dn_to_role_dn(role_dn('K-N-O'),
                                          user_dn('userone'))

        search_recorder.assert_end()
        modify_recorder.assert_end()


class TestRemoveFromRole(unittest.TestCase):
    ''' TestRemoveFromRole '''

    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_missing_user(self):
        ''' test_missing_user '''
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn
        mock_rm = self.db._remove_member_dn_from_single_role_dn = Mock()
        self.mock_conn.search_s.return_value = []

        self.assertRaises(ValueError,
                          self.db._remove_member_dn_from_role_dn,
                          role_dn('K-N-O'), user_dn('x'))

        self.mock_conn.search_s.assert_called_once_with(
            user_dn('x'), ldap.SCOPE_BASE, attrlist=())
        assert mock_rm.call_count == 0

    def test_missing_role(self):
        ''' test_missing_role '''
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn
        mock_rm = self.db._remove_member_dn_from_single_role_dn = Mock()
        recorder = self.mock_conn.search_s.side_effect = Recorder()
        recorder.expect(user_dn('userone'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[(user_dn('userone'), {})])
        recorder.expect(role_dn('K-N-X'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[])

        self.assertRaises(ValueError,
                          self.db._remove_member_dn_from_role_dn,
                          role_dn('K-N-X'), user_dn('userone'))

        recorder.assert_end()
        assert mock_rm.call_count == 0

    def test_non_member(self):
        ''' test_non_member '''
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn
        mock_rm = self.db._remove_member_dn_from_single_role_dn = Mock()
        recorder = self.mock_conn.search_s.side_effect = Recorder()
        the_filter = ('(&(objectClass=groupOfUniqueNames)'
                      '(uniqueMember=%s))') % user_dn('userone')
        recorder.expect(user_dn('userone'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[(user_dn('userone'), {})])
        recorder.expect(role_dn('K-N-O'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[(role_dn('K-N-O'), {})])
        recorder.expect(role_dn('K-N-O'), ldap.SCOPE_SUBTREE, attrlist=(),
                        filterstr=the_filter, return_value=[])

        self.assertRaises(ValueError,
                          self.db._remove_member_dn_from_role_dn,
                          role_dn('K-N-O'), user_dn('userone'))

        recorder.assert_end()
        assert mock_rm.call_count == 0

    def test_remove(self):
        ''' test_remove '''
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn
        mock_rm = self.db._remove_member_dn_from_single_role_dn = Mock()
        recorder = self.mock_conn.search_s.side_effect = Recorder()
        the_filter = ('(&(objectClass=groupOfUniqueNames)'
                      '(uniqueMember=%s))') % user_dn('userone')
        recorder.expect(user_dn('userone'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[(user_dn('userone'), {})])
        recorder.expect(role_dn('K-N'), ldap.SCOPE_BASE, attrlist=(),
                        return_value=[(role_dn('K-N'), {})])
        recorder.expect(role_dn('K-N'), ldap.SCOPE_SUBTREE, attrlist=(),
                        filterstr=the_filter,
                        return_value=[(role_dn('K-N-O'), {}),
                                      (role_dn('K-N-P'), {}),
                                      (role_dn('K-N-P-Q'), {}),
                                      (role_dn('K-N'), {})])
        recorder.expect(role_dn('K'), ldap.SCOPE_ONELEVEL, attrlist=(),
                        filterstr=the_filter,
                        return_value=[])

        self.db._remove_member_dn_from_role_dn(role_dn('K-N'),
                                               user_dn('userone'))

        recorder.assert_end()
        self.assertEqual(mock_rm.call_args_list, [
            ((role_dn('K-N-P-Q'),
              user_dn('userone').encode(self.db._encoding)), {}),
            ((role_dn('K-N-P'),
              user_dn('userone').encode(self.db._encoding)), {}),
            ((role_dn('K-N-O'),
              user_dn('userone').encode(self.db._encoding)), {}),
            ((role_dn('K-N'),
              user_dn('userone').encode(self.db._encoding)), {}),
            ((role_dn('K'),
              user_dn('userone').encode(self.db._encoding)), {})])


org_info_fixture = {
    'name': "Ye olde bridge club",
    'name_native': 'Ye ølde bridge club',
    'phone': "+45 555 2222",
    'fax': "+45 555 9999",
    'email': "bridge@example.com",
    'url': "http://bridge.example.com/",
    'postal_address': ("13 Card games road\nKøbenhavn, Danmark\n"),
    'street': "Card games road",
    'po_box': "123456",
    'postal_code': "DK 456789",
    'country': "Denmark",
    'locality': "København",
}


class OrganisationsTest(unittest.TestCase):
    ''' OrganisationsTest '''

    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_get_organisation(self):
        ''' test_get_organisation '''
        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        self.mock_conn.search_s.return_value = [(bridge_club_dn, {
            'o': [b'Ye olde bridge club'],
            'physicalDeliveryOfficeName': [b'Ye \xc3\xb8lde bridge club'],
            'telephoneNumber': [b'+45 555 2222'],
            'facsimileTelephoneNumber': [b'+45 555 9999'],
            'street': [b'Card games road'],
            'postOfficeBox': [b'123456'],
            'postalCode': [b'DK 456789'],
            'postalAddress': [b'13 Card games road\n'
                              b'K\xc3\xb8benhavn, Danmark\n'],
            'c': [b'Denmark'],
            'l': [b'K\xc3\xb8benhavn'],
            'labeledURI': [b'http://bridge.example.com/'],
            'mail': [b'bridge@example.com'],
        })]

        org_info = self.db.org_info('bridge_club')

        self.mock_conn.search_s.assert_called_once_with(
            bridge_club_dn, ldap.SCOPE_BASE)
        self.assertEqual(org_info, dict(org_info_fixture,
                                        dn=bridge_club_dn,
                                        id='bridge_club'))
        for name in org_info_fixture:
            assert isinstance(org_info[name], six.text_type)

    def test_create_organisation(self):
        ''' test_create_organisation '''
        self.db._bound = True
        poker_club_dn = self.db._org_dn('poker_club')
        self.mock_conn.add_s.return_value = (ldap.RES_ADD, [])
        self.mock_conn.search_s.return_value = [(poker_club_dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.create_org('poker_club', {
            'name': u"P\xf8ker club",
            'url': u"http://poker.example.com/",
        })

        self.mock_conn.add_s.assert_called_once_with(poker_club_dn, [
            ('cn', [b'poker_club']),
            ('objectClass', [b'top', b'groupOfUniqueNames',
                             b'organizationGroup', b'labeledURIObject',
                             b'hierarchicalGroup']),
            ('uniqueMember', [b'']),
            ('o', [b'P\xc3\xb8ker club']),
            ('labeledURI', [b'http://poker.example.com/']),
        ])

    def test_delete_organisation(self):
        ''' test_delete_organisation '''
        self.db._bound = True
        self.mock_conn.delete_s.return_value = (ldap.RES_DELETE, [])
        poker_club_dn = 'cn=poker_club,ou=Organisations,o=EIONET,l=Europe'

        self.db.delete_org('poker_club')

        self.mock_conn.delete_s.assert_called_once_with(poker_club_dn)

    def test_rename_organisation(self):
        '''test_rename_organisation '''

        def search_s_side(dn, *args, **kwargs):
            ''' search_s_side '''
            if dn in [self.db._org_dn('bridge_club'),
                      self.db._org_dn('tunnel_club')]:
                return [(dn, {})]
            return [(role_dn('eionet'), {}),
                    (role_dn('eionet-something'), {})]
        self.db._bound = True
        org_dn = self.db._org_dn
        role_dn = self.db._role_dn
        self.mock_conn.rename_s.return_value = (ldap.RES_MODRDN, [])
        self.mock_conn.search_s.side_effect = search_s_side
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.rename_org('bridge_club', 'tunnel_club')

        self.mock_conn.rename_s.assert_called_once_with(
            org_dn('bridge_club'), 'cn=tunnel_club')
        self.assertEqual(self.mock_conn.search_s.call_count, 2)
        self.assertEqual(self.mock_conn.modify_s.call_args_list[:-1], [
            ((role_dn('eionet'),
              ((ldap.MOD_DELETE, 'uniqueMember', [org_dn('bridge_club')]),
               (ldap.MOD_ADD, 'uniqueMember', [org_dn('tunnel_club')]))),
             {}),
            ((role_dn('eionet-something'),
              ((ldap.MOD_DELETE, 'uniqueMember', [org_dn('bridge_club')]),
               (ldap.MOD_ADD, 'uniqueMember', [org_dn('tunnel_club')]))),
             {})])

    def test_rename_organisation_fail(self):
        ''' test_rename_organisation_fail '''
        self.db._bound = True
        role_dn = self.db._role_dn
        self.mock_conn.rename_s.side_effect = ldap.ALREADY_EXISTS

        self.assertRaises(db_agent.NameAlreadyExists,
                          self.db.rename_org, 'bridge_club', 'tunnel_club')

        self.mock_conn.rename_s = Mock(return_value=(ldap.RES_MODRDN, []))
        self.mock_conn.search_s.return_value = [
            (role_dn('eionet'), {}), (role_dn('eionet-something'), {})]
        self.mock_conn.modify_s.side_effect = ValueError  # any error will do

        self.assertRaises(db_agent.OrgRenameError,
                          self.db.rename_org, 'bridge_club', 'tunnel_club')

    def test_get_all_organisations(self):
        ''' test_get_all_organisations '''
        self.mock_conn.search_s.return_value = [
            ('cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': [b"Bridge club"]}),
            ('cn=poker_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': [b"P\xc3\xb6ker club"]})
        ]

        orgs = self.db.all_organisations()

        self.assertEqual(
            orgs,
            {'bridge_club': {'name': "Bridge club", 'name_native': '',
                             'country': 'int'},
             'poker_club': {'name': "P\xf6ker club", 'name_native': '',
                            'country': 'int'}})
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Organisations,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            filterstr='(objectClass=organizationGroup)',
            attrlist=('o', 'c', 'physicalDeliveryOfficeName'))

    def test_members_in_organisation(self):
        ''' test_members_in_organisation '''
        self.mock_conn.search_s.return_value = [
            ('cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', {
                'uniqueMember': [b'uid=anne,ou=Users,o=EIONET,l=Europe',
                                 b'uid=jsmith,ou=Users,o=EIONET,l=Europe']
            })]

        members = self.db.members_in_org('bridge_club')

        self.assertEqual(set(members), set(['anne', 'jsmith']))
        self.mock_conn.search_s.assert_called_once_with(
            'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe',
            ldap.SCOPE_BASE, attrlist=('uniqueMember',))

    def test_remove_from_org(self):
        ''' test_remove_from_org '''

        def search_s_side(dn, *args, **kwargs):
            ''' search_s_side '''
            return [(dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.mock_conn.search_s.side_effect = search_s_side
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=[b'anne', b'jsmith', b'xy'])

        modify_statements = tuple(
            [(ldap.MOD_DELETE, 'uniqueMember',
              [b'uid=anne,ou=Users,o=EIONET,l=Europe',
               b'uid=jsmith,ou=Users,o=EIONET,l=Europe'])])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(self.db._org_dn('bridge_club'), modify_statements,
                        return_value=(ldap.RES_MODIFY, []))
        self.db.remove_from_org('bridge_club', ['anne', 'jsmith'])
        recorder.assert_end()

    def test_remove_from_org_all_members(self):
        ''' test_remove_from_org_all_members '''

        def search_s_side(dn, *args, **kwargs):
            ''' search_s_side '''
            return [(dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.mock_conn.search_s.side_effect = search_s_side
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=[b'anne', b'jsmith'])
        self.mock_conn.modify_s.reset_mock()

        modify_statements = tuple(
            [(ldap.MOD_DELETE, 'uniqueMember',
              [b'uid=anne,ou=Users,o=EIONET,l=Europe',
               b'uid=jsmith,ou=Users,o=EIONET,l=Europe'])])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(self.db._org_dn('bridge_club'), modify_statements,
                        return_value=(ldap.RES_MODIFY, []))
        self.db.remove_from_org('bridge_club', ['anne', 'jsmith'])
        recorder.assert_end()

    def test_add_to_org(self):
        ''' test_add_to_org '''

        def search_s_side(dn, *args, **kwargs):
            ''' search_s_side '''
            if dn == self.db._user_dn('anne'):
                return [(dn, {})]
            return [(self.db._org_dn('bridge_club'), {})]
        self.mock_conn.search_s.side_effect = search_s_side
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=['anne'])

        modify_statements = tuple(
            [(ldap.MOD_ADD, 'uniqueMember',
              [b'uid=anne,ou=Users,o=EIONET,l=Europe', ]), ])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(self.db._org_dn('bridge_club'), modify_statements,
                        return_value=(ldap.RES_MODIFY, []))

        self.db.add_to_org('bridge_club', ['anne'])
        recorder.assert_end()

    def test_add_to_empty_org(self):
        ''' test_add_to_empty_org '''

        def search_s_side(dn, *args, **kwargs):
            ''' search_s_side '''
            if dn == self.db._user_dn('anne'):
                return [(dn, {})]
            return [(self.db._org_dn('bridge_club'), {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=[])
        self.mock_conn.search_s.side_effect = search_s_side

        modify_statements = tuple(
            [(ldap.MOD_ADD, 'uniqueMember',
              [b'uid=anne,ou=Users,o=EIONET,l=Europe', ]),
             (ldap.MOD_DELETE, 'uniqueMember', [b''])])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(self.db._org_dn('bridge_club'), modify_statements,
                        return_value=(ldap.RES_MODIFY, []))
        self.db.add_to_org('bridge_club', ['anne'])
        recorder.assert_end()


class OrganisationEditTest(unittest.TestCase):
    ''' OrganisationEditTest '''

    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.db._bound = True
        self.mock_conn = self.db.conn
        self.mock_conn.search_s.return_value = [
            ('cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': [b'Ye olde bridge club'],
                'labeledURI': [b'http://bridge.example.com/'],
            })]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

    def tearDown(self):
        self.mock_conn.modify_s.reset_mock()

    def test_change_nothing(self):
        ''' test_change_nothing '''
        self.db.set_org_info('bridge_club', {
            'name': u"Ye olde bridge club",
            'url': u"http://bridge.example.com/",
        })

        assert self.mock_conn.modify_s.call_count == 0

    def test_add_one(self):
        ''' test_add_one '''
        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = tuple(
            [(ldap.MOD_ADD, 'telephoneNumber', [b'555 2222'])])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(bridge_club_dn, modify_statements,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        self.db.set_org_info('bridge_club', {
            'name': "Ye olde bridge club",
            'url': "http://bridge.example.com/",
            'phone': "555 2222",
        })
        recorder.assert_end()

    def test_change_one(self):
        ''' test_change_one '''
        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = tuple(
            [(ldap.MOD_REPLACE, 'o', [b'Ye new bridge club'])])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(bridge_club_dn, modify_statements,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        self.db.set_org_info('bridge_club', {
            'name': u"Ye new bridge club",
            'url': u"http://bridge.example.com/",
        })
        recorder.assert_end()

    def test_remove_one(self):
        ''' test_remove_one '''
        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = tuple([(ldap.MOD_DELETE, 'o', [])])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(bridge_club_dn, modify_statements,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        self.db.set_org_info('bridge_club', {
            'url': u"http://bridge.example.com/",
        })
        recorder.assert_end()

    def test_unicode(self):
        ''' test_unicode '''
        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = tuple([(ldap.MOD_REPLACE, 'o', [
            b'\xc5\x83\xc3\xa9w n\xc3\xa6\xe1\xb9\x81'])])
        recorder = self.mock_conn.modify_s.side_effect = Recorder()
        recorder.expect(bridge_club_dn, modify_statements,
                        return_value=(ldap.RES_MODIFY, []))
        recorder.expect(ignore_args=True,
                        return_value=(ldap.RES_MODIFY, []))
        self.db.set_org_info('bridge_club', {
            'name': "\u0143\xe9w n\xe6\u1e41",
            'url': "http://bridge.example.com/",
        })
        recorder.assert_end()


class LdapAgentUserEditingTest(unittest.TestCase):
    ''' LdapAgentUserEditingTest '''

    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_user_info_diff(self):
        ''' test_user_info_diff '''
        old_info = {
            'url': b"http://example.com/~jsmith",
            'postal_address': b"old address",
            'phone': b"555 1234",
        }
        new_info = {
            'email': b"jsmith@example.com",
            'postal_address': b"Kongens Nytorv 6, Copenhagen, Denmark",
            'phone': b"555 1234",
        }

        diff = self.db._user_info_diff('jsmith', old_info, new_info, [])

        self.assertEqual(diff, {'uid=jsmith,ou=Users,o=EIONET,l=Europe': [
            (ldap.MOD_ADD, 'mail', [b'jsmith@example.com']),
            (ldap.MOD_REPLACE, 'postalAddress', [
                b'Kongens Nytorv 6, Copenhagen, Denmark']),
            (ldap.MOD_DELETE, 'labeledURI', []),
        ]})

    def test_update_full_name(self):
        ''' test_update_full_name '''
        old_info = {'first_name': b"Joe", 'last_name': b"Smith"}
        self.db._update_full_name(old_info)  # that's what we expect in LDAP
        user_info = {'first_name': "Tester", 'last_name': "Smith"}

        diff = self.db._user_info_diff('jsmith', old_info, user_info, [])

        self.assertEqual(diff, {'uid=jsmith,ou=Users,o=EIONET,l=Europe': [
            (ldap.MOD_REPLACE, 'givenName', [b'Tester']),
            (ldap.MOD_REPLACE, 'sn', [b'Smith']),
            (ldap.MOD_REPLACE, 'cn', [b'Tester Smith']),
        ]})

    def test_change_nothing(self):
        ''' test_change_nothing '''
        old_attrs = {'mail': [b'jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {'email': 'jsmith@example.com'})

        assert self.mock_conn.modify_s.call_count == 0

    def test_add_one(self):
        ''' test_add_one '''
        old_attrs = {}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {'email': 'jsmith@example.com'})

        modify_statements = (
            (ldap.MOD_ADD, 'mail', [b"jsmith@example.com"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.db._user_dn('jsmith'), modify_statements)

    def test_remove_one(self):
        ''' test_remove_one '''
        old_attrs = {'mail': [b'jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {})

        modify_statements = (
            (ldap.MOD_DELETE, 'mail', []),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.db._user_dn('jsmith'), modify_statements)

    def test_update_one(self):
        ''' test_update_one '''
        old_attrs = {'mail': [b'jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {'email': 'jsmith@x.example.com'})

        modify_statements = (
            (ldap.MOD_REPLACE, 'mail', [b"jsmith@x.example.com"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.db._user_dn('jsmith'), modify_statements)

    def test_unicode(self):
        ''' test_unicode '''
        old_attrs = {'postalAddress': [b'The old address']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        china = "\u4e2d\u56fd"
        user_info = {'postal_address': "Somewhere in " + china}

        self.db.set_user_info('jsmith', user_info)

        modify_statements = (
            (ldap.MOD_REPLACE, 'postalAddress', [
                b"Somewhere in " + china.encode('utf-8')]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.db._user_dn('jsmith'), modify_statements)

    def test_all_fields(self):
        ''' test_all_fields '''
        from eea.usersdb.db_agent import EIONET_USER_SCHEMA

        def testvalue(vary, name):
            ''' testvalue '''
            if name == 'full_name':
                return b'%s %s' % (testvalue(vary, 'first_name'),
                                   testvalue(vary, 'last_name'))
            return b'value %s for %r' % (vary, name)

        old_jsmith_ldap = {}
        ldap_mod_statements = []
        new_info = {}
        for name, ldap_name in six.iteritems(EIONET_USER_SCHEMA):
            old_jsmith_ldap[ldap_name] = [testvalue(b'one', name)]
            new_value = testvalue(b'two', name)
            ldap_mod_statements += [(ldap.MOD_REPLACE, ldap_name, [new_value])]
            new_info[name] = new_value

        jsmith_dn = self.db._user_dn('jsmith')
        self.mock_conn.search_s.return_value = [(jsmith_dn, old_jsmith_ldap)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        new_info['first_name'] = new_info['first_name'].decode(
            self.db._encoding)
        new_info['last_name'] = new_info['last_name'].decode(self.db._encoding)
        self.db.set_user_info('jsmith', new_info)

        self.assertEqual(sorted(self.mock_conn.modify_s.call_args[0][1]),
                         sorted(ldap_mod_statements))


class LdapAgentOrganisationsTest(unittest.TestCase):
    ''' LdapAgentOrganisationsTest '''

    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_get_literal_org(self):
        ''' get organisation from user's `o` attribute '''
        data_dict = {'o': [b'My bridge club']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.db.user_info('jsmith')

        self.assertEqual(user_info['organisation'], u"My bridge club")

    def test_set_literal_org(self):
        ''' test_set_literal_org '''
        jsmith_dn = self.db._user_dn('jsmith')
        self.mock_conn.search_s.return_value = [(jsmith_dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {
            'organisation': u"Ze new organisation"})

        modify_statements = (
            (ldap.MOD_ADD, 'o', [b"Ze new organisation"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            jsmith_dn, modify_statements)

    def test_search_user_in_orgs(self):
        ''' test_search_user_in_orgs '''
        self.mock_conn.search_s.return_value = [
            ('cn=org_one,ou=Organisations,o=EIONET,l=Europe', {}),
            ('cn=org_two,ou=Organisations,o=EIONET,l=Europe', {}),
        ]

        org_ids = db_agent.UsersDB._search_user_in_orgs(self.db, 'jsmith')

        filterstr = ('(&(objectClass=organizationGroup)'
                     '(uniqueMember=uid=jsmith,ou=Users,o=EIONET,l=Europe))')
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Organisations,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            filterstr=filterstr, attrlist=())
        self.assertEqual(org_ids, ['org_one', 'org_two'])


class LdapAgentOrganisationsTestBound(unittest.TestCase):
    ''' LdapAgentOrganisationsTestBound '''

    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn
        self.db._bound = True

    def test_create_user(self):
        ''' test_create_user '''
        self.mock_conn.add_s.return_value = (ldap.RES_ADD, [])

        user_info = {'first_name': u"Jöe", 'last_name': u"Smɨth",
                     'email': 'jsmith@example.com'}
        jsmith_dn = self.db._user_dn('jsmith')
        self.mock_conn.search_s.return_value = []

        self.db.create_user('jsmith', user_info)

        self.mock_conn.add_s.assert_called_once_with(jsmith_dn, [
            ('objectClass', [b'top', b'person', b'organizationalPerson',
                             b'inetOrgPerson', b'eionetAccount']),
            ('uid', [b'jsmith']),
            ('mail', [b'jsmith@example.com']),
            ('givenName', [u"Jöe".encode('utf-8')]),
            ('cn', [u"Jöe Smɨth".encode('utf-8')]),
            ('sn', [u"Smɨth".encode('utf-8')]),
        ])

    def test_create_user_existing_id(self):
        ''' test_create_user_existing_id '''
        self.mock_conn.add_s.side_effect = ldap.ALREADY_EXISTS
        self.mock_conn.search_s.return_value = []

        user_info = {'first_name': "Joe", 'last_name': "Smith",
                     'email': 'jsmith@example.com'}
        self.assertRaises(db_agent.NameAlreadyExists,
                          self.db.create_user, 'jsmith', user_info)

    def test_create_user_existing_email(self):
        ''' test_create_user_existing_email '''
        self.mock_conn.add_s.side_effect = ldap.ALREADY_EXISTS
        jsmith_dn = self.db._user_dn('jsmith')
        user_info = {'first_name': "Joe", 'last_name': "Smith",
                     'email': 'jsmith@example.com'}
        self.mock_conn.search_s.return_value = [(jsmith_dn, user_info)]
        self.assertRaises(db_agent.EmailAlreadyExists,
                          self.db.create_user, 'jsmith', user_info)

    def test_create_user_schema_failure(self):
        ''' test_create_user_schema_failure '''
        self.mock_conn.add_s.side_effect = ldap.OBJECT_CLASS_VIOLATION

        user_info = {'first_name': "Joe", 'last_name': "Smith",
                     'email': 'jsmith@example.com'}
        self.mock_conn.search_s.return_value = []
        # the error propagates to caller
        self.assertRaises(ldap.OBJECT_CLASS_VIOLATION,
                          self.db.create_user, 'jsmith', user_info)
