# encoding: utf-8
import unittest
from copy import deepcopy

from nose import SkipTest
import ldap
from eea.usersdb import db_agent
from mock import Mock
from mock_recorder import Recorder
import six
from six.moves import map


class StubbedUsersDB(db_agent.UsersDB):
    def connect(self, server):
        return Mock()

    def _search_user_in_orgs(self, user_id):
        return []


class UsersDBTest(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_user_dn_conversion(self):
        # if uid missing, we search for user (e.g. in infoMap LDAP schema)
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
        bad_org_dns = [
            'asdf',
            'cn=a,cn=xxx,ou=Organisations,o=EIONET,l=Europe',
            'cn=a,ou=Groups,o=EIONET,l=Europe',
            'a,ou=Organisations,o=EIONET,l=Europe',
        ]
        for bad_dn in bad_org_dns:
            self.assertRaises(AssertionError, self.db._org_id, bad_dn)

    def test_role_dn_conversion(self):
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
        self.mock_conn.search_s.return_value = [
            ('cn=A,ou=Roles,o=EIONET,l=Europe', {'description': ["Role [A]"]}),
            ('cn=K,ou=Roles,o=EIONET,l=Europe', {'description': ["Role [K]"]})]
        assert self.db.role_names_in_role(None) == {'A': "Role [A]",
                                                    'K': "Role [K]"}
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Roles,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            attrlist=('description',),
            filterstr='(objectClass=groupOfUniqueNames)')

        self.mock_conn.search_s = Mock()
        self.mock_conn.search_s.return_value = [
            ('cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe',
             {'description': ["Role [A B]"]}),
            ('cn=A-C,cn=A,ou=Roles,o=EIONET,l=Europe',
             {'description': ["Role [A C]"]})]
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
        role_dn = self.db._role_dn
        user_dn = self.db._user_dn
        org_dn = self.db._org_dn

        calls_list = []

        def mock_called(dn, scope, **kwargs):
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
                (role_dn('A'), {'uniqueMember': [user_dn('userone')]}),
            ]),
            (role_dn('A'), ldap.SCOPE_ONELEVEL, [
                (role_dn('A-B'), {'uniqueMember': [user_dn('userone')]}),
            ]),
        ]
        assert self.db.members_in_role('A') == {'users': [], 'orgs': []}
        assert calls_list == [], "not all calls were made"

        # a local user
        calls_list[:] = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'), {'uniqueMember': [user_dn('userone'),
                                                 user_dn('usertwo'),
                                                 user_dn('userthree'),
                                                 org_dn('air_agency')]}),
            ]),
            (role_dn('A'), ldap.SCOPE_ONELEVEL, [
                (role_dn('A-B'), {'uniqueMember': [user_dn('usertwo')]}),
                (role_dn('A-C'), {'uniqueMember': [user_dn('userthree'),
                                                   org_dn('air_agency')]}),
            ]),
        ]
        assert self.db.members_in_role('A') == {'users': ['userone'],
                                                'orgs': []}
        assert calls_list == [], "not all calls were made"

        # a local user and an organisation
        calls_list[:] = [
            (role_dn('A'), ldap.SCOPE_BASE, [
                (role_dn('A'), {'uniqueMember': [user_dn('userone'),
                                                 user_dn('usertwo'),
                                                 user_dn('userthree'),
                                                 org_dn('air_agency')]}),
            ]),
            (role_dn('A'), ldap.SCOPE_ONELEVEL, [
                (role_dn('A-B'), {'uniqueMember': [user_dn('usertwo')]}),
                (role_dn('A-C'), {'uniqueMember': [user_dn('userthree')]}),
            ]),
        ]
        assert self.db.members_in_role('A') == {'users': ['userone'],
                                                'orgs': ['air_agency']}
        assert calls_list == [], "not all calls were made"

    def test_get_user_info(self):
        old_attrs = {
            'givenName': ["Joe"],
            'sn': ["Smith"],
            'cn': ["Joe Smith"],
            'mail': ["jsmith@example.com"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]

        user_info = self.db.user_info('jsmith')

        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', ldap.SCOPE_BASE,
            filterstr='(objectClass=organizationalPerson)')
        self.assertEqual(user_info['first_name'], u"Joe")
        self.assertEqual(user_info['last_name'], u"Smith")
        self.assertEqual(user_info['email'], u"jsmith@example.com")
        self.assertEqual(user_info['full_name'], u"Joe Smith")

    def test_get_user_info_missing_fields(self):
        data_dict = {
            'mail': ["jsmith@example.com"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.db.user_info('jsmith')

        self.assertEqual(user_info['email'], "jsmith@example.com")
        self.assertEqual(user_info['url'], "")

    def test_get_user_info_extra_fields(self):
        data_dict = {
            'mail': ["jsmith@example.com"],
            'uid': ["jsmith"],
        }
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.db.user_info('jsmith')

        for name, value in six.iteritems(user_info):
            if name == 'email':
                self.assertEqual(value, u"jsmith@example.com")
            elif name in ('dn', 'id'):
                continue
            else:
                self.assertEqual(value, u"")

    def test_user_info_bad_userid(self):
        self.mock_conn.search_s.return_value = []
        self.assertRaises(AssertionError, self.db.user_info, 'nosuchuser')

    def test_org_info(self):
        self.mock_conn.search_s.return_value = [
            ('cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
             {'o': ['Agency for Air Studies'],
              'labeledURI': ['http://www.air_agency.example.com']})]
        info = self.db.org_info('air_agency')
        self.mock_conn.search_s.assert_called_once_with(
            'cn=air_agency,ou=Organisations,o=EIONET,l=Europe',
            ldap.SCOPE_BASE)
        assert info['name'] == "Agency for Air Studies"
        assert info['url'] == "http://www.air_agency.example.com"

    def test_filter_roles(self):
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

        # TODO: assert error when deleting non-existent role
        # TODO: test deleting top-level role

    def test_search_user(self):
        self.db._unpack_user_info = Mock()
        jsmith_dn = self.db._user_dn('jsmith')
        jsmith_info = Mock()
        self.mock_conn.search_s.return_value = [(jsmith_dn, jsmith_info)]

        results = self.db.search_user(u'SM\u012bth')

        self.mock_conn.search_s.assert_called_once_with(
            self.db._user_dn_suffix, ldap.SCOPE_ONELEVEL,
            filterstr=('(&(objectClass=person)(|(mail=*sm\xc4\xabth*)'
                       '(sn=*sm\xc4\xabth*)(givenName=*sm\xc4\xabth*)'
                       '(uid=*sm\xc4\xabth*)(cn=*sm\xc4\xabth*)))'))
        self.db._unpack_user_info.assert_called_with(jsmith_dn, jsmith_info)
        self.assertEqual(results, [self.db._unpack_user_info.return_value])

    def test_search_user_by_email(self):
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

    def test_search_org(self):
        self.db._unpack_org_info = Mock()
        club_dn = self.db._org_dn('bridge_club')
        club_info = Mock()
        self.mock_conn.search_s.return_value = [(club_dn, club_info)]

        results = self.db.search_org(u'Br\u012bdGe')

        self.mock_conn.search_s.assert_called_once_with(
            self.db._org_dn_suffix, ldap.SCOPE_ONELEVEL,
            filterstr=('(&(objectClass=organizationGroup)'
                       '(|(cn=*br\xc4\xabdge*)(o=*br\xc4\xabdge*)))'))
        self.db._unpack_org_info.assert_called_with(club_dn, club_info)
        self.assertEqual(results, [self.db._unpack_org_info.return_value])

    def test_role_info(self):
        role_dn = self.db._role_dn('somerole')
        circle_dn = self.db._user_dn(db_agent.EIONET_ADMIN_UID)
        self.mock_conn.search_s.return_value = [(role_dn, {
            'description': ['Some r\xc5\x8dle'],
            'owner': [circle_dn],
            'permittedSender': ['owners']
        })]
        role_info = self.db.role_info('somerole')
        self.mock_conn.search_s.assert_called_once_with(
            role_dn, ldap.SCOPE_BASE)
        self.assertEqual(role_info, {'description': u"Some r\u014dle",
                                     'owner': [circle_dn],
                                     'permittedSender': ['owners'],
                                     'permittedPerson': []})

    def test_mail_group_info(self):
        role_dn = self.db._role_dn('somerole')
        self.mock_conn.search_s.return_value = [(role_dn, {
            'description': ['don\'t care'],
            'owner': [self.db._user_dn(db_agent.EIONET_ADMIN_UID)],
            'permittedSender': ['owners'],
            'permittedPerson': [self.db._user_dn('john')],
        })]
        mail_group_info = self.db.mail_group_info('somerole')
        self.mock_conn.search_s.assert_called_once_with(
            role_dn, ldap.SCOPE_BASE)
        self.assertEqual(mail_group_info, {'owner': [],
                                           'permittedSender': ['owners'],
                                           'permittedPerson': ['john']})

    def test_role_info_not_found(self):
        self.mock_conn.search_s.side_effect = ldap.NO_SUCH_OBJECT
        self.assertRaises(db_agent.RoleNotFound,
                          self.db.role_info, 'nosuchrole')

    def test_bind_success(self):
        self.mock_conn.simple_bind_s.return_value = (ldap.RES_BIND, [])
        self.db.bind_user('jsmith', 'some_pw')
        self.mock_conn.simple_bind_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 'some_pw')

    def test_bind_failure(self):
        self.mock_conn.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS
        self.assertRaises(ValueError, self.db.bind_user, 'jsmith', 'some_pw')
        self.mock_conn.simple_bind_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 'some_pw')

    def test_set_user_password(self):
        self.mock_conn.passwd_s.return_value = (ldap.RES_EXTENDED, [])
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', {})]
        self.db.set_user_password('jsmith', 'the_old_pw', 'some_new_pw')
        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 0,
            filterstr='(objectClass=organizationalPerson)')
        self.mock_conn.passwd_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe',
            'the_old_pw', 'some_new_pw')

    def test_set_user_password_failure(self):
        self.mock_conn.passwd_s.side_effect = ldap.UNWILLING_TO_PERFORM
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', {})]

        self.assertRaises(ValueError, self.db.set_user_password,
                          'jsmith', 'bad_old_pw', 'some_new_pw')
        self.mock_conn.search_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe', 0,
            filterstr='(objectClass=organizationalPerson)')
        self.mock_conn.passwd_s.assert_called_once_with(
            'uid=jsmith,ou=Users,o=EIONET,l=Europe',
            'bad_old_pw', 'some_new_pw')


class TestCreateRole(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn
        self.db._bound = True
        self.mock_conn.add_s.return_value = (ldap.RES_ADD, [])
        self.uid = 'john_doe'
        self.db.user_info = Mock()
        self.db.user_info.return_value = {'uid': self.uid}

    def test_create(self):
        owner_dn = self.db._user_dn(db_agent.EIONET_ADMIN_UID)
        self.db.create_role('A-B-X', "My new test role")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=A-B-X,cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe',
            [('cn', ['A-B-X']),
             ('objectClass', ['top', 'groupOfUniqueNames', 'mailListGroup']),
             ('ou', ['X']),
             ('uniqueMember', ['']),
             ('owner', [owner_dn]),
             ('permittedSender', ['owners']),
             ('description', ['My new test role']), ])

    def test_existing_role(self):
        self.mock_conn.add_s.side_effect = ldap.NO_SUCH_OBJECT
        self.assertRaises(ValueError, self.db.create_role, 'A-C', "blah")

    def test_missing_parent(self):
        self.mock_conn.add_s.side_effect = ldap.ALREADY_EXISTS
        self.assertRaises(ValueError, self.db.create_role, 'A-X-Y', "blah")

    def test_empty_description(self):
        owner_dn = self.db._user_dn(db_agent.EIONET_ADMIN_UID)
        self.db.create_role('A-B-Z', "")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=A-B-Z,cn=A-B,cn=A,ou=Roles,o=EIONET,l=Europe',
            [('cn', ['A-B-Z']),
             ('objectClass',
             ['top', 'groupOfUniqueNames', 'mailListGroup']),
             ('ou', ['Z']),
             ('uniqueMember', ['']),
             ('owner', [owner_dn]),
             ('permittedSender', ['owners'])])

    def test_create_top_role(self):
        owner_dn = self.db._user_dn(db_agent.EIONET_ADMIN_UID)
        self.db.create_role('T', "top role")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=T,ou=Roles,o=EIONET,l=Europe',
            [('cn', ['T']),
             ('objectClass', ['top', 'groupOfUniqueNames', 'mailListGroup']),
             ('ou', ['T']),
             ('uniqueMember', ['']),
             ('owner', [owner_dn]),
             ('permittedSender', ['owners']),
             ('description', ['top role']), ])

    def test_unicode(self):
        owner_dn = self.db._user_dn(db_agent.EIONET_ADMIN_UID)
        self.db.create_role('r', u"Some r\u014dle")
        self.mock_conn.add_s.assert_called_once_with(
            'cn=r,ou=Roles,o=EIONET,l=Europe',
            [('cn', ['r']),
             ('objectClass', ['top', 'groupOfUniqueNames', 'mailListGroup']),
             ('ou', ['r']),
             ('uniqueMember', ['']),
             ('owner', [owner_dn]),
             ('permittedSender', ['owners']),
             ('description', ['Some r\xc5\x8dle']), ])

    def test_ancestor_roles_dn(self):
        role_dn = self.db._role_dn("a-b-c-d-e")
        lst = self.db._ancestor_roles_dn(role_dn)
        self.assertEqual(list(map(self.db._role_dn, ["a-b-c-d-e", "a-b-c-d",
                                                "a-b-c", "a-b", "a"])), lst)


class TestAddToRole(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn
        self.db._bound = True

    def test_missing_user(self):
        user_dn = self.db._user_dn
        role_dn = self.db._role_dn

        self.mock_conn.search_s.return_value = []

        self.assertRaises(ValueError, self.db._add_member_dn_to_role_dn,
                          role_dn('K-N-O'), user_dn('x'))

        self.mock_conn.search_s.assert_called_once_with(
            user_dn('x'), ldap.SCOPE_BASE, attrlist=())

    def test_missing_role(self):
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
            dn = user_dn('userone')
            modify_recorder.expect(role_dn(r),
                                   ((ldap.MOD_ADD, 'uniqueMember', [dn]),),
                                   return_value=(ldap.RES_MODIFY, []))
            modify_recorder.expect(role_dn(r),
                                   ((ldap.MOD_DELETE, 'uniqueMember', ['']),),
                                   return_value=(ldap.RES_MODIFY, []))

        self.db._add_member_dn_to_role_dn(role_dn('K-N-O'),
                                          user_dn('userone'))

        search_recorder.assert_end()
        modify_recorder.assert_end()


class TestRemoveFromRole(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_missing_user(self):
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
            ((role_dn('K-N-P-Q'), user_dn('userone')), {}),
            ((role_dn('K-N-P'), user_dn('userone')), {}),
            ((role_dn('K-N-O'), user_dn('userone')), {}),
            ((role_dn('K-N'), user_dn('userone')), {}),
            ((role_dn('K'), user_dn('userone')), {})])


org_info_fixture = {
    'name': u"Ye olde bridge club",
    'phone': u"+45 555 2222",
    'fax': u"+45 555 9999",
    'url': u"http://bridge.example.com/",
    'postal_address': (u"13 Card games road\n"
                       u"K\xf8benhavn, Danmark\n"),
    'street': u"Card games road",
    'po_box': u"123456",
    'postal_code': u"DK 456789",
    'country': u"Denmark",
    'locality': u"K\xf8benhavn",
}


class OrganisationsTest(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_get_organisation(self):
        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        self.mock_conn.search_s.return_value = [(bridge_club_dn, {
            'o': ['Ye olde bridge club'],
            'telephoneNumber': ['+45 555 2222'],
            'facsimileTelephoneNumber': ['+45 555 9999'],
            'street': ['Card games road'],
            'postOfficeBox': ['123456'],
            'postalCode': ['DK 456789'],
            'postalAddress': ['13 Card games road\n'
                              'K\xc3\xb8benhavn, Danmark\n'],
            'st': ['Denmark'],
            'l': ['K\xc3\xb8benhavn'],
            'labeledURI': ['http://bridge.example.com/'],
        })]

        org_info = self.db.org_info('bridge_club')

        self.mock_conn.search_s.assert_called_once_with(
            bridge_club_dn, ldap.SCOPE_BASE)
        self.assertEqual(org_info, dict(org_info_fixture,
                                        dn=bridge_club_dn,
                                        id='bridge_club'))
        for name in org_info_fixture:
            assert type(org_info[name]) is six.text_type

    def test_create_organisation(self):
        self.db._bound = True
        self.mock_conn.add_s.return_value = (ldap.RES_ADD, [])

        self.db.create_org('poker_club', {
            'name': u"P\xf8ker club",
            'url': u"http://poker.example.com/",
        })

        poker_club_dn = 'cn=poker_club,ou=Organisations,o=EIONET,l=Europe'
        self.mock_conn.add_s.assert_called_once_with(poker_club_dn, [
            ('cn', ['poker_club']),
            ('objectClass', ['top', 'groupOfUniqueNames',
                             'organizationGroup', 'labeledURIObject']),
            ('uniqueMember', ['']),
            ('o', ['P\xc3\xb8ker club']),
            ('labeledURI', ['http://poker.example.com/']),
        ])

    def test_delete_organisation(self):
        self.db._bound = True
        self.mock_conn.delete_s.return_value = (ldap.RES_DELETE, [])
        poker_club_dn = 'cn=poker_club,ou=Organisations,o=EIONET,l=Europe'

        self.db.delete_org('poker_club')

        self.mock_conn.delete_s.assert_called_once_with(poker_club_dn)

    def test_rename_organisation(self):
        self.db._bound = True
        org_dn = self.db._org_dn
        role_dn = self.db._role_dn
        self.mock_conn.rename_s.return_value = (ldap.RES_MODRDN, [])
        self.mock_conn.search_s.return_value = [
            (role_dn('eionet'), {}), (role_dn('eionet-something'), {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.rename_org('bridge_club', 'tunnel_club')

        self.mock_conn.rename_s.assert_called_once_with(
            org_dn('bridge_club'), 'cn=tunnel_club')
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Roles,o=EIONET,l=Europe', ldap.SCOPE_SUBTREE,
            filterstr='(uniqueMember=%s)' % org_dn('bridge_club'), attrlist=())
        self.assertEqual(self.mock_conn.modify_s.call_args_list, [
            ((role_dn('eionet'),
              ((ldap.MOD_DELETE, 'uniqueMember', [org_dn('bridge_club')]),
               (ldap.MOD_ADD, 'uniqueMember', [org_dn('tunnel_club')]))),
             {}),
            ((role_dn('eionet-something'),
              ((ldap.MOD_DELETE, 'uniqueMember', [org_dn('bridge_club')]),
               (ldap.MOD_ADD, 'uniqueMember', [org_dn('tunnel_club')]))),
             {})])

    def test_rename_organisation_fail(self):
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
        self.mock_conn.search_s.return_value = [
            ('cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': ["Bridge club"]}),
            ('cn=poker_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': ["P\xc3\xb6ker club"]})
        ]

        orgs = self.db.all_organisations()

        self.assertEqual(orgs, {'bridge_club': u"Bridge club",
                                'poker_club': u"P\xf6ker club"})
        self.mock_conn.search_s.assert_called_once_with(
            'ou=Organisations,o=EIONET,l=Europe', ldap.SCOPE_ONELEVEL,
            filterstr='(objectClass=organizationGroup)', attrlist=('o',))

    def test_members_in_organisation(self):
        self.mock_conn.search_s.return_value = [
            ('cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', {
                'uniqueMember': ['uid=anne,ou=Users,o=EIONET,l=Europe',
                                 'uid=jsmith,ou=Users,o=EIONET,l=Europe']
            })]

        members = self.db.members_in_org('bridge_club')

        self.assertEqual(set(members), set(['anne', 'jsmith']))
        self.mock_conn.search_s.assert_called_once_with(
            'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe',
            ldap.SCOPE_BASE, attrlist=('uniqueMember',))

    def test_remove_from_org(self):
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=['anne', 'jsmith', 'xy'])

        self.db.remove_from_org('bridge_club', ['anne', 'jsmith'])

        self.mock_conn.modify_s.assert_called_once_with(
            'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', (
                (ldap.MOD_DELETE, 'uniqueMember', [
                    'uid=anne,ou=Users,o=EIONET,l=Europe',
                    'uid=jsmith,ou=Users,o=EIONET,l=Europe'
                ]),
            ))

    def test_remove_from_org_all_members(self):
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=['anne', 'jsmith'])
        self.mock_conn.modify_s.reset_mock()

        self.db.remove_from_org('bridge_club', ['anne', 'jsmith'])

        self.mock_conn.modify_s.assert_called_once_with(
            'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', (
                (ldap.MOD_ADD, 'uniqueMember', ['']),
                (ldap.MOD_DELETE, 'uniqueMember', [
                    'uid=anne,ou=Users,o=EIONET,l=Europe',
                    'uid=jsmith,ou=Users,o=EIONET,l=Europe'
                ]),
            ))

    def test_add_to_org(self):
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=['anne'])

        self.db.add_to_org('bridge_club', ['anne'])

        self.mock_conn.modify_s.assert_called_once_with(
            'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', (
                (ldap.MOD_ADD, 'uniqueMember', [
                    'uid=anne,ou=Users,o=EIONET,l=Europe',
                ]),
            ))

    def test_add_to_empty_org(self):
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])
        self.db._bound = True
        self.db.members_in_org = Mock(return_value=[])

        self.db.add_to_org('bridge_club', ['anne'])

        self.mock_conn.modify_s.assert_called_once_with(
            'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', (
                (ldap.MOD_ADD, 'uniqueMember', [
                    'uid=anne,ou=Users,o=EIONET,l=Europe',
                ]),
                (ldap.MOD_DELETE, 'uniqueMember', ['']),
            ))


class OrganisationEditTest(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.db._bound = True
        self.mock_conn = self.db.conn
        self.mock_conn.search_s.return_value = [
            ('cn=bridge_club,ou=Organisations,o=EIONET,l=Europe', {
                'o': ['Ye olde bridge club'],
                'labeledURI': ['http://bridge.example.com/'],
            })]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

    def test_change_nothing(self):
        self.db.set_org_info('bridge_club', {
            'name': u"Ye olde bridge club",
            'url': u"http://bridge.example.com/",
        })

        assert self.mock_conn.modify_s.call_count == 0

    def test_add_one(self):
        self.db.set_org_info('bridge_club', {
            'name': u"Ye olde bridge club",
            'url': u"http://bridge.example.com/",
            'phone': u"555 2222",
        })

        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = [(ldap.MOD_ADD, 'telephoneNumber', ['555 2222'])]
        self.mock_conn.modify_s.assert_called_once_with(
            bridge_club_dn, tuple(modify_statements))

    def test_change_one(self):
        self.db.set_org_info('bridge_club', {
            'name': u"Ye new bridge club",
            'url': u"http://bridge.example.com/",
        })

        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = [(ldap.MOD_REPLACE, 'o', ['Ye new bridge club'])]
        self.mock_conn.modify_s.assert_called_once_with(
            bridge_club_dn, tuple(modify_statements))

    def test_remove_one(self):
        self.db.set_org_info('bridge_club', {
            'url': u"http://bridge.example.com/",
        })

        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = [(ldap.MOD_DELETE, 'o', [])]
        self.mock_conn.modify_s.assert_called_once_with(
            bridge_club_dn, tuple(modify_statements))

    def test_unicode(self):
        self.db.set_org_info('bridge_club', {
            'name': u"\u0143\xe9w n\xe6\u1e41",
            'url': u"http://bridge.example.com/",
        })

        bridge_club_dn = 'cn=bridge_club,ou=Organisations,o=EIONET,l=Europe'
        modify_statements = [(ldap.MOD_REPLACE, 'o', [
            '\xc5\x83\xc3\xa9w n\xc3\xa6\xe1\xb9\x81'])]
        self.mock_conn.modify_s.assert_called_once_with(
            bridge_club_dn, tuple(modify_statements))


class LdapAgentUserEditingTest(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_user_info_diff(self):
        old_info = {
            'url': u"http://example.com/~jsmith",
            'postal_address': u"old address",
            'phone': u"555 1234",
        }
        new_info = {
            'email': u"jsmith@example.com",
            'postal_address': u"Kongens Nytorv 6, Copenhagen, Denmark",
            'phone': u"555 1234",
        }

        diff = self.db._user_info_diff('jsmith', old_info, new_info, [])

        self.assertEqual(diff, {'uid=jsmith,ou=Users,o=EIONET,l=Europe': [
            (ldap.MOD_ADD, 'mail', ['jsmith@example.com']),
            (ldap.MOD_REPLACE, 'postalAddress', [
                'Kongens Nytorv 6, Copenhagen, Denmark']),
            (ldap.MOD_DELETE, 'labeledURI', []),
        ]})

    def test_update_full_name(self):
        old_info = {'first_name': u"Joe", 'last_name': u"Smith"}
        self.db._update_full_name(old_info)  # that's what we expect in LDAP
        user_info = {'first_name': u"Tester", 'last_name': u"Smith"}

        diff = self.db._user_info_diff('jsmith', old_info, user_info, [])

        self.assertEqual(diff, {'uid=jsmith,ou=Users,o=EIONET,l=Europe': [
            (ldap.MOD_REPLACE, 'givenName', ['Tester']),
            (ldap.MOD_REPLACE, 'cn', ['Tester Smith']),
        ]})

    def test_change_nothing(self):
        old_attrs = {'mail': ['jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {'email': u'jsmith@example.com'})

        assert self.mock_conn.modify_s.call_count == 0

    def test_add_one(self):
        old_attrs = {}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {'email': u'jsmith@example.com'})

        modify_statements = (
            (ldap.MOD_ADD, 'mail', ["jsmith@example.com"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.db._user_dn('jsmith'), modify_statements)

    def test_remove_one(self):
        old_attrs = {'mail': ['jsmith@example.com']}
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
        old_attrs = {'mail': ['jsmith@example.com']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {'email': u'jsmith@x.example.com'})

        modify_statements = (
            (ldap.MOD_REPLACE, 'mail', ["jsmith@x.example.com"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.db._user_dn('jsmith'), modify_statements)

    def test_unicode(self):
        old_attrs = {'postalAddress': ['The old address']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', old_attrs)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        china = u"\u4e2d\u56fd"
        user_info = {'postal_address': u"Somewhere in " + china}

        self.db.set_user_info('jsmith', user_info)

        modify_statements = (
            (ldap.MOD_REPLACE, 'postalAddress', [
                "Somewhere in " + china.encode('utf-8')]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            self.db._user_dn('jsmith'), modify_statements)

    def test_all_fields(self):
        from eea.usersdb.db_agent import EIONET_USER_SCHEMA

        def testvalue(vary, name):
            if name == 'full_name':
                return '%s %s' % (testvalue(vary, 'first_name'),
                                  testvalue(vary, 'last_name'))
            else:
                return 'value %s for %r' % (vary, name)

        old_jsmith_ldap = {}
        ldap_mod_statements = []
        new_info = {}
        for name, ldap_name in six.iteritems(EIONET_USER_SCHEMA):
            old_jsmith_ldap[ldap_name] = [testvalue('one', name)]
            new_value = testvalue('two', name)
            ldap_mod_statements += [(ldap.MOD_REPLACE, ldap_name, [new_value])]
            new_info[name] = new_value

        jsmith_dn = 'uid=jsmith,ou=Users,o=EIONET,l=Europe'
        self.mock_conn.search_s.return_value = [(jsmith_dn, old_jsmith_ldap)]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', new_info)

        self.assertEqual(sorted(self.mock_conn.modify_s.call_args[0][1]),
                         sorted(ldap_mod_statements))


class LdapAgentOrganisationsTest(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn

    def test_get_literal_org(self):
        # get organisation from user's `o` attribute
        data_dict = {'o': ['My bridge club']}
        self.mock_conn.search_s.return_value = [
            ('uid=jsmith,ou=Users,o=EIONET,l=Europe', data_dict)]

        user_info = self.db.user_info('jsmith')

        self.assertEqual(user_info['organisation'], u"My bridge club")

    def test_set_literal_org(self):
        jsmith_dn = self.db._user_dn('jsmith')
        self.mock_conn.search_s.return_value = [(jsmith_dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith', {
            'organisation': u"Ze new organisation"})

        modify_statements = (
            (ldap.MOD_ADD, 'o', ["Ze new organisation"]),
        )
        self.mock_conn.modify_s.assert_called_once_with(
            jsmith_dn, modify_statements)

    def test_search_user_in_orgs(self):
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

    def test_get_member_org(self):
        raise SkipTest
        jsmith_dn = self.db._user_dn('jsmith')
        self.mock_conn.search_s.return_value = [(jsmith_dn, {})]
        self.db._search_user_in_orgs = Mock(return_value=['bridge_club',
                                                          'poker_club'])

        user_info = self.db.user_info('jsmith')

        self.assertEqual(user_info['organisation_links'], ['bridge_club'])

    def test_set_member_org(self):
        raise SkipTest
        jsmith_dn = self.db._user_dn('jsmith')
        bridge_club_dn = self.db._org_dn('bridge_club')
        self.mock_conn.search_s.return_value = [(jsmith_dn, {})]
        self.mock_conn.modify_s.return_value = (ldap.RES_MODIFY, [])

        self.db.set_user_info('jsmith',
                              {'organisation_links': ['bridge_club']})

        self.mock_conn.modify_s.assert_called_once_with(
            bridge_club_dn, ((ldap.MOD_ADD, 'uniqueMember', [jsmith_dn]),))

    def test_change_member_org(self):
        raise SkipTest
        jsmith_dn = self.db._user_dn('jsmith')
        bridge_club_dn = self.db._org_dn('bridge_club')
        poker_club_dn = self.db._org_dn('poker_club')
        yachting_club_dn = self.db._org_dn('yachting_club')
        self.db._search_user_in_orgs = Mock(return_value=['bridge_club',
                                                          'poker_club'])

        diff = self.db._user_info_diff(
            'jsmith', {'organisation': u"My own little club"},
            {'organisation_links': ['yachting_club']},
            ['bridge_club', 'poker_club'])

        self.assertEqual(diff, {
            jsmith_dn: [(ldap.MOD_DELETE, 'o', [])],
            bridge_club_dn: [(ldap.MOD_DELETE, 'uniqueMember', [jsmith_dn])],
            poker_club_dn: [(ldap.MOD_DELETE, 'uniqueMember', [jsmith_dn])],
            yachting_club_dn: [(ldap.MOD_ADD, 'uniqueMember', [jsmith_dn])],
        })

    # TODO test adding two organisation links *and* setting a value


class LdapAgentOrganisationsTestBound(unittest.TestCase):
    def setUp(self):
        self.db = StubbedUsersDB(ldap_server='')
        self.mock_conn = self.db.conn
        self.db._bound = True

    def test_create_user(self):
        self.mock_conn.add_s.return_value = (ldap.RES_ADD, [])

        user_info = {'first_name': u"Jöe", 'last_name': u"Smɨth"}
        self.db.create_user('jsmith', user_info)

        jsmith_dn = 'uid=jsmith,ou=Users,o=EIONET,l=Europe'
        self.mock_conn.add_s.assert_called_once_with(jsmith_dn, [
            ('objectClass', ['top', 'person', 'organizationalPerson',
                             'inetOrgPerson']),
            ('uid', ['jsmith']),
            ('givenName', [u"Jöe".encode('utf-8')]),
            ('cn', [u"Jöe Smɨth".encode('utf-8')]),
            ('sn', [u"Smɨth".encode('utf-8')]),
        ])

    def test_create_user_existing_id(self):
        self.mock_conn.add_s.side_effect = ldap.ALREADY_EXISTS

        user_info = {'first_name': "Joe", 'last_name': "Smith"}
        self.assertRaises(db_agent.NameAlreadyExists,
                          self.db.create_user, 'jsmith', user_info)

    def test_create_user_schema_failure(self):
        self.mock_conn.add_s.side_effect = ldap.OBJECT_CLASS_VIOLATION

        user_info = {'first_name': "Joe", 'last_name': "Smith"}
        # the error propagates to caller
        self.assertRaises(ldap.OBJECT_CLASS_VIOLATION,
                          self.db.create_user, 'jsmith', user_info)
