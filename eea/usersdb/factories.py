from eea.usersdb import UsersDB
from AccessControl.SecurityManagement import getSecurityManager
from Products.LDAPUserFolder.LDAPUser import LDAPUser


def agent_from_uf(ldap_folder, **config):
    """ Get agent instance based on pas.plugins.ldap """
    ldap_settings = ldap_folder['pasldap'].settings
    server = ldap_settings['server.uri'].split('://')[-1]

    config['ldap_server'] = server
    try:
        config['users_dn'] = ldap_settings['users.baseDN']
        config['roles_dn'] = ldap_settings['groups.baseDN']
    except AttributeError:
        # Leave eea.userdb defaults
        pass
    db = UsersDB(**config)
    if config.get('bind') is True:
        user_dn, user_pwd = config.get('user_dn'), config.get('user_pw', '')
        if not user_dn:
            user = getSecurityManager().getUser()  # get plone user
            user_sheet = user.getPropertysheet('pasldap')
            user_object = user_sheet._get_ldap_principal()
            try:
                # user_dn = user.getUserDN()
                user_dn = user_object.context._dn
                user_pwd = user._getPassword()  # need replacement ?
                if not user_pwd or user_pwd == 'undef':
                    # This user object did not result from a login
                    user_dn = user_pwd = ''
            except Exception:
                user_dn = user_pwd = ''
        db.perform_bind(user_dn, user_pwd)
    return db


def agent_from_uf_ldapuserfolder(ldap_folder, **config):
    """ Get agent instance based on acl_users LDAP User Folder"""

    server = ldap_folder._delegate._servers[0]
    config['ldap_server'] = "%s:%s" % (server['host'], server['port'])
    try:
        config['users_dn'] = ldap_folder.users_base
        config['roles_dn'] = ldap_folder.groups_base
    except AttributeError:
        # Leave eea.userdb defaults
        pass
    db = UsersDB(**config)
    if config.get('bind') is True:
        user_dn, user_pwd = config.get('user_dn'), config.get('user_pw', '')
        if not user_dn:
            user = getSecurityManager().getUser()
            if isinstance(user, LDAPUser):
                user_dn = user.getUserDN()
                user_pwd = user._getPassword()
                if not user_pwd or user_pwd == 'undef':
                    # This user object did not result from a login
                    user_dn = user_pwd = ''
            else:
                user_dn = user_pwd = ''
            try:
                user_dn = user.getUserDN()
                user_pwd = user._getPassword()
                if not user_pwd or user_pwd == 'undef':
                    # This user object did not result from a login
                    user_dn = user_pwd = ''
            except Exception:
                user_dn = user_pwd = ''
        db.perform_bind(user_dn, user_pwd)
    return db


def agent_from_site(site, **config):
    """ Get agent instance based on a Naaya site with ldap user source """
    # import pdb; pdb.set_trace() not tested
    source = site.getAuthenticationTool().getSources()[0]
    ldap_folder = source.getUserFolder()
    return agent_from_uf(ldap_folder)
