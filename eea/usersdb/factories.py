from eea.usersdb import UsersDB
from AccessControl.SecurityManagement import getSecurityManager
from Products.LDAPUserFolder.LDAPUser import LDAPUser


def agent_from_uf(ldap_folder, **config):
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
        db.perform_bind(user_dn, user_pwd)
    return db


def agent_from_site(site, **config):
    """ Get agent instance based on a Naaya site with ldap user source """
    source = site.getAuthenticationTool().getSources()[0]
    ldap_folder = source.getUserFolder()
    return agent_from_uf(ldap_folder, **config)
