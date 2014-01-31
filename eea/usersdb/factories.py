from eea.usersdb import UsersDB

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
    return UsersDB(**config)

def agent_from_site(site, **config):
    """ Get agent instance based on a Naaya site with ldap user source """
    source = site.getAuthenticationTool().getSources()[0]
    ldap_folder = source.getUserFolder()
    return agent_from_uf(ldap_folder)
