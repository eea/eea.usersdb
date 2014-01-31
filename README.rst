eea.usersdb
===========

Library to access the EIONET users database, stored in LDAP.

    >>> import eea.usersdb
    >>> users_db = eea.usersdb.UsersDB(ldap_server='ldap2.eionet.europa.eu')
    >>> print users_db.user_info('someuserid')
    ... {'id': 'someuserid', 'full_name': ...}

