eea.usersdb
===========
 
.. image:: https://ci.eionet.europa.eu/buildStatus/icon?job=Eionet/eea.usersdb/develop&subject=develop
  :target: https://ci.eionet.europa.eu/job/Eionet/job/eea.usersdb/job/develop/display/redirect
  :alt: Develop
.. image:: https://ci.eionet.europa.eu/buildStatus/icon?job=Eionet/eea.usersdb/master&subject=master
  :target: https://ci.eionet.europa.eu/job/Eionet/job/eea.usersdb/job/master/display/redirect
  :alt: Master
.. image:: https://img.shields.io/github/v/release/eea/eea.usersdb
  :target: https://eggrepo.eea.europa.eu/d/eea.usersdb/
  :alt: Release

Library to access the EIONET users database, stored in LDAP.

    >>> import eea.usersdb
    >>> users_db = eea.usersdb.UsersDB(ldap_server='ldap2.eionet.europa.eu')
    >>> print users_db.user_info('someuserid')
    ... {'id': 'someuserid', 'full_name': ...}

