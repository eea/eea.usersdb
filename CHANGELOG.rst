1.2.1-ispra (unreleased)
------------------------

1.2.0-ispra (2021-11-23)
------------------------
* compatibility with new colander [dumitval]
* update for creating users in custom RDN setup [simiamih]

1.1.1 (2012-08-29)
--------------------
* new method: `set_role_description` [simiamih]

1.1.0 (2012-07-19)
--------------------
* _user_id and _user_dn do not assume uid is in dn [simiamih]
* introduced new config: users_rdn [simiamih]
* removed attr-s of roles passed to _user_id [simiamih]

1.0.7 (2012-07-03)
--------------------
* Updated db_agent to support different LDAP schemas in search and other
  operations [bogdatan]

1.0.6 (2012-06-06)
--------------------
* search_user accepts lookup selectors [bogdatan]

1.0.5 (2012-06-01)
--------------------
* added members_in_role_and_subroles [simiamih]
* new fix for compatibility with python-ldap 2.4.9 [simiamih]

1.0.4 (2012-05-22)
--------------------
* compatibility with python-ldap 2.4.9 [simiamih]

1.0.3 (2012-05-10)
--------------------
* case insensitive assertion for ldap role results [simiamih]
* creating role adds mailingListGroup objectClass, owner and permittedSender
  attributes [simiamih]

1.0.2 (2012-02-10)
--------------------
* member removal methods: rm from roles, organisations, rm user [simiamih]
* bulk methods: check emails and usernames for existence in db [simiamih]
* more options for filter_roles: filterstr and attrlist [simiamih]
* fix: removing user from role also removes him from ancestor roles that
  do not have subroles containing user [simiamih]

1.0.1 (2011-04-06)
--------------------
* Backport to Python 2.4 [moregale]

1.0 (2011-03-07)
--------------------
* Initial version [moregale]
