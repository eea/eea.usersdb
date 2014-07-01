1.3.13 (unreleased)
------------------------

1.3.12 (2014-07-01)
------------------------
* Feature: added the org_exists API method to avoid clogging logs with
  tracebacks from LDAP server
  [tiberich #19143]

1.3.11 (2014-06-26)
------------------------
* Feature: added the possibilty to perform merge roles, prefill roles
  [tiberich #20140]

1.3.10 (2014-03-12)
------------------------
* Feature: added support for pending membership to organisations
  [tiberich #15263]
* Bug fix: properly parse timestamps when format contains microseconds
  [tiberich #18676]
* Feature: allow using streaming methods to get the results from ldap,
  for large result sets
  [tiberich #18676]

1.3.9 (2014-02-03)
------------------------
* Change: avoid dependency on Zope's DateTime, use datetime instead
  [tiberich, alex morega]

1.3.8 (2013-12-04)
------------------------
* Bug fix: permitted senders are not users, don't try to save changelog for them
[tiberich #17608]
* PEP8 the db_agent.py module
[tiberich]

1.3.7 (2013-12-03)
------------------------
* Bug fix: fixed adding/edditing permitted sender
  [tiberich #17608]

1.3.6 (2013-11-21)
------------------------
* allow single quotes (') in user's email address [dumitval]
* Feature: Added a method to retrieve all user information from ldap sql data dump
  [tiberich #16665]
* Feature: added the email/mail field to the EIONET organisation schema
  [tiberich #17369]

1.3.5 (23-10-2013)
--------------------
* Allow enable/disable of users
  [tiberich #17085]

1.3.4 (2013-10-10)
--------------------
* Allow removing inexisting ldap users from ldap roles (cleanup) [dumitval]

1.3.3 (2013-09-05)
--------------------
* #15628; changed output of all_organisations [simiamih]

1.3.2 (2013-08-06)
--------------------
* using "c" for country of organisations [simiamih]

1.3.1 (2013-06-17)
--------------------
* #14597; method to unset/rm role leader [simiamih]

1.3.0 (2013-02-21)
--------------------
* #10163; using phonenumbers lib to validate phone numbers [simiamih]
* #9181: complete agent API to return info for multiple uids [mihaitab]
* #9994 adding/removing owner for a role propagates to subroles [simiamih]
* #9181 duplicate emails no longer allowed for users [simiamih]
* getcertificate; may be used in profile page #13772 [simiamih]
* #9231 implements hierarchicalGroup for roles [simiamih]

1.2.2 (2012-11-30)
--------------------
* new method: `members_in_subroles_with_source` [simiamih]

1.2.1 (2012-11-12)
--------------------
* `uid` is not editable, keep it as operational attr [simiamih]

1.2.0 (2012-11-09)
--------------------
* including some operational ldap attrs in user info unpack [simiamih]
* added factories module [simiamih]
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
