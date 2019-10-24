from __future__ import print_function
import subprocess
import ldap
from ldap.ldapobject import LDAPObject
from ldap.resiter import ResultProcessor
from six.moves import input

LDAP_TIMEOUT = 10

search_users_cmd = ('ldapsearch -LLL -h {server} -s sub -D "{user_dn}" '
                    '-w {password} -x -b "{base_dn}" dn')

no_limits_user_dn = "cn=Accounts Browser,o=EIONET,l=Europe"
write_access_user_dn = "cn=Eionet Administrator,o=EIONET,l=Europe"


class StreamingLDAPObject(LDAPObject, ResultProcessor):
    """ Useful in getting more results by bypassing
        results size restrictions"""
    pass


def connect(server):
    info = server.split(':')
    if (len(info) == 2):
        if info[1] == '389':
            server = info[0]
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    conn = StreamingLDAPObject('ldaps://' + server)
    conn.protocol_version = ldap.VERSION3
    conn.timeout = LDAP_TIMEOUT

    try:
        conn.whoami_s()
    except ldap.SERVER_DOWN:
        conn = ldap.initialize('ldap://' + server)
        conn.protocol_version = ldap.VERSION3
        conn.timeout = LDAP_TIMEOUT
        conn.whoami_s()

    return conn


def main(server, write_password, password):
    conn = connect(server)
    conn.simple_bind(write_access_user_dn, write_password)
    base_dn = "ou=Users,o=EIONET,l=Europe"

    search_cmd = search_users_cmd.format(server=server,
                                         user_dn=no_limits_user_dn,
                                         password=password, base_dn=base_dn)
    out = subprocess.Popen(search_cmd, stdout=subprocess.PIPE,
                           shell=True).stdout.read()
    dns = [l for l in out.split('\n') if l.strip()]
    dns = [dn for dn in dns if len(dn.split('uid=')) > 1]
    uids = [dn.split('uid=')[1].split(',')[0] for dn in dns]
    problem_uids = []
    modified = 0
    for uid in uids:
        userdetails = conn.search_s(base_dn, 1, filterstr="(uid=%s)" % uid)
        user_dn = 'uid=%s,%s' % (uid, base_dn)
        destinationIndicator = userdetails[0][1].get('destinationIndicator')
        reasonToCreate = userdetails[0][1].get('reasonToCreate')
        if destinationIndicator and destinationIndicator != reasonToCreate:
            destinationIndicator = destinationIndicator[0]
            try:
                conn.modify_s(user_dn,
                              [(ldap.MOD_REPLACE,
                                'reasonToCreate',
                                destinationIndicator)])
                print('Modified user %s: reasonToCreate: %s' % (
                    uid, destinationIndicator))
                modified += 1
            except ldap.UNAVAILABLE_CRITICAL_EXTENSION as e:
                problem_uids.append((uid, e))

    print('Modified %s users' % modified)
    print(problem_uids)

if __name__ == "__main__":

    server = input("Enter server address: ")
    password = input("Enter password for user '{0}': ".format(
                         no_limits_user_dn))
    write_password = input("Enter password for user '{0}': ".format(
                               write_access_user_dn))

    main(server, write_password, password)
