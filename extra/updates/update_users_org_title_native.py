import subprocess
import ldap
from ldap.ldapobject import LDAPObject
from ldap.resiter import ResultProcessor

LDAP_TIMEOUT = 10

search_orgs_cmd = ('ldapsearch -LLL -h {server} -s sub -D "{user_dn}" '
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
    base_dn = "ou=Organisations,o=EIONET,l=Europe"

    search_cmd = search_orgs_cmd.format(server=server,
                                        user_dn=no_limits_user_dn,
                                        password=password, base_dn=base_dn)
    out = subprocess.Popen(search_cmd, stdout=subprocess.PIPE,
                           shell=True).stdout.read()
    dns = [l for l in out.split('\n') if l.strip()]
    dns = [dn for dn in dns if len(dn.split('cn=')) > 1]
    oids = [dn.split('cn=')[1].split(',')[0] for dn in dns]
    problem_oids = []
    modified = 0
    for oid in oids:
        orgdetails = conn.search_s(base_dn, 1, filterstr="(cn=%s)" % oid)
        org_dn = 'cn=%s,%s' % (oid, base_dn)
        org_title_native = orgdetails[0][1].get('physicalDeliveryOfficeName',
                                                '')
        if org_title_native:
            org_title_native = org_title_native[0]
        if org_title_native:
            continue
        org_title = orgdetails[0][1].get('o', '')
        if org_title:
            org_title = org_title[0]
        try:
            conn.modify_s(org_dn, [
                (ldap.MOD_REPLACE, 'physicalDeliveryOfficeName', org_title)
                ])
            print 'Modified organisation %s: %s' % (oid, org_title)
            modified += 1
        except ldap.UNAVAILABLE_CRITICAL_EXTENSION, e:
            problem_oids.append((oid, e))

    print 'Modified %s users' % modified
    print problem_oids

if __name__ == "__main__":

    server = raw_input("Enter server address: ")
    password = raw_input("Enter password for user '{0}': ".format(
                         no_limits_user_dn))
    write_password = raw_input("Enter password for user '{0}': ".format(
                               write_access_user_dn))

    main(server, write_password, password)
