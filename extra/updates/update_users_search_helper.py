''' add search helper to users '''
# pylint: disable=redefined-outer-name,too-many-locals
from __future__ import print_function
import subprocess
from six.moves import input
import ldap
from ldap.ldapobject import LDAPObject
from ldap.resiter import ResultProcessor
from transliterate import translit, get_available_language_codes
from unidecode import unidecode

LDAP_TIMEOUT = 10

search_users_cmd = ('ldapsearch -LLL -h {server} -s sub -D "{user_dn}" '
                    '-w {password} -x -b "{base_dn}" dn')

no_limits_user_dn = "cn=Accounts Browser,o=EIONET,l=Europe"
write_access_user_dn = "cn=Eionet Administrator,o=EIONET,l=Europe"


class StreamingLDAPObject(LDAPObject, ResultProcessor):
    """ Useful in getting more results by bypassing
        results size restrictions"""
    pass


def transliterate(first_name, last_name, full_name_native, search_helper):
    ''' transliterate unicode characters to ascii '''
    vocab = set(first_name.split(' ') + last_name.split(' ') +
                full_name_native.split(' ') + search_helper.split(' '))
    langs = get_available_language_codes()
    ascii_values = []
    translate_table = {
        0xe4: ord('a'),
        0xc4: ord('A'),
        0xf6: ord('o'),
        0xd6: ord('O'),
        0xfc: ord('u'),
        0xdc: ord('U'),
    }

    for name in vocab:
        name = name.decode('utf-8')
        ascii_values.append(unidecode(name))
        for lang in langs:
            try:
                ascii_values.append(
                    str(translit(name, lang, reversed=True)))
            except UnicodeEncodeError:
                # if we encounter other characters = other languages
                # than German
                pass
        try:
            ascii_values.append(
                str(name.replace(u'\xdf', 'ss').translate(translate_table)))
        except UnicodeEncodeError:
            # if we encounter other characters = other languages than German
            pass
    return ' '.join(sorted(set(ascii_values))).strip()


def connect(server):
    ''' create connection to server '''
    info = server.split(':')
    if len(info) == 2:
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
    ''' main method '''
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
        full_name_native = userdetails[0][1].get('displayName', '')
        if full_name_native:
            full_name_native = full_name_native[0]
        search_helper = userdetails[0][1].get('businessCategory', '')
        if search_helper:
            search_helper = search_helper[0]
        search_helper = transliterate(userdetails[0][1]['givenName'][0],
                                      userdetails[0][1]['sn'][0],
                                      full_name_native,
                                      search_helper)
        try:
            conn.modify_s(user_dn, [
                (ldap.MOD_REPLACE, 'businessCategory', search_helper)
            ])
            print('Modified user %s: %s' % (uid, search_helper))
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
