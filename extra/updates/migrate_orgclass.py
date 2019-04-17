#!/usr/bin/python2.7

import subprocess

search_orgs_cmd = 'ldapsearch -LLL -h {server} -s sub -D "{user_dn}" '\
    '-w {password} -x -b {base_dn} dn'
modify_cmd = 'ldapmodify -x -c -h {server} -D "{user_dn}" -w {password}'\
    ' -f /tmp/out.ldiff'

operation = """{dn}
changetype: modify
add: objectClass
objectClass: eionetOrganisation

"""

no_limits_user_dn = "cn=Accounts Browser,o=EIONET,l=Europe"
write_access_user_dn = "cn=Eionet Administrator,o=EIONET,l=Europe"
server = 'ldap.eionet.europa.eu'


def main(server, write_password, password):
    base_dn = "ou=Organisations,o=EIONET,l=Europe"

    search_cmd = search_orgs_cmd.format(
        server=server, user_dn=no_limits_user_dn, password=password,
        base_dn=base_dn)
    out = subprocess.Popen(
        search_cmd, stdout=subprocess.PIPE, shell=True).stdout.read()
    dns = [l for l in out.split('\n') if l.strip()]

    with open("/tmp/out.ldiff", "w") as outf:
        for dn in dns:
            if "cn=" not in dn:
                continue
            s = operation.format(dn=dn)
            outf.write(s)

    cmd = modify_cmd.format(server=server, user_dn=write_access_user_dn,
                            password=write_password)
    subprocess.Popen(cmd, shell=True)   # , stdout=subprocess.PIPE, shell=True)


if __name__ == "__main__":
    # import sys
    # import argparse
    # parser = argparse.ArgumentParser(description='Migrate the LDAP server')

    # parser.add_argument('--server', type=str,
    #                 help='LDAP Server Address')
    # parser.add_argument('--user_dn', type=str,
    #                 help='DN for login user')

    # args = parser.parse_args()
    # if not (args.server and args.user_dn):
    #     parser.print_help()
    #     sys.exit(1)

    # server = args.server
    # user_dn = args.user_dn

    password = raw_input(
        "Enter password for user '{}': ".format(no_limits_user_dn))
    write_password = raw_input(
        "Enter password for user '{}': ".format(write_access_user_dn))

    main(server, write_password, password)
