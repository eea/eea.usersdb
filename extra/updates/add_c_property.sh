#!/bin/bash
echo -n "Input LDAP host address, containing port number: "
read server
echo "We need credentials for a user that can retrieve unlimited number \
of results and that can write in ou=Organisations"
echo -n "Input user DN: "
read user
echo -n "Input user password: "
read -s pass
bucket_file="apply.ldif"
operation="changetype: modify
add: c
c: "

orgs=$(ldapsearch -h $server -LLL -s sub -D "$user" -w $pass -x -b ou=Organisations,o=EIONET,l=Europe dn | grep "^dn:" | tail -n +2)
> $bucket_file
echo -e "\n"
i=0
OLDIFS=$IFS
IFS=$'\n'
for r in $orgs
do
i=$(($i+1))
if [ $(($i%10)) -eq 0 ]; then
 for x in $(seq $(($i/10)))
 do
  echo -n "#"
 done
 echo -ne "\r"
fi
echo "$r" >> $bucket_file
echo -n "$operation" >> $bucket_file
echo "${r:7:2}" >> $bucket_file
echo -e "\n" >> $bucket_file
done
IFS=$OLDIFS
ldapmodify -x -h $server -D "$user" -w $pass -f $bucket_file \
 && echo "Successfully applied $bucket_file. You can remove this file" \
 || echo "Something went wrong in ldapmodify"

