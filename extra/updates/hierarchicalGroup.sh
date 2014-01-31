#!/bin/bash
echo -e "\nMake sure no new roles/organisations are created while you run this script\n\n"
echo -n "Input LDAP host address, containing port number: "
read server
echo "We need credentials for a user that can retrieve unlimited number \
of results and that can write in ou=Roles and ou=Organisations"
echo -n "Input user DN: "
read user
echo -n "Input user password: "
read -s pass
bucket_file="apply.ldif"
operation="changetype: modify
add: objectClass
objectClass: hierarchicalGroup"

roles=$(ldapsearch -h $server -LLL -s sub -D "$user" -w $pass -x -b ou=Roles,o=EIONET,l=Europe dn | tail -n +3)
orgs=$(ldapsearch -h $server -LLL -s sub -D "$user" -w $pass -x -b ou=Organisations,o=EIONET,l=Europe dn | tail -n +3)

> $bucket_file
echo -e "\n"
i=0
for r in $roles $orgs
do
i=$(($i+1))
if [ $(($i%100)) -eq 0 ]; then
 for x in $(seq $(($i/100)))
 do
  echo -n "#"
 done
 echo -ne "\r"
fi
was_dn=false
if [ "$r" = "dn:" ]
then
  was_dn=true
  if [ $i -ne 1 ]
  then
    echo -e "$operation""\n" >> $bucket_file
  fi
  echo -n "dn:" >> $bucket_file
else
  if [ $was_dn ]
  then
   echo " $r" >> $bucket_file
  else
   # otherwise, continuation line
   echo -ne "\n $r" >> $bucket_file
  fi
  was_dn=false
fi
done
echo -e "$operation""\n" >> $bucket_file
echo -e "\n"

ldapmodify -x -h $server -D "$user" -w $pass -f $bucket_file \
 && echo "Successfully applied $bucket_file. You can remove this file" \
 || echo "Something went wrong in ldapmodify"

