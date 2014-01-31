#!/bin/bash
#  !!! REQUIRES ldap-utils debian package (for ldapsearch)
# adapted from https://svn.eionet.europa.eu/projects/Zope/ticket/5215#comment:4

#AFTER_YESTERDAY=$(date -d "yesterday" +%Y%m%d235959Z)
AFTER_YESTERDAY=$(date +%Y%m%d%h0000Z)
BEFORE_YESTERDAY=$(date -d "yesterday" +%Y%m%d000000Z)
LDAP_CNT=$(ldapsearch -v -h ldap.eionet.europa.eu -x -b o=EIONET,l=Europe "(&(modifyTimestamp>="$BEFORE_YESTERDAY")(modifyTimestamp<="$AFTER_YESTERDAY"))" 2>&1 | grep numResponses | cut -d ' ' -f 3)
LDAP_CNT2=$(ldapsearch -v -h ldap2.eionet.europa.eu -x -b o=EIONET,l=Europe "(&(modifyTimestamp>="$BEFORE_YESTERDAY")(modifyTimestamp<="$AFTER_YESTERDAY"))" 2>&1 | grep numResponses | cut -d ' ' -f 3)
LDAP_CNT3=$(ldapsearch -v -h ldap3.eionet.europa.eu -x -b o=EIONET,l=Europe "(&(modifyTimestamp>="$BEFORE_YESTERDAY")(modifyTimestamp<="$AFTER_YESTERDAY"))" 2>&1 | grep numResponses | cut -d ' ' -f 3)

echo "====== LDAP1: ======"
echo "$LDAP_CNT"
echo "===================="

echo "====== LDAP2: ======"
echo "$LDAP_CNT2"
echo "===================="

echo "====== LDAP3: ======"
echo "$LDAP_CNT3"
echo "===================="

test "$LDAP_CNT" = "$LDAP_CNT2" || exit 1
test "$LDAP_CNT2" = "$LDAP_CNT3" || exit 1
