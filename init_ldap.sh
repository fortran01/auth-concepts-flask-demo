#!/bin/bash

# Wait for OpenLDAP server to start
echo "Waiting for OpenLDAP to start..."
sleep 10

# Add the LDIF file to the LDAP server
echo "Adding test users to LDAP..."
ldapadd -x -H ldap://openldap:389 \
    -D "cn=admin,dc=example,dc=org" \
    -w admin_password \
    -f /ldap_init.ldif

echo "LDAP initialization completed." 