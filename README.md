# gMSADumper

## Description

Reads any gMSA password blobs the user can access and parses the values.

## Usage
Basic:

`$ python3 gMSADumper.py -u user -p password -d domain.local`

Pass the Hash, specific LDAP server:

`$ python gMSADumper.py -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc01.domain.local`

## Previous Work and Acknowledgements
Impacket for parsing the gMSA blob and some code from https://github.com/n00py/LAPSDumper/
