# HANDS-ON 1:

```
Enumerate following for the us.techcorp.local domain:
– Users
– Computers
– Domain Administrators
– Enterprise Administrators
– Kerberos Policy
```
## Index of content
  1. [Users](#users)
  2. [Computers](#computers)
  3. [Domain Administrators](#domain-administrators)
  4. [Enterprise Administrators](#enterprise-administrators)
  5. [Kerberos Policy](#kerberos-policy)


## Users

```
PS C:\AD\Tools\InviShell> Get-ADUser -Filter * | select -ExpandProperty samaccountname
Administrator
Guest
krbtgt
TECHCORP$
emptest
adconnect
mgmtadmin
helpdeskadmin
dbservice
atauser
exchangeadmin
HealthMailbox3bd1057
HealthMailboxc8de558
HealthMailbox01f72be
HealthMailbox128342c
HealthMailboxbb3d25e
HealthMailbox87cf12f
HealthMailboxd517735
HealthMailbox86956b9
HealthMailbox307c425
HealthMailbox7f97592
HealthMailboxd933b3c
exchangemanager
exchangeuser
pawadmin
jwilliams
webmaster
EU$
serviceaccount
devuser
testda
decda
appsvc
provisioningsvc
studentuser31
studentuser32
studentuser33
studentuser34
studentuser35
studentuser36
studentuser37
studentuser38
studentuser39
studentuser40
studentuser41
studentuser42
studentuser43
studentuser44
studentuser45
studentuser46
studentuser47
studentuser48
studentuser49
studentuser50
Support31user
Support32user
Support33user
Support34user
Support35user
Support36user
Support37user
Support38user
Support39user
Support40user
Support41user
Support42user
Support43user
Support44user
Support45user
Support46user
Support47user
Support48user
Support49user
Support50user

```
## Computers

```
PS C:\AD\Tools\InviShell> Get-ADComputer -FIlter * | select name, DNSHOstName

name         DNSHOstName
----         -----------
US-DC        US-DC.us.techcorp.local
US-EXCHANGE  US-Exchange.us.techcorp.local
US-MGMT      US-Mgmt.us.techcorp.local
US-HELPDESK  US-HelpDesk.us.techcorp.local
US-MSSQL     US-MSSQL.us.techcorp.local
US-MAILMGMT  US-MailMgmt.us.techcorp.local
US-JUMP      US-Jump.us.techcorp.local
US-WEB       US-Web.us.techcorp.local
US-ADCONNECT US-ADConnect.us.techcorp.local
STUDENT31    student31.us.techcorp.local
STUDENT32    student32.us.techcorp.local
STUDENT33    student33.us.techcorp.local
STUDENT34    student34.us.techcorp.local
STUDENT35    student35.us.techcorp.local
STUDENT36    student36.us.techcorp.local
STUDENT37    student37.us.techcorp.local
STUDENT38    student38.us.techcorp.local
STUDENT39    student39.us.techcorp.local
STUDENT40    student40.us.techcorp.local
STUDENT41    student41.us.techcorp.local
STUDENT42    student42.us.techcorp.local
STUDENT43    student43.us.techcorp.local
STUDENT44    student44.us.techcorp.local
STUDENT45    student45.us.techcorp.local
STUDENT46    student46.us.techcorp.local
STUDENT47    student47.us.techcorp.local
STUDENT48    student48.us.techcorp.local
STUDENT49    student49.us.techcorp.local
STUDENT50    student50.us.techcorp.local

```

## Domain Administrators

```
PS C:\AD\Tools\InviShell> Get-ADGroup -Identity 'Domain Admins' -Properties *


adminCount                      : 1
CanonicalName                   : us.techcorp.local/Users/Domain Admins
CN                              : Domain Admins
Created                         : 7/5/2019 12:49:17 AM
createTimeStamp                 : 7/5/2019 12:49:17 AM
Deleted                         :
Description                     : Designated administrators of the domain
DisplayName                     :
DistinguishedName               : CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local
dSCorePropagationData           : {7/30/2019 5:35:19 AM, 7/10/2019 9:53:40 AM, 7/10/2019 9:00:03 AM, 7/6/2019 9:11:13 PM...}
GroupCategory                   : Security
GroupScope                      : Global
groupType                       : -2147483646
HomePage                        :
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=decda,CN=Users,DC=us,DC=techcorp,DC=local, CN=Administrator,CN=Users,DC=us,DC=techcorp,DC=local}
MemberOf                        : {CN=Denied RODC Password Replication Group,CN=Users,DC=us,DC=techcorp,DC=local, CN=Administrators,CN=Builtin,DC=us,DC=techcorp,DC=local}
Members                         : {CN=decda,CN=Users,DC=us,DC=techcorp,DC=local, CN=Administrator,CN=Users,DC=us,DC=techcorp,DC=local}
Modified                        : 7/19/2019 12:16:32 PM
modifyTimeStamp                 : 7/19/2019 12:16:32 PM
Name                            : Domain Admins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=techcorp,DC=local
ObjectClass                     : group
ObjectGUID                      : 218cc77d-0e1c-41ed-91b2-730f6279c325
objectSid                       : S-1-5-21-210670787-2521448726-163245708-512
ProtectedFromAccidentalDeletion : False
SamAccountName                  : Domain Admins
sAMAccountType                  : 268435456
sDRightsEffective               : 0
SID                             : S-1-5-21-210670787-2521448726-163245708-512
SIDHistory                      : {}
uSNChanged                      : 282184
uSNCreated                      : 12315
whenChanged                     : 7/19/2019 12:16:32 PM
whenCreated                     : 7/5/2019 12:49:17 AM

```

## Enterprise Administrators

```
PS C:\AD\Tools\InviShell> Get-ADGroup -Filter * -Server techcorp.local | select name | Select-String  -Pattern "Admin"

@{name=Administrators}
@{name=Hyper-V Administrators}
@{name=Storage Replica Administrators}
@{name=Schema Admins}
@{name=Enterprise Admins}
@{name=Domain Admins}
@{name=Key Admins}
@{name=Enterprise Key Admins}
@{name=DnsAdmins}
@{name=Security Administrator}
```

```
PS C:\AD\Tools\InviShell> Get-ADGroupMember -Identity "Enterprise Admins" -Server techcorp.local


distinguishedName : CN=Administrator,CN=Users,DC=techcorp,DC=local
name              : Administrator
objectClass       : user
objectGUID        : a8ee80ca-edc5-4c5d-a210-b58ca11bd055
SamAccountName    : Administrator
SID               : S-1-5-21-2781415573-3701854478-2406986946-500
```

```
PS C:\AD\Tools\InviShell> Get-ADGroupMember -Identity "Enterprise Key Admins" -Server techcorp.local
```

## Kerberos policy

```
PS C:\AD\Tools\InviShell> Get-DomainPolicy


Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=42; MinimumPasswordLength=7; PasswordComplexity=1; PasswordHistorySize=24; LockoutBadCount=0; RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0; LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=System.Object[]; MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\us.techcorp.local\sysvol\us.techcorp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy

```

```
PS C:\AD\Tools\InviShell> Get-DomainPolicy -Server techcorp.local


Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=42; MinimumPasswordLength=7; PasswordComplexity=1; PasswordHistorySize=24; LockoutBadCount=0; RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0; LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange=System.Object[]; MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\us.techcorp.local\sysvol\us.techcorp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```
