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


### Execute DCSync attack to pull hashes of krbtgt
