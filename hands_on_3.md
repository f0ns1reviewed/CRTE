# HANDS ON 3:

```
Enumerate following for the us.techcorp.local domain:
− ACL for the Domain Admins group
− All modify rights/permissions for the studentuserx
```
## Index of content
    
   1.[ACL Domain Admin](#acl-domain-admin)
   
   2.[Permissions studentusers](#permissions-studentusers)
  
## ACL Domain Admin

```
PS C:\AD\Tools\InviShell> Get-DomainObjectACL -Identity "Domain Admins" -ResolveGUIDs | select AceType, ActiveDirectoryRigths, ObjectDN, ObjectSID

            AceType ActiveDirectoryRigths ObjectDN                                             ObjectSID
            ------- --------------------- --------                                             ---------
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
AccessAllowedObject                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
      AccessAllowed                       CN=Domain Admins,CN=Users,DC=us,DC=techcorp,DC=local S-1-5-21-210670787-2521448726-163245708-512
```

## Permissions studentusers

```
PS C:\AD\Tools\InviShell> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentuser34"}
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distingui
shedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distingui
shedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distingui
shedname with Convert-ADName
```
```
PS C:\AD\Tools\BloodHound-win32-x64\BloodHound-win32-x64>  Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "StudentUsers"}
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distinguishedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distinguishedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distinguishedname with Convert-ADName


ObjectDN                : CN=Support48User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support49User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support50User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support31User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support32User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support33User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support34User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support35User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support36User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support37User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support38User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support39User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support40User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support41User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support42User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support43User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support44User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support45User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support46User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Support47User,CN=Users,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : OU=MailMgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, ExtendedRight
ObjectAceType           : ms-Mcs-AdmPwd
AceFlags                : ContainerInherit, InheritOnly
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=US-MAILMGMT,OU=MailMgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, ExtendedRight
ObjectAceType           : ms-Mcs-AdmPwd
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Windows Virtual Machine,CN=US-MAILMGMT,OU=MailMgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, ExtendedRight
ObjectAceType           : ms-Mcs-AdmPwd
AceFlags                : ContainerInherit, InheritOnly, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1116
IdentityReferenceName   : studentusers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group


```
