# HANDS-ON 2:

```
Enumerate following for the us.techcorp.local domain:
− Restricted Groups from GPO
− Membership of the restricted groups
− List all the OUs
− List all the computers in the Students OU.
− List the GPOs
− Enumerate GPO applied on the Students OU.
```
## Index of content

  1. [Restricted Groups](#restricted-groups)
  2. [Memberships](#memberships)
  3. [All OUs](#all-ous)
  4. [Computers student OU](#computers-student-ou)
  5. [GPOs](#gpos)
  6. [GPOs applied OU](#gpos-applied-ou)

## Restricted Groups
```
PS C:\AD\Tools\InviShell> Get-DomainGPO -Properties displayname, distinguishedname

displayname                       distinguishedname
-----------                       -----------------
Default Domain Policy             CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=us,DC=techcorp,DC=local
Default Domain Controllers Policy CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=us,DC=techcorp,DC=local
MailMgmt                          CN={7162874B-E6F0-45AD-A3BF-0858DA4FA02F},CN=Policies,CN=System,DC=us,DC=techcorp,DC=local
PAW                               CN={AFC6881A-5AB6-41D0-91C6-F2390899F102},CN=Policies,CN=System,DC=us,DC=techcorp,DC=local
Mgmt                              CN={B78BFC6B-76DB-4AA4-9CF6-26260697A8F9},CN=Policies,CN=System,DC=us,DC=techcorp,DC=local
StudentPolicies                   CN={FCE16496-C744-4E46-AC89-2D01D76EAD68},CN=Policies,CN=System,DC=us,DC=techcorp,DC=local
```

```
PS C:\AD\Tools\InviShell> Get-DomainGPOLocalGroup


GPODisplayName : Mgmt
GPOName        : {B78BFC6B-76DB-4AA4-9CF6-26260697A8F9}
GPOPath        : \\us.techcorp.local\SysVol\us.techcorp.local\Policies\{B78BFC6B-76DB-4AA4-9CF6-26260697A8F9}
GPOType        : RestrictedGroups
Filters        :
GroupName      : US\machineadmins
GroupSID       : S-1-5-21-210670787-2521448726-163245708-1118
GroupMemberOf  : {S-1-5-32-544}
GroupMembers   : {}
```
## Memberships

```
PS C:\AD\Tools\InviShell> Get-DomainGroupMember -Identity machineadmins


GroupDomain             : us.techcorp.local
GroupName               : machineadmins
GroupDistinguishedName  : CN=MachineAdmins,OU=Mgmt,DC=us,DC=techcorp,DC=local
MemberDomain            : us.techcorp.local
MemberName              : studentuser39
MemberDistinguishedName : CN=studentuser39,CN=Users,DC=us,DC=techcorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-210670787-2521448726-163245708-16109

```
## All OUs

```
PS C:\AD\Tools\InviShell> Get-DomainOU | select displayname,distinguishedname

displayname distinguishedname
----------- -----------------
            OU=Domain Controllers,DC=us,DC=techcorp,DC=local
Mgmt        OU=Mgmt,DC=us,DC=techcorp,DC=local
MailMgmt    OU=MailMgmt,DC=us,DC=techcorp,DC=local
PAW         OU=PAW,DC=us,DC=techcorp,DC=local
Students    OU=Students,DC=us,DC=techcorp,DC=local
```

## Computers student OU
```
PS C:\AD\Tools\InviShell> Get-DomainComputer -SearchBase 'OU=Students,DC=us,DC=techcorp,DC=local' | select name, dnshostname

name      dnshostname
----      -----------
STUDENT31 student31.us.techcorp.local
STUDENT32 student32.us.techcorp.local
STUDENT33 student33.us.techcorp.local
STUDENT34 student34.us.techcorp.local
STUDENT35 student35.us.techcorp.local
STUDENT36 student36.us.techcorp.local
STUDENT37 student37.us.techcorp.local
STUDENT38 student38.us.techcorp.local
STUDENT39 student39.us.techcorp.local
STUDENT40 student40.us.techcorp.local
STUDENT41 student41.us.techcorp.local
STUDENT42 student42.us.techcorp.local
STUDENT43 student43.us.techcorp.local
STUDENT44 student44.us.techcorp.local
STUDENT45 student45.us.techcorp.local
STUDENT46 student46.us.techcorp.local
STUDENT47 student47.us.techcorp.local
STUDENT48 student48.us.techcorp.local
STUDENT49 student49.us.techcorp.local
STUDENT50 student50.us.techcorp.local
```
## GPOs
```
PS C:\AD\Tools\InviShell> Get-DomainGPO -Properties displayname, cn

displayname                       cn
-----------                       --
Default Domain Policy             {31B2F340-016D-11D2-945F-00C04FB984F9}
Default Domain Controllers Policy {6AC1786C-016F-11D2-945F-00C04fB984F9}
MailMgmt                          {7162874B-E6F0-45AD-A3BF-0858DA4FA02F}
PAW                               {AFC6881A-5AB6-41D0-91C6-F2390899F102}
Mgmt                              {B78BFC6B-76DB-4AA4-9CF6-26260697A8F9}
StudentPolicies                   {FCE16496-C744-4E46-AC89-2D01D76EAD68}
```
## GPOs applied OU

```
PS C:\AD\Tools\InviShell> Get-DomainGPO -Identity 'StudentPolicies'


usncreated               : 330304
displayname              : StudentPolicies
gpcmachineextensionnames : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]
whenchanged              : 7/20/2019 2:17:57 PM
objectclass              : {top, container, groupPolicyContainer}
gpcfunctionalityversion  : 2
showinadvancedviewonly   : True
usnchanged               : 338463
dscorepropagationdata    : {7/30/2019 12:35:19 PM, 1/1/1601 12:00:00 AM}
name                     : {FCE16496-C744-4E46-AC89-2D01D76EAD68}
flags                    : 0
cn                       : {FCE16496-C744-4E46-AC89-2D01D76EAD68}
gpcfilesyspath           : \\us.techcorp.local\SysVol\us.techcorp.local\Policies\{FCE16496-C744-4E46-AC89-2D01D76EAD68}
distinguishedname        : CN={FCE16496-C744-4E46-AC89-2D01D76EAD68},CN=Policies,CN=System,DC=us,DC=techcorp,DC=local
whencreated              : 7/20/2019 11:48:51 AM
versionnumber            : 4
instancetype             : 4
objectguid               : b9bb82a1-5cc2-4264-b4f4-bdf6a238817b
objectcategory           : CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=techcorp,DC=local
```
