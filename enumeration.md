# Enumeration Keys

## Unconstrained delegation

```
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Server us.techcorp.local
```

## Principals GMSA

```
Get-ADServiceAccount -Identity jumpone -Properties * | select samaccountname, PrincipalsAllowedToRetrieveManagedPassword
(Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
```
## Identify LAPS

```
Import-Module 'C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1'
C:\AD\Tools\Get-LAPSPermissions.ps1
Get-ADComputer -Identity us-mailmgmt -Properties * | select ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName *
```

## Service principal names

```
Get-ADUser -Identity support34user -Properties ServicePrincipalName
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server techcorp.local
```

## Principal Memberships

```
Get-ADPrincipalGroupMembership -Identity
```
## User Groups Memberships Recursive
```
function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName)
{
$groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName |
select -ExpandProperty distinguishedname)
$groups
if ($groups.count -gt 0)
{
foreach ($group in $groups)
{
Get-ADPrincipalGroupMembershipRecursive $group
}
}
}
```
## Groups Memberships
```
Get-DomainGroupMember -Identity machineadmins
```
## Interestings ACLs (PowerView)
```
Find-InterestingDomainAcl | ?{$_.IdentityReferenceName -match 'Managers'}
```
## ACLs by identity
```
Get-DomainObjectACL -Identity "Domain Admins" -ResolveGUIDs | select AceType, ActiveDirectoryRigths, ObjectDN, ObjectSID
Get-DomainObjectAcl | select -expandProperty ObjectDN  | Get-Unique | % {$_;Get-Acl AD:\$_  | select -ExpandProperty Access | ?{$_.IdentityReference -like '*Managers*'}}
```
## GPO
```
Get-DomainGPO -Properties displayname, distinguishedname
Get-DomainGPO -Properties displayname, cn
Get-DomainGPO -Identity 'StudentPolicies'
```
## GPO Local
```
Get-DomainGPOLocalGroup
```
## Domains
```
(Get-ADForest).domains
Get-ADTrust -Filter * | select source, target, direction, distinguishedname
```

## Domain OUS
```
Get-DomainOU | select displayname,distinguishedname
```

