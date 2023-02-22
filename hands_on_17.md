# Hands-On 17:

## Index Of content:

  1.[]()
  2.[]()
  
## Cerity:

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>C:\AD\Tools\Certify.exe cas

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate authorities
[*] Using the search base 'CN=Configuration,DC=techcorp,DC=local'


[*] Root CAs

    Cert SubjectName              : CN=TECHCORP-DC-CA, DC=techcorp, DC=local
    Cert Thumbprint               : F95C7E9F28F50C87F309A6EFB2CB3AEB0B2FAC86
    Cert Serial                   : 4F3F87A449C15587446B046111AA6313
    Cert Start Date               : 7/12/2019 12:02:05 AM
    Cert End Date                 : 7/12/2024 12:12:04 AM
    Cert Chain                    : CN=TECHCORP-DC-CA,DC=techcorp,DC=local



[*] NTAuthCertificates - Certificates that enable authentication:

    Cert SubjectName              : CN=TECHCORP-DC-CA, DC=techcorp, DC=local
    Cert Thumbprint               : F95C7E9F28F50C87F309A6EFB2CB3AEB0B2FAC86
    Cert Serial                   : 4F3F87A449C15587446B046111AA6313
    Cert Start Date               : 7/12/2019 12:02:05 AM
    Cert End Date                 : 7/12/2024 12:12:04 AM
    Cert Chain                    : CN=TECHCORP-DC-CA,DC=techcorp,DC=local


[*] Enterprise/Enrollment CAs:

    Enterprise CA Name            : TECHCORP-DC-CA
    DNS Hostname                  : Techcorp-DC.techcorp.local
    FullName                      : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=TECHCORP-DC-CA, DC=techcorp, DC=local
    Cert Thumbprint               : F95C7E9F28F50C87F309A6EFB2CB3AEB0B2FAC86
    Cert Serial                   : 4F3F87A449C15587446B046111AA6313
    Cert Start Date               : 7/12/2019 12:02:05 AM
    Cert End Date                 : 7/12/2024 12:12:04 AM
    Cert Chain                    : CN=TECHCORP-DC-CA,DC=techcorp,DC=local
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
      Allow  ManageCA, ManageCertificates               TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
    Enrollment Agent Restrictions : None

    Enabled Certificate Templates:
        ForAdminsofPrivilegedAccessWorkstations
        Users
        WDAC
        DirectoryEmailReplication
        DomainControllerAuthentication
        KerberosAuthentication
        EFSRecovery
        EFS
        DomainController
        WebServer
        Machine
        User
        SubCA
        Administrator





Certify completed in 00:00:18.7932429

```
