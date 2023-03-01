# Hands-ON 22:
```
Find a service account in the eu.local forest and Kerberoast its password.
```

## Index Of Content:
  1. [Find service accounts](#find-service-accounts)  

## Find service accounts


```
 Get-ADTrust -Filter 'IntraForest -ne $true' | %{Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName -Server $_.Name}


DistinguishedName    : CN=krbtgt,CN=Users,DC=eu,DC=local
Enabled              : False
GivenName            :
Name                 : krbtgt
ObjectClass          : user
ObjectGUID           : a36265f2-2db1-4555-acc2-e9736fc1b6f6
SamAccountName       : krbtgt
ServicePrincipalName : {kadmin/changepw}
SID                  : S-1-5-21-3657428294-2017276338-1274645009-502
Surname              :
UserPrincipalName    :

DistinguishedName    : CN=storagesvc,CN=Users,DC=eu,DC=local
Enabled              : True
GivenName            : storage
Name                 : storagesvc
ObjectClass          : user
ObjectGUID           : 041fedb0-a442-4cdf-af34-6559480a2d74
SamAccountName       : storagesvc
ServicePrincipalName : {MSSQLSvc/eu-file.eu.local}
SID                  : S-1-5-21-3657428294-2017276338-1274645009-1106
Surname              : svc
UserPrincipalName    : storagesvc

```

