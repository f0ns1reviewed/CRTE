# HANDS ON 4:

```
Enumerate all domains in the techcorp.local forest.
- Map the trusts of the us.techcorp.local domain.
- Map external trusts in techcorp.local forest.
- Identify external trusts of us domain. Can you enumerate trusts for a trusting forest?

```
## Index of content

  1. [Enumerate All Domains](#enumerate-all-domains)
  2. [Trust of us techcorp local](#trust-of-us-techcorp-local)
  3. [External trust of techcorp local](#external-trust-of-techcorp-local)
  4. [Identify external trust of us](#identify-external-trust-of-us)

## Enumerate All Domains
```
PS C:\AD\Tools\InviShell> (Get-ADForest).domains
techcorp.local
us.techcorp.local
```
## Trust of us techcorp local
```
PS C:\AD\Tools\InviShell> Get-ADTrust -Filter * | select source, target, direction, distinguishedname

source                     target             direction distinguishedname
------                     ------             --------- -----------------
DC=us,DC=techcorp,DC=local techcorp.local BiDirectional CN=techcorp.local,CN=System,DC=us,DC=techcorp,DC=local
DC=us,DC=techcorp,DC=local eu.local       BiDirectional CN=eu.local,CN=System,DC=us,DC=techcorp,DC=local
```
## External trust of techcorp local
```
PS C:\AD\Tools\InviShell> Get-ADTrust -Filter 'intraFOrest -ne $True' -Server (Get-ADForest).name | select source, targe
t, name, Direction

source               target         name               Direction
------               ------         ----               ---------
DC=techcorp,DC=local usvendor.local usvendor.local BiDirectional
DC=techcorp,DC=local bastion.local  bastion.local        Inbound
```

## Identify external trust of us
```
PS C:\AD\Tools\InviShell> (Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True -and ForestTransitive -
ne $TRUE)' -Server $_}


Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=eu.local,CN=System,DC=us,DC=techcorp,DC=local
ForestTransitive        : False
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : eu.local
ObjectClass             : trustedDomain
ObjectGUID              : 917942a6-ef2d-4c87-8084-35ad6281c89b
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : True
Source                  : DC=us,DC=techcorp,DC=local
Target                  : eu.local
TGTDelegation           : False
TrustAttributes         : 4
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

```

```
PS C:\AD\Tools\InviShell> (Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True -and ForestTransitive -ne $TRUE)' -Server $_} | select source, target, Direction

source                     target       Direction
------                     ------       ---------
DC=us,DC=techcorp,DC=local eu.local BiDirectional
```
