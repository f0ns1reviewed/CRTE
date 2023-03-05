# Content Lab7:

In this lab the attacker should detect, undertand and abusse permissions of LAPS 
```
  - Determine if studentuserx has permissions to set UserAccountControl flags for any user.
  - If yes, force set a SPN on the user and obtain a TGS for the user
```

| computer | user |
| ------- | ------ |
| ActiveDiretory | supportxuser |

Enumerate ACLs :
```
  - Find permissions for modifiate support users
  - Set Spn for user
```

Perform a kerberoast attack over the target modified user:

[kerberoast](content_lab6.md)




