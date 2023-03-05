# Content Lab11:

| computer | user |
| ------- | ------ |
| xxxx | xxxx |
| xxxx | xxxxx |

![Unconstrained Delegation](unconstrained_delegation.png)

The attacker should abusse and understand Kerberos Delegation (Unconstrained):
```
  - Find a server in US domain where Unconstrained Delegation is enabled.
  - Compromise that server and get Domain Admin privileges.
```

1. A user provides credentials to the Domain Controller.
2. The DC returns a TGT
3. The user request a TGS for the web servide on Web Server
4. The DC provides TGS
5. The user sends the TGT and TGS to the web server.
6. The web server service TGT and TGS to the web server
7. The web server service account use the user's TGT to request a TGS for the database server from the DC
8. The web server service account connects to the database server as the user.




