# Content Lab8:

| computer | user |
| ------- | ------ |
| ActiveDiretory | serviceaccount |
| ActiveDiretory | appsvc |



```
  - Identify OUs where LAPS is in use and user(s) who have permission to read passwords.
  - Abuse the permissions to get the clear text password(s).
```


LAPS:

```
  - Local Administrator Password Solution provides centralized storage of local userspasswords in AD with periodic randomizing.
  - It's designed for mitigate the risk of lateral escalation on the same domain
  - Storage in clear text, transmission is encrypted with kerberos
  - COnfigruable using GPOs
  - ACLs forr eading the clear text passwords, only the Domain Admins and explicitly allowed users can read the passwords.
```

![LAPS](LAPS.png)
