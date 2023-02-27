# Hands-On 19:

```
Find out the machine where Azure AD Connect is installed.
Compromise the machine and extract the password of AD Connect user in clear-text.
Using the AD Connect user's password, extract secrets from us-dc and techcorp-dc.
```

## Index Of Content:

  1. [Find Machine Azure AD](#find-machine-azure-ad)
  2. [Compromise machine](#compromise-machine)
  3. [Extract secrets](#extract-secrets)

## Find Machine Azure AD

```
PS C:\Users\studentuser17> Get-ADUser -Filter "SamAccountName -like '*'" -Server techcorp.local -Properties *| select  SamAccountName, Description | fl


SamAccountName : Administrator
Description    : Built-in account for administering the computer/domain

SamAccountName : Guest
Description    : Built-in account for guest access to the computer/domain

SamAccountName : krbtgt
Description    : Key Distribution Center Service Account

SamAccountName : US$
Description    :

SamAccountName : MSOL_16fb75d0227d
Description    : Account created by Microsoft Azure Active Directory Connect with installation identifier 16fb75d0227d4957868d5c4ae0688943 running on computer US-ADCONNECT configured to synchronize to tenant
                 techcorpus.onmicrosoft.com. This account must have directory replication permissions in the local Active Directory and write permission on certain attributes to enable Hybrid Deployment.

SamAccountName : $431000-R3GTAO0291F9
Description    :

SamAccountName : SM_6fcd6ac55a6146a0a
Description    :

SamAccountName : SM_154a18cd4a8e48f09
Description    :

SamAccountName : SM_01a48ed0a28c423d9
Description    :

SamAccountName : SM_37c4dd3af61044398
Description    :

SamAccountName : SM_8b0a3d48bd2541249
Description    :

SamAccountName : SM_8bf409db7e874ebe9
Description    :

SamAccountName : SM_73d4ee9dc8674c898
Description    :

SamAccountName : SM_eca5036b49c740608
Description    :

SamAccountName : SM_309ad2430f0b4251b
Description    :

SamAccountName : USVENDOR$
Description    :

SamAccountName : BASTION$
Description    :

SamAccountName : privuser
Description    :

SamAccountName : testuser
Description    :

```

## Compromise machine

```
```

## Extract secrets

```
```

