#Version 0.2 - Manuel Michalski
#Last Update: 27. Oktober 2022
#Description: Deactivate RemotePowerShell for all except exclude list
#CVE-2022-41082
#Link: https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/

### Load Exchange Module ###
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

### Get the users with Remote Powershell enabled ###
$all_users = Get-User -ResultSize Unlimited -Filter 'RemotePowerShellEnabled -eq $true' | select -exp SamAccountName

### excluded the chosen ones ###
# Exclude administrator and sampleuser1
$exclude_list = $all_users -match '^administrator$|^sampleuser1$'

### Create result ###
$result = Compare-Object -ReferenceObject $all_users -DifferenceObject $exclude_list -PassThru

### Deactivate ###  
foreach($user in $result){
Set-User $user -RemotePowershellEnabled $false
}

#Activate Single Users
#1. Add User to the exclude list
#2. Activate users:
#Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
#Set-User $user -RemotePowershellEnabled $false
