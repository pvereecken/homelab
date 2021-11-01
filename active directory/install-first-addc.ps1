# Prerequisites:
# - Clean Windows Server (VM) deployed with IP configuration

# This script remotely connects to the desired server and installs:
# - The first Active Directory Domain Controller
# - DNS Server + Forward Zone(s), PTR Zone(s) and Forwarder(s)
# - DHCP Server + scopes you define
# - GPOs for NTP servers on PDC and non-PDC
#
#############################################
# Import Modules
#############################################
Function Enable-Modules
{
Import-Module .\modules\vm-deployment.psm1
}
Enable-Modules
#############################################
# VM variables
#############################################
$VM_IP = "10.24.10.2" # IP of new domain controller
$SDDC_SubnetID = "24" # as in 10.24.x.x
$SDDC_InfraID = "10" # as in 10.24.10.x
$SDDC_MgmtID = "20" # as in 10.24.20.x
$SDDC_DomainName = "" # as in domain.sddc.com
$AD_SafeMode_PWD = "" # Active Directory safemode password

$AD_User_Domain_Admin = "adm-domainadmin"
$AD_User_Domain_User = "user"

$AD_DomainUser = $SDDC_DomainName.Split(".")[0] + "\" + $AD_User_Domain_Admin
$Creds_AD_User1 = Get-Credential -Message "Enter AD credentials for Domain Admin "$AD_DomainUser""

$AD_DomainUser = $SDDC_DomainName.Split(".")[0] + "\" + $AD_User_Domain_User
#Write-host "Enter AD credentials for $AD_DomainUser"
$Creds_AD_User2 = Get-Credential -Message "Enter AD credentials for Domain User "$AD_DomainUser""

#############################################
# INSTALL AD, DNS, DHCP
#############################################
# Connect to VM with local admin/pwd
$PSSession = PSConnect-Workgroup $VM_IP

# Install AD, DNS
Invoke-Command -Session $PSSession -ScriptBlock {
    # Start logging
    Start-Transcript -Path "C:\install\1-install-active-directory.txt"
        
    # Install Active Directory
    Write-Host -ForegroundColor Yellow "[AD] Installing Domain Services ..."
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Verbose
    
    # Install root domain
    Write-Host -ForegroundColor Yellow "[AD] Installing ADDSForest, DNS ..."
    [SecureString]$sec_AD_SafeMode_PWD = $Using:AD_SafeMode_PWD | ConvertTo-SecureString -AsPlainText -Force;
    Install-ADDSForest -DomainName $Using:SDDC_DomainName -SafeModeAdministratorPassword $sec_AD_SafeMode_PWD -InstallDns -NoRebootOnCompletion -Confirm:$false
    
    # Reboot
    Restart-Computer -Force -Confirm:$false
}
My-Logger "Rebooting ..."
Start-sleep 60

# Connect to VM with domain admin/pwd
$PSSession = PSConnect-AD $VM_IP

Invoke-Command -Session $PSSession -ScriptBlock {
    # Start logging
    Start-Transcript -Path "C:\install\2-configure-active-directory.txt" -Append

    # Check DNS Primary Zone
    $check_DNS_FW_Zone = Get-DnsServerZone -Name $Using:SDDC_DomainName
    if((($check_DNS_FW_Zone.ZoneName) -eq $Using:SDDC_DomainName) -and (($check_DNS_FW_Zone.ZoneType) -eq "Primary")){
        Write-Host -ForegroundColor Green "[DNS] Primary Zone $Using:SDDC_DomainName EXISTS"
    }
    elseif($check_DNS_FW_Zone -eq $null){
        Write-Host -ForegroundColor Red "[DNS] Primary Zone ERROR"
    }

    # Add Domain Admin
    $AD_Domain_User_Username = ($Using:Creds_AD_User1.UserName).Split("\")[1]
    $AD_Domain_User_Password = $Using:Creds_AD_User1.Password

    #[SecureString]$secureString = $AD_Domain_Admin_PWD | ConvertTo-SecureString -AsPlainText -Force 
    New-ADUser -Name $AD_Domain_User_Username -AccountPassword $AD_Domain_User_Password -PassThru -PasswordNeverExpires:$true -ChangePasswordAtLogon:$false -Verbose | Enable-ADAccount -Verbose
    
    # Add user to Domain Admins group
    Add-ADGroupMember -Identity "Domain Admins" -Members $AD_Domain_User_Username -Verbose

    # Check new Domain User
    $AD_newuser = $AD_Domain_User_Username
    $check_AD_User = Get-ADUser -Filter 'sAMAccountName -eq $AD_newuser'
    if(($check_AD_User.Name -eq $AD_Domain_User_Username) -and (($check_AD_User.Enabled) -eq "True")){
        Write-Host -ForegroundColor Green "[AD] Domain Admin: $AD_Domain_User_Username ADDED"
    }
    else{
        Write-Host -ForegroundColor Red "[AD] Domain Admin: $AD_Domain_User_Username FAILED TO ADD"
    }

    # Check if added to Domain Admins group
    $check_AD_Group = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select -ExpandProperty SamAccountName
    if ($check_AD_Group -contains $AD_Domain_User_Username) {
        Write-Host -ForegroundColor Green "[AD] Domain Admin: $AD_Domain_User_Username is a member of Domain Admins"
    } 
    else {
        Write-Host -ForegroundColor Red "[AD] Domain Admin: $AD_Domain_User_Username is not a member of Domain Admins"
    }

    # Add Domain User
    $AD_Domain_User_Username = ($Using:Creds_AD_User2.UserName).Split("\")[1]
    $AD_Domain_User_Password = $Using:Creds_AD_User2.Password

    #[SecureString]$secureString = $AD_Domain_Admin_PWD | ConvertTo-SecureString -AsPlainText -Force 
    New-ADUser -Name $AD_Domain_User_Username -AccountPassword $AD_Domain_User_Password -PassThru -PasswordNeverExpires:$true -ChangePasswordAtLogon:$false -Verbose | Enable-ADAccount -Verbose

    # Check new Domain User
    $AD_newuser = $AD_Domain_User_Username
    $check_AD_User = Get-ADUser -Filter 'sAMAccountName -eq $AD_newuser'
    if(($check_AD_User.Name -eq $AD_Domain_User_Username) -and (($check_AD_User.Enabled) -eq "True")){
        Write-Host -ForegroundColor Green "[AD] Domain User: $AD_Domain_User_Username ADDED"
    }
    else{
        Write-Host -ForegroundColor Red "[AD] Domain User: $AD_Domain_User_Username FAILED TO ADD"
    }

    # Add DNS PTR Zone: INFRA
    Add-DnsServerPrimaryZone -NetworkID ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".0/24") -ZoneFile ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".in-addr.arpa.dns") -Verbose

    # Check DNS PTR Zone: INFRA
    $check_DNS_PTR_Zone = Get-DnsServerZone -Name ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa")
    if((($check_DNS_PTR_Zone.ZoneName) -eq ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa")) -and (($check_DNS_PTR_Zone.IsReverseLookupZone) -eq "True")){
        Write-Host -ForegroundColor Green "[DNS] PTR Zone: $Using:SDDC_InfraID.$Using:SDDC_SubnetID.10.in-addr.arpa (INFRA) ADDED"
    }
    else{
        Write-Host -ForegroundColor Red "[DNS] PTR Zone: $Using:SDDC_InfraID.$Using:SDDC_SubnetID.10.in-addr.arpa (INFRA) FAILED TO ADD"
    }

    # Add DNS PTR Zone: MGMT
    Add-DnsServerPrimaryZone -NetworkID ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".0/24") -ZoneFile ($Using:SDDC_MgmtID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa.dns”) -Verbose

    # Check DNS PTR Zone: MGMT
    $check_DNS_PTR_Zone = Get-DnsServerZone -Name ($Using:SDDC_MgmtID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa")
    if((($check_DNS_PTR_Zone.ZoneName) -eq ($Using:SDDC_MgmtID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa")) -and (($check_DNS_PTR_Zone.IsReverseLookupZone) -eq "True")){
        Write-Host -ForegroundColor Green "[DNS] PTR Zone: $Using:SDDC_MgmtID + "." + $Using:SDDC_SubnetID.10.in-addr.arpa (MGMT) ADDED"
    }
    elseif($check_DNS_PTR_Zone -eq $null){
        Write-Host -ForegroundColor Red "[DNS] PTR Zone: ($Using:SDDC_MgmtID + "." + $Using:SDDC_SubnetID.10.in-addr.arpa) (MGMT) FAILED TO ADD"
    }

    # Add DNS Forwarders
    Add-DnsServerForwarder -IPAddress 192.168.1.84 -Verbose
    Add-DnsServerForwarder -IPAddress 192.168.1.88 -Verbose

    # Check DNS Forwarders
    $check_DNS_Forwarders = Get-DnsServerForwarder
    if((($check_DNS_Forwarders.IPAddress) -contains "192.168.1.84") -and (($check_DNS_Forwarders.IPAddress) -contains "192.168.1.88")){
        Write-Host -ForegroundColor Green "[DNS] Forwarders: $check_DNS_Forwarders ADDED"
    }
    else{
        Write-Host -ForegroundColor Red "[DNS] Forwarders: $check_DNS_Forwarders FAILED TO ADD"
    }

    $check_DNS = Test-DnsServer -IPAddress ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".2") -ZoneName $Using:SDDC_DomainName
    if($check_DNS.Result -eq "Success"){
        Write-Host -ForegroundColor Green "[DNS] test SUCCESS"
    }
    else{
        Write-Host -ForegroundColor Red "[DNS] test FAILED"
    }
  
    # Set Zone Transfers to main DNS Servers
    #Write-Host -ForegroundColor Yellow "[DNS] Setting zone transfers to main lab DNS servers ..."
    #Set-DnsServerPrimaryZone -Name $Using:SDDC_DomainName -Notify NotifyServers -NotifyServers "192.168.1.11","192.168.1.21" -SecondaryServers "192.168.1.11","192.168.1.21" -SecureSecondaries TransferToSecureServers -Verbose
    #Set-DnsServerPrimaryZone -Name ("1." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -Notify NotifyServers -NotifyServers "192.168.1.11","192.168.1.21" -SecondaryServers "192.168.1.11","192.168.1.21" -SecureSecondaries TransferToSecureServers -Verbose
    #Set-DnsServerPrimaryZone -Name ("9." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -Notify NotifyServers -NotifyServers "192.168.1.11","192.168.1.21" -SecondaryServers "192.168.1.11","192.168.1.21" -SecureSecondaries TransferToSecureServers -Verbose
  
    # Add DNS A records
    Write-Host -ForegroundColor Yellow "[DNS] Adding A records ..."
    Add-DnsServerResourceRecordA -Name igw -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".1") -Verbose
    Add-DnsServerResourceRecordA -Name esxi101 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + "101") -Verbose
    Add-DnsServerResourceRecordA -Name esxi102 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".102") -Verbose
    Add-DnsServerResourceRecordA -Name esxi103 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".103") -Verbose
    Add-DnsServerResourceRecordA -Name esxi104 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".104") -Verbose
    Add-DnsServerResourceRecordA -Name esxi105 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".105") -Verbose
    Add-DnsServerResourceRecordA -Name esxi106 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".106") -Verbose
    Add-DnsServerResourceRecordA -Name esxi107 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".107") -Verbose
    Add-DnsServerResourceRecordA -Name esxi108 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".108") -Verbose
    Add-DnsServerResourceRecordA -Name esxi109 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".109") -Verbose
    Add-DnsServerResourceRecordA -Name vcenter -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".17") -Verbose
    Add-DnsServerResourceRecordA -Name nsx1 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".18") -Verbose
    Add-DnsServerResourceRecordA -Name vcd1 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".25") -Verbose
    Add-DnsServerResourceRecordA -Name vcd1-proxy -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".26") -Verbose
    Add-DnsServerResourceRecordA -Name esxi201 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".201") -Verbose
    Add-DnsServerResourceRecordA -Name esxi202 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".202") -Verbose
    Add-DnsServerResourceRecordA -Name esxi203 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".203") -Verbose
    Add-DnsServerResourceRecordA -Name esxi204 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".204") -Verbose
    Add-DnsServerResourceRecordA -Name esxi205 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".205") -Verbose
    Add-DnsServerResourceRecordA -Name esxi206 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".206") -Verbose
    Add-DnsServerResourceRecordA -Name esxi207 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".207") -Verbose
    Add-DnsServerResourceRecordA -Name esxi208 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".208") -Verbose
    Add-DnsServerResourceRecordA -Name esxi209 -ZoneName $Using:SDDC_DomainName -IPv4Address ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".209") -Verbose
    
    # Add DNS PTR records
    Write-Host -ForegroundColor Yellow "[DNS] Adding DNS records ..."
    Add-DnsServerResourceRecordPtr -Name 1 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("igw." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 101 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi101." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 102 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi102." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 103 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi103." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 104 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi104." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 105 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi105." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 106 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi106." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 107 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi107." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 108 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi108." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 109 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi109." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 17 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("vcenter." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 18 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("nsx1." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 25 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("vcd1." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 26 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("vcd1-proxy." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 201 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi201." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 202 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi202." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 203 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi203." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 204 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi204." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 205 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi205." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 206 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi206." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 207 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi207." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 208 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi208." + $Using:SDDC_DomainName) -Verbose
    Add-DnsServerResourceRecordPtr -Name 209 -ZoneName ($Using:SDDC_InfraID + "." + $Using:SDDC_SubnetID + ".10.in-addr.arpa") -PtrDomainName ("esxi209." + $Using:SDDC_DomainName) -Verbose
#}        
    # Install DHCP Role
    Write-Host -ForegroundColor Yellow "[DHCP] Installing role ..."
    Install-WindowsFeature DHCP -IncludeManagementTools -Verbose

    # Check DHCP Role
    $check_DHCP_Feature = Get-WindowsFeature -Name DHCP
    if($check_DHCP_Feature.InstallState -eq "Installed"){
        Write-Host -ForegroundColor Green "[DHCP] Installation SUCCESS"
    }
    else{
        Write-Host -ForegroundColor Red "[DHCP] Installation FAILED"
    }

    # Add DHCP scope: INFRA
    Write-Host -ForegroundColor Yellow "[DHCP] Adding scope INFRA ..."
    Add-DHCPServerv4Scope -Name “INFRA” -StartRange ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".220") -EndRange ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".250") -SubnetMask 255.255.255.0 -State Active
    Set-DhcpServerv4Scope -ScopeId ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".0") -LeaseDuration 1.00:00:00
    Set-DHCPServerv4OptionValue -ScopeID ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".0") -DnsDomain $Using:SDDC_DomainName -DnsServer ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".2") -Router ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".1")

    # Check DHCP scope: INFRA
    $check_DHCP_scope = Get-DhcpServerv4Scope
    if((($check_DHCP_scope.ScopeId) -eq ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_InfraID + ".0")) -and (($check_DHCP_scope.State) -eq "Active")){
        Write-Host -ForegroundColor Green "[DHCP] Adding scope INFRA SUCCESS"
    }
    else{
        Write-Host -ForegroundColor Green "[DHCP] Adding scope INFRA FAILED"
    }

    # Add DHCP scope: MGMT
    Write-Host -ForegroundColor Yellow "[DHCP] Adding scope MGMT ..."
    Add-DHCPServerv4Scope -Name “MGMT” -StartRange ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".220") -EndRange ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".250") -SubnetMask 255.255.255.0 -State Active
    Set-DhcpServerv4Scope -ScopeId ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".0") -LeaseDuration 1.00:00:00
    Set-DHCPServerv4OptionValue -ScopeID ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".0") -DnsDomain $Using:SDDC_DomainName -DnsServer ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".2") -Router ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".1")

    # Check DHCP scope: MGMT
    $check_DHCP_scope = Get-DhcpServerv4Scope
    if((($check_DHCP_scope.ScopeId) -eq ("10." + $Using:SDDC_SubnetID + "." + $Using:SDDC_MgmtID + ".0")) -and (($check_DHCP_scope.State) -eq "Active")){
        Write-Host -ForegroundColor Green "[DHCP] Adding scope MGMT SUCCESS"
    }
    else{
        Write-Host -ForegroundColor Green "[DHCP] Adding scope MGMT FAILED"
    }

    # Authorizing DHCP Server in domain
    Write-Host -ForegroundColor Yellow "[DHCP] Authorizing in domain ..."
    Add-DhcpServerInDC -DnsName $Using:SDDC_DomainName -IpAddress $Using:VM_IP

    # Check DHCP authorization in domain
    $check_DHCP_auth = Get-DhcpServerInDC
    $DHCP_IP = ($check_DHCP_auth.IPAddress).IPAddressToString
    if(($DHCP_IP -eq $Using:VM_IP) -and (($check_DHCP_auth.DnsName) -eq $Using:SDDC_DomainName)){
        Write-Host -ForegroundColor Green "[DHCP] Authorizing in domain SUCCESS"
    }
    else{
        Write-Host -ForegroundColor Red "[DHCP] Authorizing in domain FAILED"
    }
    # Restart DHCP Service
    Write-Host -ForegroundColor Yellow "[DHCP[ Restarting ..."
    Restart-Service dhcpserver -Verbose
    
    Stop-Transcript
}

# Check PSSession
$check_PSSession = $PSSession.State
if($check_PSSession -ne "Opened"){
    # Connect to VM with domain admin/pwd
    $PSSession = PSConnect-AD $VM_IP
}

# Create GPOs - copy local script and remote execute
My-Logger "[GPO] Copy script to remote server ..."
Copy-Item .\create-gpo-ntp.ps1 -ToSession $PSSession -Force -PassThru -Destination C:\install

Invoke-Command -Session $PSSession -ScriptBlock {
    Start-Transcript -Path "C:\install\3-create-gpo-ntp.txt" -Append
    Write-Host -ForegroundColor Yellow  "[GPO] Creating ..."
    Set-Location -Path 'C:\install\';& powershell.exe "./create-gpo-ntp.ps1"
    Stop-Transcript
    Write-Host -ForegroundColor Yellow  "[GPO] Removing script from remote server ..."
    Remove-Item "C:\install\create-gpo-ntp.ps1"
}
# Remove all outstanding PSSessions
$check_PSSession = Get-PSSession
if($check_PSSession -ne $null){
    Get-PSSession | Remove-PSSession
}

# End
My-Logger "[$VM_Name] Install & Configure DONE"