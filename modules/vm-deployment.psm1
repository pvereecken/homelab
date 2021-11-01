#######################################################################
# Logging
#######################################################################
Function My-Logger {
    param(
    [Parameter(Mandatory=$true)]
    [String]$message
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor Green " $message"
    $logMessage = "[$timeStamp][$VM_Name] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}
# Disable certificate check
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -DisplayDeprecationWarnings $false -Scope Session -Confirm:$false
#######################################################################
# Function: Create VM in workgroup from regular VMware Template
#######################################################################
Function Create-VM-Windows-Workgroup {
    param(
    [Parameter(Mandatory=$true)] [String] $wg_VM_Name,
    [Parameter(Mandatory=$true)] [String] $wg_VM_IP,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_CPUs,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_CoresPerSocket,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_MEM,
    [Parameter(Mandatory=$true)] [String] $wg_VM_Network,
    [Parameter(Mandatory=$true)] [String] $wg_VM_OrgName
    )
    My-Logger "[$wg_VM_Name] Deploying ..."
    # Create Customisation
    $check_TempSpec = Get-OSCustomizationSpec
    if($check_TempSpec -ne $null){
        Remove-OSCustomizationSpec TempSpec -confirm:$false
    }

    $CustSpec = New-OSCustomizationSpec `
    -OSType "Windows"`
    -Name "TempSpec" `
    -Type NonPersistent `
    -NamingScheme  "Fixed" `
    -NamingPrefix $wg_VM_Name `
    -Workgroup "WORKGROUP" `
    -FullName $VM_LocalAdmin `
    -AdminPassword $VM_LocalAdminPW `
    -AutoLogonCount 1 `
    -OrgName $wg_VM_OrgName `
    -Description "Temp Custom Spec for VM deployment" `
    -TimeZone 110 `
    -ChangeSid `
    -ErrorAction Stop
 
    # Set Network Properties
 
    $IP =  @{OScustomizationNicMapping = Get-OSCustomizationNicMapping -OSCustomizationSpec $CustSpec}
    $IP.IPMode = "UseStaticIP"
    $IP.IPAddress = $wg_VM_IP
    $IP.SubnetMask = $SubnetMask
    $IP.DefaultGateway = $DefaultGW
    $IP.dns = $DNSServer1 #,$DNSServer2
 
    Set-OSCustomizationNicMapping @IP
 
    # Deploy VM
    $NewVM = New-VM -Name $wg_VM_Name `
                -Template $VI_Template_Win `
                -VMHost $VI_Host `
                -Datastore $VI_Datastore_OS `
                -OSCustomizationSpec $CustSpec `
                -ErrorAction Stop

    # Customize VM Hardware: CPU, Cores and Memory
    My-Logger "[$wg_VM_Name] Configuring VM Hardware ..."
    Set-VM -VM $wg_VM_Name -NumCPU $wg_VM_CPUs -CoresPerSocket $wg_VM_CoresPerSocket -MemoryGB $wg_VM_MEM -confirm:$false
    My-Logger "[$wg_VM_Name] $wg_VM_CPUs CPU(s) with $wg_VM_CoresPerSocket Core(s) CONFIGURED"
    My-Logger "[$wg_VM_Name] $WG_VM_MEM GB RAM CONFIGURED"

    # Customize VM Hardware: Network
    Get-VM $wg_VM_Name | Get-NetworkAdapter | Set-NetworkAdapter -Portgroup $wg_VM_Network -confirm:$false
    My-Logger "[$wg_VM_Name] Portgroup $wg_VM_Network CONNECTED"

    # Power On VM
    My-Logger "[$wg_VM_Name] Powering On ..."
    Start-VM $wg_VM_Name

    # Wait for customization
    My-Logger "[$wg_VM_Name] Guest OS Customization STARTING ..."
    Start-Sleep 60
    do{
        $check_VM = Get-VM -Name $wg_VM_Name | Select Name,@{N="DNS_Name";E={$_.Guest.HostName}},@{N="IP_Address";E={$_.Guest.IPAddress}}
        My-Logger "[$wg_VM_Name] Waiting for Guest OS Customization ..."
        Start-Sleep 20
    }until ($check_VM.DNS_Name -eq $wg_VM_Name -and $check_VM.IP_Address -like "*$wg_VM_IP*")
    My-Logger "[$wg_VM_Name] Guest OS Customization DONE"
}
#######################################################################
# Function: Create VM in workgroup from VMware Content Library Template
#######################################################################
<#
Function Create-VM-Windows-Workgroup-CL {
    param(
    [Parameter(Mandatory=$true)] [String] $wg_VM_Name,
    [Parameter(Mandatory=$true)] [String] $wg_VM_IP,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_CPUs,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_CoresPerSocket,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_MEM,
    [Parameter(Mandatory=$true)] [String] $wg_VM_Network,
    [Parameter(Mandatory=$true)] [String] $wg_VM_OrgName
    )
    My-Logger "[$wg_VM_Name] Deploying ..."
    # Create Customisation
    $check_TempSpec = Get-OSCustomizationSpec
    if($check_TempSpec -ne $null){
        Remove-OSCustomizationSpec TempSpec -confirm:$false
    }

    $CustSpec = New-OSCustomizationSpec `
    -OSType "Windows"`
    -Name "TempSpec" `
    -Type NonPersistent `
    -NamingScheme  "Fixed" `
    -NamingPrefix $wg_VM_Name `
    -Workgroup "WORKGROUP" `
    -FullName $VM_LocalAdmin `
    -AdminPassword $VM_LocalAdminPW `
    -AutoLogonCount 1 `
    -OrgName $wg_VM_OrgName `
    -Description "Temp Custom Spec for VM deployment" `
    -TimeZone 110 `
    -ChangeSid `
    -ErrorAction Stop
 
    # Set Network Properties
 
    $IP =  @{OScustomizationNicMapping = Get-OSCustomizationNicMapping -OSCustomizationSpec $CustSpec}
    $IP.IPMode = "UseStaticIP"
    $IP.IPAddress = $wg_VM_IP
    $IP.SubnetMask = $SubnetMask
    $IP.DefaultGateway = $DefaultGW
    $IP.dns = $DNSServer1 ,$DNSServer2
 
    Set-OSCustomizationNicMapping @IP
 
    # Deploy VM
    $NewVM = $VI_Template_Win | New-VM -Name $wg_VM_Name `
                -VMHost $VI_Host `
                -Datastore $VI_Datastore_OS `
                -ErrorAction Stop `
                -confirm:$false

    # Customize VM Hardware: CPU, Cores and Memory
    My-Logger "[$wg_VM_Name] Configuring VM Hardware ..."
    Set-VM -VM $wg_VM_Name -NumCPU $wg_VM_CPUs -CoresPerSocket $wg_VM_CoresPerSocket -MemoryGB $wg_VM_MEM -confirm:$false
    My-Logger "[$wg_VM_Name] $wg_VM_CPUs CPU(s) with $wg_VM_CoresPerSocket Core(s) CONFIGURED"
    My-Logger "[$wg_VM_Name] $WG_VM_MEM GB RAM CONFIGURED"

    # Customize VM Hardware: Network
    Get-VM $wg_VM_Name | Get-NetworkAdapter | Set-NetworkAdapter -Portgroup $wg_VM_Network -confirm:$false
    My-Logger "[$wg_VM_Name] Portgroup $wg_VM_Network CONNECTED"

    # Set customization specification
    Set-VM -VM $wg_VM_Name -OSCustomizationSpec $CustSpec -confirm:$false

    # Power On VM
    My-Logger "[$wg_VM_Name] Powering On ..."
    Start-VM $wg_VM_Name -confirm:$false

    # Wait for customization
    My-Logger "[$wg_VM_Name] Guest OS Customization STARTING ..."
    Start-Sleep 60
    do{
        $check_VM = Get-VM -Name $wg_VM_Name | Select Name,@{N="DNS_Name";E={$_.Guest.HostName}},@{N="IP_Address";E={$_.Guest.IPAddress}}
        My-Logger "[$wg_VM_Name] Waiting for Guest OS Customization ..."
        Start-Sleep 20
    }until ($check_VM.DNS_Name -eq $wg_VM_Name -and $check_VM.IP_Address -like "*$wg_VM_IP*")
    My-Logger "[$wg_VM_Name] Guest OS Customization DONE"
}    
#>
#######################################################################
# Function: Create VM and join Active Directory domain
#######################################################################
Function Create-VM-Windows-ADJoined {
    param(
    [Parameter(Mandatory=$true)] [String] $wg_VM_Name,
    [Parameter(Mandatory=$true)] [String] $wg_VM_IP,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_CPUs,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_CoresPerSocket,
    [Parameter(Mandatory=$true)] [int32] $wg_VM_MEM,
    [Parameter(Mandatory=$true)] [String] $wg_VM_Network,
    [Parameter(Mandatory=$true)] [String] $wg_VM_OrgName,
    [Parameter(Mandatory=$true)] [String] $wg_VM_ADDomain
    )
    My-Logger "[$wg_VM_Name] Deploying ..."
    # Create Customisation
    $check_TempSpec = Get-OSCustomizationSpec
    if($check_TempSpec -ne $null){
        Remove-OSCustomizationSpec TempSpec -confirm:$false
    }

    $CustSpec = New-OSCustomizationSpec `
    -OSType "Windows"`
    -Name "TempSpec" `
    -Type NonPersistent `
    -NamingScheme  "Fixed" `
    -NamingPrefix $wg_VM_Name `
    -Domain $wg_VM_ADDomain `
    -DomainCredentials $Creds_AD_Admin `
    -FullName $VM_LocalAdmin `
    -AdminPassword $VM_LocalAdminPW `
    -AutoLogonCount 1 `
    -OrgName $wg_VM_OrgName `
    -Description "Temp Custom Spec for VM deployment" `
    -TimeZone 110 `
    -ChangeSid `
    -ErrorAction Stop
 
     ## Set Network Properties
 
    $IP =  @{OScustomizationNicMapping = Get-OSCustomizationNicMapping -OSCustomizationSpec $CustSpec}
    $IP.IPMode = "UseStaticIP"
    $IP.IPAddress = $wg_VM_IP
    $IP.SubnetMask = $SubnetMask
    $IP.DefaultGateway = $DefaultGW
    $IP.dns = $DNSServer1 ,$DNSServer2
 
    Set-OSCustomizationNicMapping @IP
 
    ## Deploy VM
    $NewVM = New-VM -Name $wg_VM_Name `
                -Template $VI_Template_Win `
                -VMHost $VI_Host `
                -Datastore $VI_Datastore_OS `
                -OSCustomizationSpec $CustSpec `
                -ErrorAction Stop
 
    # Customize VM hardware - CPU, MEM
    My-Logger "[$wg_VM_Name] Configuring VM Hardware ..."
    Set-VM -VM $wg_VM_Name -NumCPU $wg_VM_CPUs -CoresPerSocket $wg_VM_CoresPerSocket -MemoryGB $wg_VM_MEM -confirm:$false
    My-Logger "[$wg_VM_Name] vCPU: $wg_VM_CPUs CPU(s) with $wg_VM_CoresPerSocket Core(s) CONFIGURED"
    My-Logger "[$wg_VM_Name] RAM: $WG_VM_MEM GB RAM CONFIGURED"

    # Customize VM hardware - Portgroup
    Get-VM $wg_VM_Name | Get-NetworkAdapter | Set-NetworkAdapter -Portgroup $wg_VM_Network -confirm:$false
    My-Logger "[$wg_VM_Name] Network: $wg_VM_Network CONNECTED"

    # Power On VM
    My-Logger "[$wg_VM_Name] Powering On ..."
    Start-VM $wg_VM_Name

    # Wait for customization
    My-Logger "[$wg_VM_Name] Guest OS Customization STARTING ..."
    Start-Sleep 60
    do{
        $check_VM = Get-VM -Name $wg_VM_Name | Select Name,@{N="DNS_Name";E={$_.Guest.HostName}},@{N="IP_Address";E={$_.Guest.IPAddress}}
        $target_Name = $wg_VM_Name + "." + $SDDC_DomainName
        My-Logger "[$wg_VM_Name] Waiting for Guest OS Customization ..."
        Start-Sleep 20
    }until ($check_VM.DNS_Name -eq $target_Name -and $check_VM.IP_Address -like "*$wg_VM_IP*")
    My-Logger "[$wg_VM_Name] Guest OS Customization DONE" 
}

#######################################################################
# Function: Add Virtual Disk to VM
#######################################################################
Function Add-VirtualDisk {
    param(
    [Parameter(Mandatory=$true)] [String] $VMDK_VM_Name,
    [Parameter(Mandatory=$true)] [int32] $VMDK_Size
    )
    My-Logger "[$VMDK_VM_Name] Adding extra VMDK: $VMDK_Size GB ..."
    
    $VMDK_scsicontroller = Get-ScsiController -VM $VMDK_VM_Name | Select -Unique
    Get-VM $VMDK_VM_Name | New-Harddisk -Controller $VMDK_scsicontroller -CapacityGB $VMDK_Size -Datastore $VI_Datastore_Data -ThinProvisioned
}

#######################################################################
# Function: PSSession to VM by WORKGROUP\Administrator
#######################################################################
Function PSConnect-Workgroup {
    param(
    [Parameter(Mandatory=$true)] [String] $wgc_IP
    )
    $connectiontimeout = 0
    $username = "$VM_Name\$VM_LocalAdmin"
    [SecureString]$secureString = $VM_LocalAdminPW | ConvertTo-SecureString -AsPlainText -Force 
    [PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString
        
    # Start remote powershell session to VM
    do{
        $session = New-PSSession -ComputerName $wgc_IP -Credential $creds
        My-Logger "[PSSession] Connecting to $wgc_IP (WORKGROUP\Administrator) ..."
        sleep -seconds 10
        $connectiontimeout++
    }until ($session.state -match "Opened" -or $connectiontimeout -ge 10)
    My-Logger "[PSSession] Connected!"
    return $session
}
#######################################################################
# Function: PSSession to VM by WORKGROUP\Administrator
#######################################################################
Function PSConnect-AD {
    param(
    [Parameter(Mandatory=$true)] [String] $adc_IP
    )
    #$connectiontimeout = 0
    #$username = "$AD_OrgName\$VM_LocalAdmin"
    #[SecureString]$secureString = $VM_LocalAdminPW | ConvertTo-SecureString -AsPlainText -Force 
    #[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $secureString
        
    #starts up a remote powershell session to the computer
    do{
        $session = New-PSSession -ComputerName $adc_IP -Credential $Creds_AD_Admin
        My-Logger "[PSSession] Connecting to $adc_IP (DOMAIN\USERNAME) ..."
        sleep -seconds 10
        $connectiontimeout++
    }until ($session.state -match "Opened" -or $connectiontimeout -ge 10)
    My-Logger "[PSSession] Connected!"
    return $session
}
#######################################################################
# Function: Rename VM to include client domain and IP nr
#######################################################################
Function Rename-VM {
    param(
    [Parameter(Mandatory=$true)] [String] $f_VM_Name
    )
    My-Logger "[$f_VM_Name] Renaming VM ..."
    $VM_Name = Get-VM -Name $f_VM_Name -Server $VI_Session
    $VM_IPAddress = (Get-VM -Name $f_VM_Name | Select Name, @{N="IP";E={@($_.guest.IPAddress[0])}}).IP
    $VM_IPAddress_LastOctet = $VM_IPAddress.Split(".")[3]
    $SDDC_Name = $SDDC_DomainName.Split(".")[0]
    # Set name to domain-IP-VM name
    #$VM_NewName = $SDDC_Name + "-" + $VM_IPAddress_LastOctet + "-" + $VM_Name
    # Set name to domain-VM name
    $VM_NewName = $SDDC_Name + "-" + $VM_Name
    Get-VM -Name $f_VM_Name | Set-VM -Name $VM_NewName -Confirm:$false
    My-Logger "[$f_VM_Name] Renamed $f_VM_Name to $VM_NewName ..."
}