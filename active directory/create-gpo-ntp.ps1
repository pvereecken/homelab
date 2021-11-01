param([switch]$whatif)
 
    Set-StrictMode -Version 2.0
 
    $VerbosePreference = 'Continue'
    $WarningPreference = 'Continue'
    $ErrorPreference = 'Continue'
 
    if ($whatif.IsPresent) { 
      $WhatIfPreference = $True
      Write-Verbose "WhatIf Enabled"
    } Else {
      $WhatIfPreference = $False
    }

    # Define variables specific to your Active Directory environment
 
    # Set this to the NTP Servers the PDCe will sync with
    $TimeServers = "0.nl.pool.ntp.org,0x8 1.nl.pool.ntp.org,0x8 2.nl.pool.ntp.org,0x8 3.nl.pool.ntp.org,0x8"
 
    # This is the name of the GPO for the PDCe policy
    $PDCeGPOName = "Time Source PDC"
 
    # This is the WMI Filter for the PDCe Domain Controller
    $PDCeWMIFilter = @("PDC Domain Controller",
                       "Queries for the domain controller that holds the PDC emulator FSMO role",
                       "root\CIMv2",
                       "Select * from Win32_ComputerSystem where DomainRole=5")
 
    # This is the name of the GPO for the non-PDC policy
    $NonPDCeGPOName = "Time Source non-PDC"
 
    # This is the WMI Filter for the non-PDCe Domain Controllers
    $NonPDCeWMIFilter = @("Non-PDC Domain Controllers",
                          "Queries for all domain controllers except for the one that holds the PDC emulator FSMO role",
                          "root\CIMv2",
                          "Select * from Win32_ComputerSystem where DomainRole=4")
 
    # This is the name of the GPO for the Domain Member policy
    $DomainMembersGPOName = "Time Source Others"
 
    # Set this to True to include the registry value to disable the Virtual Host Time Synchronization provider (VMICTimeProvider)
    $DisableVirtualHostTimeSynchronization = $True
 
    # Set this to true to set the Allow System Only Change registry value
    $EnableAllowSystemOnlyChange = $True
 
    # Set this to the number of seconds you would like to wait for Active Directory replication
    # to complete before retrying to add the WMI filter to the Group Policy Object (GPO).
    $SleepTimer = 10

    # Import the Active Directory Module
    Import-Module ActiveDirectory -WarningAction SilentlyContinue
    if ($Error.Count -eq 0) {
      Write-Verbose "Successfully loaded Active Directory Powershell's module"
    } else {
      Write-Error "Error while loading Active Directory Powershell's module : $Error"
      exit
    }
 
    # Import the Group Policy Module
    Import-Module GroupPolicy -WarningAction SilentlyContinue
    if ($Error.Count -eq 0) {
      Write-Verbose "Successfully loaded Group Policy Powershell's module"
    } else {
      Write-Error "Error while loading Group Policy Powershell's module : $Error"
      exit
    }

    # Get the Current Domain &amp; Forest Information
    $DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $DomainName = $DomainInfo.Name
    $ForestName = $DomainInfo.Forest.Name
 
    # Get AD Distinguished Name
    $DomainDistinguishedName = $DomainInfo.GetDirectoryEntry() | select -ExpandProperty DistinguishedName  
 
    If ($DomainName -eq $ForestName) {
      $IsForestRoot = $True
    } Else {
      $IsForestRoot = $False
    }

    function ConvertTo-WmiFilter([Microsoft.ActiveDirectory.Management.ADObject[]] $ADObject)
    {
      # The concept of this function has been taken directly from the GPWmiFilter.psm1 module
      # written by Bin Yi from Microsoft. I have modified it to allow for the challenges of
      # Active Directory replication. It will return the WMI filter as an object of type
      # "Microsoft.GroupPolicy.WmiFilter".
      $gpDomain = New-Object -Type Microsoft.GroupPolicy.GPDomain
      $ADObject | ForEach-Object {
        $path = 'MSFT_SomFilter.Domain="' + $gpDomain.DomainName + '",ID="' + $_.Name + '"'
        $filter = $NULL
        try
          {
            $filter = $gpDomain.GetWmiFilter($path)
          }
        catch
          {
            write-Error "The WMI filter could not be found."
          }
        if ($filter)
          {
            [Guid]$Guid = $_.Name.Substring(1, $_.Name.Length - 2)
            $filter | Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru | Add-Member -MemberType NoteProperty -Name Content -Value $_."msWMI-Parm2" -PassThru
          } else {
            write-Warning "Waiting $SleepTimer seconds for Active Directory replication to complete."
            start-sleep -s $SleepTimer
            write-warning "Trying again to retrieve the WMI filter."
            ConvertTo-WmiFilter $ADObject
          }
      }
    }

    function Enable-ADSystemOnlyChange([switch] $disable)
    {
        # This function has been taken directly from the GPWmiFilter.psm1
        # module written by Bin Yi from Microsoft.
        $valueData = 1
        if ($disable)
        {
            $valueData = 0
        }
        $key = Get-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -ErrorAction SilentlyContinue
        if (!$key) {
            New-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -ItemType RegistryKey | Out-Null
        }
        $kval = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -Name "Allow System Only Change" -ErrorAction SilentlyContinue
        if (!$kval) {
            New-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -Name "Allow System Only Change" -Value $valueData -PropertyType DWORD | Out-Null
        } else {
            Set-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -Name "Allow System Only Change" -Value $valueData | Out-Null
        }
    }

    Function Create-Policy {
      param($GPOName,$TargetOU,$NtpServer,$AnnounceFlags,$Type,$MaxPosPhaseCorrection,$MaxNegPhaseCorrection,$SpecialPollInterval,$WMIFilter)
 
      If ($WMIFilter -ne "none") {
        $UseAdministrator = $False
        If ($UseAdministrator -eq $False) {
          $msWMIAuthor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        } Else {
          $msWMIAuthor = "Administrator@" + [System.DirectoryServices.ActiveDirectory.Domain]::getcurrentdomain().name
        }
 
        # Create WMI Filter
        $WMIGUID = [string]"{"+([System.Guid]::NewGuid())+"}"
        $WMIDN = "CN="+$WMIGUID+",CN=SOM,CN=WMIPolicy,CN=System,"+$DomainDistinguishedName
        $WMICN = $WMIGUID
        $WMIdistinguishedname = $WMIDN
        $WMIID = $WMIGUID
  
        $now = (Get-Date).ToUniversalTime()
        $msWMICreationDate = ($now.Year).ToString("0000") + ($now.Month).ToString("00") + ($now.Day).ToString("00") + ($now.Hour).ToString("00") + ($now.Minute).ToString("00") + ($now.Second).ToString("00") + "." + ($now.Millisecond * 1000).ToString("000000") + "-000"
        $msWMIName = $WMIFilter[0]
        $msWMIParm1 = $WMIFilter[1] + " "
        $msWMIParm2 = "1;3;10;" + $WMIFilter[3].Length.ToString() + ";WQL;" + $WMIFilter[2] + ";" + $WMIFilter[3] + ";"
 
        # msWMI-Name: The friendly name of the WMI filter
        # msWMI-Parm1: The description of the WMI filter
        # msWMI-Parm2: The query and other related data of the WMI filter
        $Attr = @{"msWMI-Name" = $msWMIName;"msWMI-Parm1" = $msWMIParm1;"msWMI-Parm2" = $msWMIParm2;"msWMI-Author" = $msWMIAuthor;"msWMI-ID"=$WMIID;"instanceType" = 4;"showInAdvancedViewOnly" = "TRUE";"distinguishedname" = $WMIdistinguishedname;"msWMI-ChangeDate" = $msWMICreationDate; "msWMI-CreationDate" = $msWMICreationDate} 
        $WMIPath = ("CN=SOM,CN=WMIPolicy,CN=System,"+$DomainDistinguishedName) 
 
        $array = @()
        $SearchRoot = [adsi]("LDAP://CN=SOM,CN=WMIPolicy,CN=System,"+$DomainDistinguishedName)
        $search = new-object System.DirectoryServices.DirectorySearcher($SearchRoot)
        $search.filter = "(objectclass=msWMI-Som)"
        $results = $search.FindAll()
        ForEach ($result in $results) {
          $array += $result.properties["mswmi-name"].item(0)
        }
 
        if ($array -notcontains $msWMIName) {
          write-Verbose "Creating the $msWMIName WMI Filter..."
          If ($EnableAllowSystemOnlyChange) {
            Enable-ADSystemOnlyChange
          }
          $SOMContainer = [adsi]("LDAP://CN=SOM,CN=WMIPolicy,CN=System,"+$DomainDistinguishedName)
          $NewWMIFilter = $SOMContainer.create('msWMI-Som',"CN="+$WMIGUID)
          $NewWMIFilter.put("msWMI-Name",$msWMIName)
          $NewWMIFilter.put("msWMI-Parm1",$msWMIParm1)
          $NewWMIFilter.put("msWMI-Parm2",$msWMIParm2)
          $NewWMIFilter.put("msWMI-Author",$msWMIAuthor)
          $NewWMIFilter.put("msWMI-ID",$WMIID)
          $NewWMIFilter.put("instanceType",4)
          $NewWMIFilter.put("showInAdvancedViewOnly","TRUE")
          $NewWMIFilter.put("distinguishedname",$WMIdistinguishedname)
          $NewWMIFilter.put("msWMI-ChangeDate",$msWMICreationDate)
          $NewWMIFilter.put("msWMI-CreationDate",$msWMICreationDate)
          If ($WhatIfPreference -eq $False) {
            $NewWMIFilter.setinfo()
          }
          write-Verbose "Waiting $SleepTimer seconds for Active Directory replication to complete."
          start-sleep -s $SleepTimer
        } Else {
          write-Warning "The $msWMIName WMI Filter already exists"
        }
 
        # Get WMI filter
        #
        $SearchRoot = [adsi]("LDAP://CN=SOM,CN=WMIPolicy,CN=System,"+$DomainDistinguishedName)
        $search = new-object System.DirectoryServices.DirectorySearcher($SearchRoot)
        $search.filter = "(&amp;(objectclass=msWMI-Som)(mswmi-name=$msWMIName))"
        $results = $search.FindAll()
        ForEach ($result in $results) {
          # To create a WmiFilter object using the ConvertTo-WmiFilter function we need to
          # first create an object with the following 7 properties:
          # DistinguishedName, msWMI-Name, msWMI-Parm1, msWMI-Parm2, Name, ObjectClass, ObjectGUID
          #$WMIFilterADObject = New-Object -TypeName Microsoft.ActiveDirectory.Management.ADObject
          # There is an Get-ADSIResult function written by Warren Frame that will achieve this:
          # - https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-ADSIObject.ps1
          # - https://gallery.technet.microsoft.com/scriptcenter/Get-ADSIObject-Portable-ae7f9184
          #$WMIFilterADObject | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -value $result.properties["distinguishedname"].item(0)
          #$WMIFilterADObject | Add-Member -MemberType NoteProperty -Name "msWMI-Name" -value $result.properties["mswmi-name"].item(0)
          #$WMIFilterADObject | Add-Member -MemberType NoteProperty -Name "msWMI-Parm1" -value $result.properties["mswmi-parm1"].item(0)
          #$WMIFilterADObject | Add-Member -MemberType NoteProperty -Name "msWMI-Parm2" -value $($result.properties["mswmi-parm2"].item(0))
          #$WMIFilterADObject | Add-Member -MemberType NoteProperty -Name "Name" -value $result.properties["name"].item(0)
          #$WMIFilterADObject | Add-Member -MemberType NoteProperty -Name "ObjectClass" -value "msWMI-Som"
          ## Convert the ObjectGUID property byte array to a GUID
          #[GUID]$GUID = $result.properties["ObjectGUID"].item(0)
          #$WMIFilterADObject | Add-Member -MemberType NoteProperty -Name "ObjectGUID" -value $GUID
 
          $WMIFilterADObject = New-Object -TypeName Microsoft.ActiveDirectory.Management.ADObject
          $WMIFilterADObject.DistinguishedName = $result.properties["distinguishedname"].item(0)
          $WMIFilterADObject."msWMI-Name" = $result.properties["mswmi-name"].item(0)
          $WMIFilterADObject."msWMI-Parm1" = $result.properties["mswmi-parm1"].item(0)
          $WMIFilterADObject."msWMI-Parm2" = ($result.properties["mswmi-parm2"].item(0)).ToString()
          #$WMIFilterADObject.Name = $result.properties["name"].item(0)
          $WMIFilterADObject.ObjectClass = "msWMI-Som"
          # Convert the ObjectGUID property byte array to a GUID
          [GUID]$GUID = $result.properties["ObjectGUID"].item(0)
          $WMIFilterADObject.ObjectGUID = $GUID
        }
    #&gt;
        $WMIFilterADObject = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties "msWMI-Name","msWMI-Parm1","msWMI-Parm2" | 
                    Where {$_."msWMI-Name" -eq "$msWMIName"}
        #$WMIFilterADObject
        #$WMIFilterADObject | gm –Force
        #ConvertTo-WmiFilter $WMIFilterADObject
      }
 
      $ExistingGPO = get-gpo $GPOName -ea "SilentlyContinue"
      If ($ExistingGPO -eq $NULL) {
        write-Verbose "Creating the $GPOName Group Policy Object..."
 
        If ($WhatIfPreference -eq $False) {
          $GPO = New-GPO -Name $GPOName
 
          write-verbose "Disabling User Settings"
          $GPO.GpoStatus = "UserSettingsDisabled"
        }
 
        If ($WMIFilter -ne "none") {
          If ($WhatIfPreference -eq $False) {
            Write-Verbose "Adding the WMI Filter"
            $GPO.WmiFilter = ConvertTo-WmiFilter $WMIFilterADObject
          }
        }
 
        If ($WhatIfPreference -eq $False) {
          write-verbose "Setting the registry keys in the Preferences section of the new GPO"
 
          Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer `
            -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" `
            -Type DWord -ValueName "AnnounceFlags" -Value $AnnounceFlags | out-null
          Write-Verbose "Set AnnounceFlags to a value of $AnnounceFlags"
 
          If ($MaxPosPhaseCorrection -ne "default") {
            Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer `
              -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" `
              -Type DWord -ValueName "MaxPosPhaseCorrection" -Value $MaxPosPhaseCorrection | out-null
            Write-Verbose "Set MaxPosPhaseCorrection to a value of $MaxPosPhaseCorrection"
          }
 
          If ($MaxNegPhaseCorrection -ne "default") {
            Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer `
              -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" `
              -Type DWord -ValueName "MaxNegPhaseCorrection" -Value $MaxNegPhaseCorrection | out-null
            Write-Verbose "Set MaxNegPhaseCorrection to a value of $MaxNegPhaseCorrection"
          }
 
          If ($SpecialPollInterval -ne "default") {
            Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer `
              -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" `
              -Type DWord -ValueName "SpecialPollInterval" -Value $SpecialPollInterval | out-null
            Write-Verbose "Set SpecialPollInterval to a value of $SpecialPollInterval"
          }
 
          Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer `
            -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" `
            -Type String -ValueName "NtpServer" -Value "$NtpServer" | out-null
          Write-Verbose "Set NtpServer to a value of $NtpServer"
  
          Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer `
            -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" `
            -Type String -ValueName "Type" -Value "$Type" | out-null
          Write-Verbose "Set Type to a value of $Type"
 
          If ($DisableVirtualHostTimeSynchronization) {
            # Disable the Hyper-V/ESX time synchronization integration service.
            Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer `
              -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider" `
              -Type DWord -ValueName "Enabled" -Value 0 -Disable | out-null
            Write-Verbose "Disabled the VMICTimeProvider"
          }
 
          # Link the new GPO to the specified OU
          write-Verbose "Linking the $GPOName Group Policy Object to the $TargetOU OU..."
          New-GPLink -Name $GPOName -Target "$TargetOU" | out-null
        }
      } Else {
        write-Warning "The $GPOName Group Policy Object already exists."
        If ($WMIFilter -ne "none") {
          write-Verbose "Adding the $msWMIName WMI Filter..."
          If ($WhatIfPreference -eq $False) {
            $ExistingGPO.WmiFilter = ConvertTo-WmiFilter $WMIFilterADObject
          }
          write-Verbose "Linking the $GPOName Group Policy Object to the $TargetOU OU..."
          If ($WhatIfPreference -eq $False) {
            Try {
              New-GPLink -Name $GPOName -Target "$TargetOU" -errorAction Stop | out-null
            }
            Catch {
              write-verbose "The GPO is already linked"
            }
          }
        }
      }
      write-Verbose "Completed."
      $ObjectExists = $NULL
    }

    If ($IsForestRoot) {
      $PDCeType = "NTP"
    } Else {
      $PDCeType = "AllSync"
    }
 
    $TargetDCOU = "OU=Domain Controllers," + $DomainDistinguishedName
 
    # Syntax:
    # Create-Policy &lt;GPOName&gt; &lt;TargetOU&gt; &lt;NtpServer&gt; &lt;AnnounceFlags&gt; &lt;Type&gt; &lt;MaxPosPhaseCorrection&gt; &lt;MaxNegPhaseCorrection&gt; &lt;SpecialPollInterval&gt; &lt;WMIFilter&gt;
 
    Write-Verbose "Creating the WMI Filters and Policies..."
 
    Create-Policy "$PDCeGPOName" "$TargetDCOU" "$TimeServers" 5 $PDCeType 172800 172800 3600 $PDCeWMIFilter
    Create-Policy "$NonPDCeGPOName" "$TargetDCOU" "time.windows.com,0x9" 10 "NT5DS" 172800 172800 "default" $NonPDCeWMIFilter
    Create-Policy "$DomainMembersGPOName" "$DomainDistinguishedName" "time.windows.com,0x9" 10 "NT5DS" 172800 172800 "default" "none"