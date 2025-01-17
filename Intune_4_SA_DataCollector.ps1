<#
_author_ = Sven Riebe <sven_riebe@Dell.com>
_twitter_ = @SvenRiebe
_version_ = 1.0.1
_Dev_Status_ = Test
Copyright (c)2023 Dell Inc. or its subsidiaries. All Rights Reserved.

No implied support and test in test environment/device before using in any production environment.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

<#Version Changes

1.0.0   inital version
1.0.1   delete invcolpc process for getting install base to SA database and add assettag field to datatables

Knowing Issues
-   tbd
#>

#>

<#
.Synopsis
   This PowerShell collecting data from Dell SupportAssist like Drivers need to updated, installed drivers and update results. It will generate 3 custom table in Microsoft LogAnalytics missing/installed/Results and upload these informations to LogAnalytics (portal.azure.com)
   IMPORTANT: This script need Dell SupportAssist for Business first otherwise you will get no details about installed/missing drivers
   IMPORTANT: LogAnalytics is a service from Microsoft and is NOT free of charge please checking your MS contracts if you have this service availible otherwise you need to order this service.
   IMPORTANT: This script does not reboot the system to apply or query system.
   IMPORTANT: This script is supporting Dell Business Devices only (Optiplex, Precision, Latitude and Mobile XPS)

.DESCRIPTION
   This PowerShell is using the Dell SupportAssist driver scandetails and collect all installed Driver Informations Driver-Name, Driver-Version and Driver-Category, Driver-Severity and using the LogAnalytics API to upload all informations directly to portal.azure.com / LogAnalytics Service.
   
#>

################################################################
###  Variables Section                                       ###
################################################################

#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = "Your LogAnalytics ID"
$SharedKey = "your LogAnalytics Key"
$LogTypeInstalled = "DellDriverInstalled"                   # if you are using the Dell SA Dashboard, do not change this as the queries will no longer run successfully
$LogTypeMissing = "DellDriverMissing"                       # if you are using the Dell SA Dashboard, do not change this as the queries will no longer run successfully
$LogTypeEvents = "DellUpdateEvents"                         # if you are using the Dell SA Dashboard, do not change this as the queries will no longer run successfully
$LogTypePenetrationRate = "DellUpdatePenetrationRate"       # if you are using the Dell SA Dashboard, do not change this as the queries will no longer run successfully
$LogTypeNonComplianceList = "DellUpdateNonComplianceList"   # if you are using the Dell SA Dashboard, do not change this as the queries will no longer run successfully
$TimeStampField = ""
#***********************************************************************************************************

## Do not change ##
$MSEventLogName = "Dell"
$MSEventSource = "DSA LogAnalytics"

################################################################
###  Functions Section                                       ###
################################################################

<#
The functions Function Build-Signature and Function Post-LogAnalyticsData was developed by https://www.systanddeploy.com/2022/05/intune-reporting-with-log-analytics.html and used by me without any change
#>

# Log analytics functions
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
    {
        $xHeaders = "x-ms-date:" + $date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    
        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($sharedKey)
    
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
        return $authorization
    }

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
    {
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $body.Length
        $signature = Build-Signature `
            -customerId $customerId `
            -sharedKey $sharedKey `
            -date $rfc1123date `
            -contentLength $contentLength `
            -method $method `
            -contentType $contentType `
            -resource $resource
        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    
        $headers = @{
            "Authorization" = $signature;
            "Log-Type" = $logType;
            "x-ms-date" = $rfc1123date;
            "time-generated-field" = $TimeStampField;
        }
    
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
        return $response.StatusCode
    }

# Function checking if DSA is installed on a device
function CheckForAppInstall
    {

        <# Description: 
            Author:  Gus Chavira
            This function will accept arguments for :
            -app application to check install status

            Comment out all Write-host when used to suppress output while be used in a remediation script

            Changelog:
                1.0.0 Initial Version
                1.1.0 Updated to use Registry uninstall section to determine installed apps as backup method 
                1.1.1 Updated to use like condition operator to allow * in search of app

            For Dell apps use app name of:  
            1.  DellOptimizerUI - Dell Optimizer
            2.  Dell Command | Monitor - DCM
            3.  Dell SupportAssist - SA
            4.  Dell SupportAssist for Business PCs - SA Commerical
            5.  Dell Command | Update - DCU

            Example use :  CheckForAppInstall -AppName "Dell Command | Update"


        #>

        [CmdletBinding()]
         param (

                [Parameter(Mandatory=$true)]
                [ValidateNotNullOrEmpty()]
               [string]$AppName
           )

        try {
    
          # Check the software inventory via conventional way 
          $SWInstalled = Get-Package | Select-Object -Property Name, Version

          # Get a list of all installed applications from the registry
          $uninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
          $regKeys = Get-ChildItem $uninstallKey | ForEach-Object { Get-ItemProperty $_.PsPath }


          Write-output "Looking for $AppName in Inventory"


          if ($SWInstalled.Name -like $AppName)
          {
            Write-output "Found App in Inventory"
            return $true
          }
          else
          {
              # Backup way to check if app is installed via registry info
              # Iterate through each registry key to find the application
              foreach ($app in $regKeys)
              {
                if ($app.DisplayName -like $AppName) 
               {
                 Write-Output "Checking $app.Displayname app"
                 Write-Output "$AppName is installed"
                 # Optionally, you can output more details like version, publisher, etc.
                 Write-Output "Version: $($app.DisplayVersion)"
                 Write-Output "Publisher: $($app.Publisher)"
                 return $true
                }
              }

              # If the application is not found, notify that it is not installed
              Write-Output "$AppName is not installed"
              return $false


          }

        }
        catch
        {
             Write-output "Error"

        }

    }

function New-MSEventLog
    {

        Param (

                [Parameter(Mandatory = $true)][string]$Message,
                [Parameter(Mandatory = $true)][ValidateSet("12", "11", "13","14","10")][long]$EventID,
                [Parameter(Mandatory = $true)][ValidateSet("Error", "Information", "FailureAudit", "SuccessAudit", "Warning")][string]$EntryType

                )
        # add source to microsoft event
        New-EventLog -LogName $MSEventLogName -Source $MSEventSource -ErrorAction Ignore
        
        # Writing Log to MS Event
        Write-EventLog -LogName $MSEventLogName -Source $MSEventSource -EntryType $EntryType -EventId $EventID -Message $Message

        Write-Host $Message

    }

function get-SATDUpdateStatus
    {
        
        <#
        .Synopsis
        This function using the SATD internal Database and checking the last scan time and how many updates are open.

        .Description
        This function use the DB of Support Assist to check the update status of a device.

        Changelog:
            1.0.0   Initial Version
            1.0.1   change installation control form date to SessionID
            1.0.2   add Function Install-PSModule and add option to get the drivers by installation details and Installation status
            1.0.3   split the MissingDriver option to last and all scannes
            1.0.4   updated function Install_PSModule Version 1.0.1
            1.0.5   sending return false if the device has no SA scans in the last 7 days
            1.0.6   adding support of installed driver
            1.0.7   adding CategoryName to Output

        Requirements:
            - Install of the PSSQLite Module form the PowerShell Gallery should be allowed
            - Run with Admin rights or System Context
            - Dell Support Assist 3.6 or newer installed on the device


        .Parameter Modus
        Value defined the output "UpdateCounter" gives a overview how many drivers are open to install and if a Update is required on the device. "MissingDriverLastScan" will build a Array with driver details and driver installation status of the last scanned drivers. "MissingDriverAllScan" will build a Array with driver details and driver installation status of scanns of Support Assist.

        .Example
        This example checking the database of Support Assist and check how many updates are missings and are patched since the last scan.
        get-SATDUpdateStatus -modus UpdateCounter

        .Example
        This example shows all identified drivers for update and show all relevant details like Name, Installationstatus, RestorePoint, ect. from the last scan and update
        get-SATDUpdateStatus -modus MissingDriverLastScan

        .Example
        This example shows all identified drivers for update and show all relevant details like Name, Installationstatus, RestorePoint, ect. from all Support Assist scan from frist installation to know if you make inplace updates for Support Assist
        get-SATDUpdateStatus -modus MissingDriverAllScan

        #>
               
        param 
            (
                [Parameter(mandatory=$true)][ValidateSet('UpdateCounter','MissingDriverLastScan','MissingDriverAllScan','InstalledAll')][String]$Modus
            )

        #########################################################################################################
        ####                                    Function Section                                             ####
        #########################################################################################################

        function Install-PSModule
            {
                
                <#
                .Synopsis
                This function checking if a PowerShell Module is installed on a device or not. If not it will install the PowerShell Module. Is install successfull or the module still exist the function return a True otherwise a false.
        
                .Description
                This function allows you agentless to set BIOS Pasword or to change BIOS Settings
        
                .Parameter ModuleName
                Value is the name of the PowerShell module you are looking for.
        
                .Parameter Version
                This is the value is of the required version of module
        
        
                Changelog:
                    1.0.0   Initial Version
                    1.0.1   correct install check and add update function
                    1.0.2   fix issue some PS-Module have problems if they are still imported and if will try again to import the same module.
        
        
                .Example
                This example will check/install Dell Command PowerShell Provider
                
                Install-PSModule -ModuleName DellBIOSProvider
        
                .Example
                This example will check/install Dell Command PowerShell Provider with version V2.7.2
                
                Install-PSModule -ModuleName DellBIOSProvider -Version 2.7.2
        
                #>
                    
                param 
                    (
        
                        [Parameter(mandatory=$true)] [String]$ModuleName,
                        [Parameter(mandatory=$false)] [version]$Version
        
                    )
        
        
                #########################################################################################################
                ####                                    Program Section                                              ####
                #########################################################################################################
                try 
                    {
                        #prepare device by install Nuget
                        try 
                            {
                                $NugetInstall = Get-PackageProvider -Name Nuget -ErrorAction Stop
                                Write-Host "Package Nuget is installed Version" $NugetInstall.Version -ForegroundColor Green
                            }
                        catch 
                            {
                                Write-Host "Package Nuget is not installed" -ForegroundColor Yellow
                    
                                try 
                                    {
                                        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
                                        Write-Host "Package Nuget is installed successfull" -ForegroundColor Green
                                    }
                                catch 
                                    {
                                        Write-Host "Package Nuget is installed failed" -ForegroundColor Red
                                        Exit 1
                                    }
                            }
        
                        
                        If($null -eq $Version)
                            {                            
                                # Check if Modul is existing on the device
                                try 
                                    {
                                        $ModulStatus = Get-InstalledModule -Name $ModuleName -ErrorAction Stop
                                        
                                        If($null -ne $ModulStatus)
                                            {
                                                Write-Host "Module" $ModuleName "exist" -ForegroundColor Green
                                                Write-Host "Checking if imported"
                                                
                                                $CheckImport = Get-Module -Name $ModuleName
        
                                                If($null -eq $CheckImport)
                                                    {
                                                        Write-Host "Module" $ModuleName "is not imported"
        
                                                        try 
                                                            {
                                                                Import-Module $ModuleName -Verbose -Force -ErrorAction Stop
                                                                Write-Host "Import Module" $ModuleName "is successfull" -ForegroundColor Green
                                                                Return $true
                                                            }
                                                        catch 
                                                            {
                                                                Write-Host "Import Module" $ModuleName "is fail" -ForegroundColor Red
                                                                Return $false
                                                            }
                                                    }
                                                else 
                                                    {
                                                        Write-Host "Module" $ModuleName "is still imported" -ForegroundColor Green
                                                        Return $true
                                                    }
                                            }                             
                                    }
                                catch 
                                    {
                                        Write-Host "Module" $ModuleName "not found" -ForegroundColor Red
                                        Write-Host "Module" $ModuleName "will installed"
        
                                        try 
                                            {
                                                Install-Module -Name $ModuleName -Force -ErrorAction Stop
                                                Import-Module $ModuleName -Verbose -Force -ErrorAction Stop
                                                Write-Host "Module" $ModuleName "installed successful" -ForegroundColor Green
                                                Return $true
                                            }
                                        catch 
                                            {
                                                Write-Host "Module" $ModuleName "installation failed" -ForegroundColor Red
                                                Return $false
                                            }
                                    }
                            }
                        else 
                            {
                                # Check if Modul is existing on the device
                                try 
                                    {
                                        $ModulStatus = Get-InstalledModule -Name $ModuleName -ErrorAction Stop
                                        [version]$installedVersion = $ModulStatus.Version
        
                                        if ($Version -gt $installedVersion)
                                            {
                                                Write-Host "Module" $ModuleName "exist" -ForegroundColor Green
                                                Write-Host "Module" $ModuleName "will updated now to powershell"
        
                                                try 
                                                    {
                                                        Update-Module -Name $ModuleName -Verbose -Force -ErrorAction Stop
                                                        Write-Host "Update Module" $ModuleName "is successfull" -ForegroundColor Green
                                                        Return $true
                                                    }
                                                catch 
                                                    {
                                                        Write-Host "Update Module" $ModuleName "is fail" -ForegroundColor Red
                                                        Return $false
                                                    }
        
                                            }
                                        else 
                                            {                                      
                                                Write-Host "Module" $ModuleName "exist" -ForegroundColor Green
                                                Write-Host "Checking if imported"
                                                        
                                                $CheckImport = Get-Module -Name $ModuleName
                
                                                If($null -eq $CheckImport)
                                                    {
                                                        Write-Host "Module" $ModuleName "is not imported"
                
                                                        try 
                                                            {
                                                                Import-Module $ModuleName -Verbose -Force -ErrorAction Stop
                                                                Write-Host "Import Module" $ModuleName "is successfull" -ForegroundColor Green
                                                                Return $true
                                                            }
                                                        catch 
                                                            {
                                                                Write-Host "Import Module" $ModuleName "is fail" -ForegroundColor Red
                                                                Return $false
                                                            }
                                                    }
                                                else 
                                                    {
                                                        Write-Host "Module" $ModuleName "is still imported" -ForegroundColor Green
                                                        Return $true
                                                    }
                                            }
                                    }
                                catch 
                                    {
                                        Write-Host "Module" $ModuleName "not found" -ForegroundColor Red
                                        Write-Host "Module" $ModuleName "will installed"
                            
                                        try 
                                            {
                                                Install-Module -Name $ModuleName -RequiredVersion $Version -ErrorAction Stop
                                                Import-Module $ModuleName -Verbose -Force -ErrorAction Stop
                                                Write-Host "Module" $ModuleName "installed successful" -ForegroundColor Green
                                                Return $true
                                            }
                                        catch 
                                            {
                                                Write-Host "Module" $ModuleName "installation failed" -ForegroundColor Red
                                                Return $false
                                            }
                                    }
                            }
                    }
                catch 
                    {
                        Write-Host "Module" $ModuleName "vailidation failed"
                        Return $false
                    }
            }

        #########################################################################################################
        ####                                    Variable Section                                             ####
        #########################################################################################################
        $ModulName = "PSSQLite"
        $DataSource = $env:ProgramData + "\Dell\SupportAssist\Agent\Db\CentralDataStore.db"
        $Query = "SELECT * FROM DriverScan"
        $QueryUpdate = "SELECT * FROM DriverInstall"
        $QueryUpdateList = "SELECT * FROM DriverScanDetails"
        $QueryInstall = "SELECT * FROM InventoryDetails"
        $today = Get-Date

        #########################################################################################################
        ####                                    Program Section                                             ####
        #########################################################################################################

        # Checking if Module is installed
        $ProcessStop = Install-PSModule -ModuleName $ModulName
        
        If ($ProcessStop -eq $true)
            {
                If ($Modus -eq "UpdateCounter")
                    {
                        # check if data source existing and get latest datas
                        try 
                            {
                                $CheckDataSource = Test-Path -Path $DataSource -ErrorAction Stop
                            }
                        catch 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                            }
                        If ($CheckDataSource -eq $true)
                            {
                                try 
                                    {
                                        [array]$ResultScan = Invoke-SqliteQuery -DataSource $DataSource -Query $Query -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "no access Table DriverScan"
                                        Return $false
                                    }

                                    If ($null -ne $ResultScan)
                                        {
                                            $ScanArray = @()

                                            foreach ($Result in $ResultScan)
                                                {
                                                    #temporay Array
                                                    $TempResult = New-Object -TypeName psobject

                                                    # convert Time form Unix to UTC and local time
                                                    $BaseTime = $Result.ModifiedTime
                                                    $DateTime = [System.DateTimeOffset]::FromUnixTimeSeconds($BaseTime)

                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'ID' -Value $Result.ID
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'ScanType' -Value $Result.ScanType
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'AvailableDriversForUpdate' -Value $Result.AvailableDriversForUpdate
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'Status' -Value $Result.Status
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'LaunchContext' -Value $Result.LaunchContext
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'ModifiedTime' -Value $Result.ModifiedTime
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'SessionId' -Value $Result.SessionId
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'UTCTime' -Value $DateTime.UtcDateTime
                                                    $TempResult | Add-Member -MemberType NoteProperty -Name 'LocalTime' -Value $DateTime.LocalDateTime

                                                    $ScanArray += $TempResult
                                                }

                                            # select the latest result    
                                            $LastScanResult = $ScanArray | Sort-Object UtcTime | Select-Object -Last 1

                                            # check if the last scan not older than 7 days
                                            
                                            $AgeScan = $today - (Get-date($LastScanResult.LocalTime))

                                            If ($AgeScan.Day -le 7 -and 0 -eq $LastScanResult.AvailableDriversForUpdate)
                                                {
                                                    Write-Host "No DriverScan in last 7 days"
                                                    Return $false
                                                }
                                            else 
                                                {
                                                    # checking the last Updates on the device made by SupportAssist
                                                    try 
                                                        {
                                                            [array]$ResultInstall = Invoke-SqliteQuery -DataSource $DataSource -Query $QueryUpdate -ErrorAction Stop
                                                        }
                                                    catch 
                                                        {
                                                            Write-Host "No access to Table DriverInstall"
                                                            Return $false
                                                        }

                                                    [array]$DoneUpdate = $ResultInstall | Where-Object {$_.SessionId -eq $LastScanResult.SessionId} | Where-Object {$_.InstallationStatus -eq "Installed"}
                                                    
                                                    if (($DoneUpdate.Count) -lt ($LastScanResult.AvailableDriversForUpdate)) 
                                                        {
                                                            $Update = $true
                                                            $LastScanResult | Add-Member -MemberType NoteProperty -Name 'Patched' -Value $DoneUpdate.Count
                                                        }
                                                    else 
                                                        {
                                                            $Update = $false
                                                            $LastScanResult | Add-Member -MemberType NoteProperty -Name 'Patched' -Value $DoneUpdate.Count
                                                        }

                                                    # Add check result to variable
                                                    $LastScanResult | Add-Member -MemberType NoteProperty -Name 'UpdateRequired' -Value $Update

                                                    return $LastScanResult | Select-Object UTCTime, UpdateRequired,AvailableDriversForUpdate,Patched
                                                }
                                        }
                                    else 
                                        {
                                                $Update = $true
                                                $LastScanResult = New-Object -TypeName psobject
                                                $LastScanResult | Add-Member -MemberType NoteProperty -Name 'UTCTime' -Value $null
                                                $LastScanResult | Add-Member -MemberType NoteProperty -Name 'UpdateRequired' -Value $Update
                                                $LastScanResult | Add-Member -MemberType NoteProperty -Name 'AvailableDriversForUpdate' -Value $null
                                                $LastScanResult | Add-Member -MemberType NoteProperty -Name 'Patched' -Value $null

                                                return $LastScanResult | Select-Object UTCTime, UpdateRequired,AvailableDriversForUpdate
                                        }

                            }
                        else 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                                Return False
                            }

                    }
                If ($Modus -eq "MissingDriverLastScan")
                    {
                         # check if data source existing and get latest datas
                         try 
                            {
                                $CheckDataSource = Test-Path -Path $DataSource -ErrorAction Stop
                            }
                        catch 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                            }
                        If ($CheckDataSource -eq $true)
                            {
                                # checking getting Tables Scan / Install / Details
                                            
                                ## DriverScan
                                try 
                                    {
                                        [array]$TableDriverScan = Invoke-SqliteQuery -DataSource $DataSource -Query $Query -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "No access to Table DriverScan"
                                        Return $false
                                    }
                                                    
                                ## DriverScanDetails  
                                try 
                                    {
                                        [array]$TableDriverScanDetails = Invoke-SqliteQuery -DataSource $DataSource -Query $QueryUpdateList -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "No access to Table DriverScanDetails"
                                        Return $false
                                    }
                                                    
                                ## DriverInstall   
                                try 
                                    {
                                        [array]$TableDriverInstall = Invoke-SqliteQuery -DataSource $DataSource -Query $QueryUpdate -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "No access to Table DriverInstall"
                                        Return $false
                                    }

                                If ($null -ne $TableDriverScan)
                                    {
                                        $ScanArray = @()

                                        foreach ($Scan in $TableDriverScan)
                                            {
                                                #temporay Array
                                                $TempScan = New-Object -TypeName psobject

                                                # convert Time form Unix to UTC and local time
                                                $BaseTime = $Scan.ModifiedTime
                                                $DateTime = [System.DateTimeOffset]::FromUnixTimeSeconds($BaseTime)

                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'ID' -Value $Scan.ID
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'ScanType' -Value $Scan.ScanType
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'AvailableDriversForUpdate' -Value $Scan.AvailableDriversForUpdate
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'Status' -Value $Scan.Status
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'LaunchContext' -Value $Scan.LaunchContext
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'ModifiedTime' -Value $Scan.ModifiedTime
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'SessionId' -Value $Scan.SessionId
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'UTCTime' -Value $DateTime.UtcDateTime
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'LocalTime' -Value $DateTime.LocalDateTime

                                                $ScanArray += $TempScan
                                            }


                                            # select the latest result    
                                            $LastScanResult = $ScanArray | Sort-Object UtcTime | Select-Object -Last 1

                                            # check if the last scan not older than 7 days
                                            
                                            $AgeScan = $today - (Get-date($LastScanResult.LocalTime))

                                            If ($AgeScan.Day -le 7 -and 0 -eq $LastScanResult.AvailableDriversForUpdate)
                                                {
                                                    Write-Host "No DriverScan in last 7 days"
                                                    Return $false
                                                }
                                            else 
                                                {
                                                    $ScanDriver = $TableDriverScanDetails | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}

                                                    foreach ($Scaned in $ScanDriver)
                                                        {
                                                            #temporay Array
                                                            $TempDriver = New-Object -TypeName psobject

                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ID' -Value $LastScanResult.ID
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'Status' -Value $LastScanResult.Status
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'LaunchContext' -Value $LastScanResult.LaunchContext
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'SessionId' -Value $LastScanResult.SessionId
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'UTCTime' -Value $LastScanResult.UTCTime
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'LocalTime' -Value $LastScanResult.LocalTime
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverDellVersion' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverDellVersion
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverId' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverId
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverTitle' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverTitle
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverReleaseDate' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverReleaseDate
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverDescription' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverDescription
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverCategory' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverCategory
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverCategoryName' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverCategoryName
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverType' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverType
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'RecordID' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).RecordID
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverTypeName' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverTypeName
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'RebootRequired' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).RebootRequired
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'CatalogVersion' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).CatalogVersion
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverImportanceLevel' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverImportanceLevel
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverUniqeID' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverUniqeID
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverSize' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverSize
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'FileName' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).FileName
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DownloadUrl' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DownloadUrl
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ModifiedTime' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).ModifiedTime
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ImportantUrl' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).ImportantUrl
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'HashAlgorithm' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).HashAlgorithm
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'HashValue' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).HashValue
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'SortOrder' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).SortOrder
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsInventoryComponent' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).IsInventoryComponent
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ComponentIdMatchingInventory' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).ComponentIdMatchingInventory
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'InventoryVersion' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).InventoryVersion
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsIsvLocked' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).IsIsvLocked
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsDependency' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).IsDependency
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'HasDependency' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).HasDependency
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsDockUpdate' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).IsDockUpdate
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'PluginId' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).PluginId
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsBSodCausing' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).IsBSodCausing
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsPowerAdapterRequired' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).IsPowerAdapterRequired
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DeviceDescription' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DeviceDescription
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'BsodRate' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).BsodRate
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'BsodVersion' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).BsodVersion
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsBiosPasswordSet' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).IsBiosPasswordSet
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ReclassifiedDriverImportance' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).ReclassifiedDriverImportance
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'BiosCodeStatus' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).BiosCodeStatus
                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverScan_id' -Value ($Scaned | Where-Object {$_.DriverScan_id -eq $LastScanResult.ID}).DriverScan_id
                                                           
                                                            [Array]$DriverArray += $TempDriver

                                                        }
                                                    
                                                        foreach ($Install in $DriverArray) 
                                                            {
                                                                $found = $false
                                                                foreach ($Installation in $TableDriverInstall) 
                                                                    {
                                                                        if ($Install.RecordID -eq $Installation.DriverScanDetails_id) 
                                                                            {
                                                                                $found = $true
                                                                                If ($found -eq $true)
                                                                                    {
                                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallID' -Value $Installation.ID
                                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationStatus' -Value $Installation.InstallationStatus
                                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallModifiedTime' -Value $Installation.ModifiedTime
                                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallType' -Value $Installation.InstallType
                                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationReturnCode' -Value $Installation.InstallationReturnCode
                                                                                        If($null -ne $Installation.RestorePoint_id)
                                                                                            {
                                                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'RestorePoint_id' -Value $Installation.RestorePoint_id
                                                                                            }
                                                                                        else 
                                                                                            {
                                                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'RestorePoint_id' -Value "no RestorePoint"
                                                                                            }
                                                                                    }
                                                                                break
                                                                            }
                                                                    }
                                                                    if ($true -ne $found) 
                                                                        {
                                                                            $Install  | Add-Member -MemberType NoteProperty -Name 'InstallID' -Value "N/A"
                                                                            $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationStatus' -Value "not installed"
                                                                            $Install  | Add-Member -MemberType NoteProperty -Name 'InstallModifiedTime' -Value "N/A"
                                                                            $Install  | Add-Member -MemberType NoteProperty -Name 'InstallType' -Value "N/A"
                                                                            $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationReturnCode' -Value "N/A"
                                                                            $Install  | Add-Member -MemberType NoteProperty -Name 'RestorePoint_id' -Value "N/A"
                                                                        }
                                                            }
                                                        

                                                    return $DriverArray
                                                }
                                    }
                                else 
                                    {
                                        Write-Host "No scan data"
                                        return $false
                                    }

                            }
                        else 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                                Return False
                            }
                    }
                If ($Modus -eq "MissingDriverAllScan")
                    {
                         # check if data source existing and get latest datas
                         try 
                            {
                                $CheckDataSource = Test-Path -Path $DataSource -ErrorAction Stop
                            }
                        catch 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                            }
                        If ($CheckDataSource -eq $true)
                            {
                                # checking getting Tables Scan / Install / Details
                                            
                                ## DriverScan
                                try 
                                    {
                                        [array]$TableDriverScan = Invoke-SqliteQuery -DataSource $DataSource -Query $Query -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "No access to Table DriverScan"
                                        Return $false
                                    }
                                                    
                                ## DriverScanDetails  
                                try 
                                    {
                                        [array]$TableDriverScanDetails = Invoke-SqliteQuery -DataSource $DataSource -Query $QueryUpdateList -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "No access to Table DriverScanDetails"
                                        Return $false
                                    }
                                                    
                                ## DriverInstall   
                                try 
                                    {
                                        [array]$TableDriverInstall = Invoke-SqliteQuery -DataSource $DataSource -Query $QueryUpdate -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "No access to Table DriverInstall"
                                        Return $false
                                    }

                                If ($null -ne $TableDriverScan)
                                    {
                                        $ScanArray = @()

                                        foreach ($Scan in $TableDriverScan)
                                            {
                                                #temporay Array
                                                $TempScan = New-Object -TypeName psobject

                                                # convert Time form Unix to UTC and local time
                                                $BaseTime = $Scan.ModifiedTime
                                                $DateTime = [System.DateTimeOffset]::FromUnixTimeSeconds($BaseTime)

                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'ID' -Value $Scan.ID
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'ScanType' -Value $Scan.ScanType
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'AvailableDriversForUpdate' -Value $Scan.AvailableDriversForUpdate
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'Status' -Value $Scan.Status
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'LaunchContext' -Value $Scan.LaunchContext
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'ModifiedTime' -Value $Scan.ModifiedTime
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'SessionId' -Value $Scan.SessionId
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'UTCTime' -Value $DateTime.UtcDateTime
                                                $TempScan | Add-Member -MemberType NoteProperty -Name 'LocalTime' -Value $DateTime.LocalDateTime

                                                $ScanArray += $TempScan
                                            }

                                        foreach ($Scaned in $TableDriverScanDetails)
                                            {
                                                $found = $false
                                                foreach ($Scan in $ScanArray) 
                                                    {
                                                            if ($Scan.ID -eq $Scaned.DriverScan_id)
                                                                {
                                                                    $found = $true
                                                                    If ($found -eq $true)
                                                                        {
                                                                            #temporay Array
                                                                            $TempDriver = New-Object -TypeName psobject

                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ID' -Value $Scan.ID
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ScanType' -Value $Scan.ScanType
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'AvailableDriversForUpdate' -Value $Scan.AvailableDriversForUpdate
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'Status' -Value $Scan.Status
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'LaunchContext' -Value $Scan.LaunchContext
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ModifiedTimeScan' -Value $Scan.ModifiedTime
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'SessionId' -Value $Scan.SessionId
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'UTCTime' -Value $Scan.UTCTime
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'LocalTime' -Value $Scan.LocalTime
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverDellVersion' -Value $Scaned.DriverDellVersion
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverId' -Value $Scaned.DriverId
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverTitle' -Value $Scaned.DriverTitle
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverReleaseDate' -Value $Scaned.DriverReleaseDate
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverDescription' -Value $Scaned.DriverDescription
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverCategory' -Value $Scaned.DriverCategory
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverCategoryName' -Value $Scaned.DriverCategoryName
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverType' -Value $Scaned.DriverType
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'RecordID' -Value $Scaned.RecordID
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverTypeName' -Value $Scaned.DriverTypeName
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'RebootRequired' -Value $Scaned.RebootRequired
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'CatalogVersion' -Value $Scaned.CatalogVersion
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverImportanceLevel' -Value $Scaned.DriverImportanceLevel
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverUniqeID' -Value $Scaned.DriverUniqeID
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverSize' -Value $Scaned.DriverSize
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'FileName' -Value $Scaned.FileName
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DownloadUrl' -Value $Scaned.DownloadUrl
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ModifiedTime' -Value $Scaned.ModifiedTime
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ImportantUrl' -Value $Scaned.ImportantUrl
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'HashAlgorithm' -Value $Scaned.HashAlgorithm
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'HashValue' -Value $Scaned.HashValue
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'SortOrder' -Value $Scaned.SortOrder
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsInventoryComponent' -Value $Scaned.IsInventoryComponent
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ComponentIdMatchingInventory' -Value $Scaned.ComponentIdMatchingInventory
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'InventoryVersion' -Value $Scaned.InventoryVersion
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsIsvLocked' -Value $Scaned.IsIsvLocked
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsDependency' -Value $Scaned.IsDependency
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'HasDependency' -Value $Scaned.HasDependency
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsDockUpdate' -Value $Scaned.IsDockUpdate
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'PluginId' -Value $Scaned.PluginId
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsBSodCausing' -Value $Scaned.IsBSodCausing
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsPowerAdapterRequired' -Value $Scaned.IsPowerAdapterRequired
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DeviceDescription' -Value $Scaned.DeviceDescription
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'BsodRate' -Value $Scaned.BsodRate
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'BsodVersion' -Value $Scaned.BsodVersion
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'IsBiosPasswordSet' -Value $Scaned.IsBiosPasswordSet
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'ReclassifiedDriverImportance' -Value $Scaned.ReclassifiedDriverImportance
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'BiosCodeStatus' -Value $Scaned.BiosCodeStatus
                                                                            $TempDriver | Add-Member -MemberType NoteProperty -Name 'DriverScan_id' -Value $Scaned.DriverScan_id
                                                                        }
                                                                        
                                                                    break
                                                                }
                                                    }
                                                                                        
                                                [Array]$DriverArray += $TempDriver

                                            }
                                                    
                                        foreach ($Install in $DriverArray) 
                                            {
                                                $found = $false
                                                foreach ($Installation in $TableDriverInstall) 
                                                    {
                                                        if ($Install.RecordID -eq $Installation.DriverScanDetails_id) 
                                                            {
                                                                $found = $true
                                                                If ($found -eq $true)
                                                                    {
                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallID' -Value $Installation.ID
                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationStatus' -Value $Installation.InstallationStatus
                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallModifiedTime' -Value $Installation.ModifiedTime
                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallType' -Value $Installation.InstallType
                                                                        $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationReturnCode' -Value $Installation.InstallationReturnCode

                                                                        If($null -ne $Installation.RestorePoint_id)
                                                                            {
                                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'RestorePoint_id' -Value $Installation.RestorePoint_id
                                                                            }
                                                                        else 
                                                                            {
                                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'RestorePoint_id' -Value "no RestorePoint"
                                                                            }
                                                                    }
                                                                        break
                                                            }
                                                    }
                                                        if ($true -ne $found) 
                                                            {
                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'InstallID' -Value "N/A"
                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationStatus' -Value "not installed"
                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'InstallModifiedTime' -Value "N/A"
                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'InstallType' -Value "N/A"
                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'InstallationReturnCode' -Value "N/A"
                                                                $Install  | Add-Member -MemberType NoteProperty -Name 'RestorePoint_id' -Value "N/A"
                                                            }
                                            }
                                                        

                                        return $DriverArray
                                                
                                    }
                                else 
                                    {
                                        Write-Host "No scan data"
                                        return $false
                                    }

                            }
                        else 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                                Return False
                            }
                    }
                if ($Modus -eq "InstalledAll") 
                    {
                        # check if data source existing and get latest datas
                         try 
                            {
                                $CheckDataSource = Test-Path -Path $DataSource -ErrorAction Stop
                            }
                        catch 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                            }
                        If ($CheckDataSource -eq $true)
                            {
                                # checking getting Tables Scan / Install / Details
                                            
                                ## DriverInstalled
                                try 
                                    {
                                        [array]$TableDriverInventory = Invoke-SqliteQuery -DataSource $DataSource -Query $QueryInstall -ErrorAction Stop
                                    }
                                catch 
                                    {
                                        Write-Host "No access to Table InventoryDetails"
                                        Return $false
                                    }
                                                    
                                If ($null -ne $TableDriverInventory)
                                    {
                                        $InventoryArray = @()

                                        foreach ($Inventory in $TableDriverInventory)
                                            {
                                                #temporay Array
                                                $TempInventory = New-Object -TypeName psobject

                                                # convert Time form Unix to UTC and local time
                                                $BaseTime = $Inventory.ModifiedTime
                                                $DateTime = [System.DateTimeOffset]::FromUnixTimeSeconds($BaseTime)

                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'RecordID' -Value $Inventory.RecordID
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverDellVersion' -Value $Inventory.DriverDellVersion
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverID' -Value $Inventory.DriverID
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverTitle' -Value $Inventory.DriverTitle
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverReleaseDate' -Value $Inventory.DriverReleaseDate
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverDescription' -Value $Inventory.DriverDescription
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverCategoryName' -Value $Inventory.DriverCategoryName                                
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverType' -Value $Inventory.DriverType
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverTypeName' -Value $Inventory.DriverTypeName
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'RebootRequired' -Value $Inventory.RebootRequired
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'CatalogVersion' -Value $Inventory.CatalogVersion
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverImportanceLevel' -Value $Inventory.DriverImportanceLevel
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverUniqeID' -Value $Inventory.DriverUniqeID
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverSize' -Value $Inventory.DriverSize
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'FileName' -Value $Inventory.FileName
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DownloadUrl' -Value $Inventory.DownloadUrl
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'ImportantUrl' -Value $Inventory.ImportantUrl
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'HashAlgorithm' -Value $Inventory.HashAlgorithm
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'HashValue' -Value $Inventory.HashValue
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'SortOrder' -Value $Inventory.SortOrder
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'IsInventoryComponent' -Value $Inventory.IsInventoryComponent                                
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'ComponentIdMatchingInventory' -Value $Inventory.ComponentIdMatchingInventory
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'Dependencies' -Value $Inventory.Dependencies
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'InventoryVersion' -Value $Inventory.InventoryVersion
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'IsDependency' -Value $Inventory.IsDependency
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'HasDependency' -Value $Inventory.HasDependency
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'IsDockUpdate' -Value $Inventory.IsDockUpdate
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'IsIsvLocked' -Value $Inventory.IsIsvLocked
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'pluginId' -Value $Inventory.pluginId
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'SharedModules' -Value $Inventory.SharedModules
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'IsBSodCausing' -Value $Inventory.IsBSodCausing
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'IsPowerAdapterRequired' -Value $Inventory.IsPowerAdapterRequired
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DeviceDescription' -Value $Inventory.DeviceDescription
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'BsodRate' -Value $Inventory.BsodRate
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'BsodVersion' -Value $Inventory.BsodVersion                                
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'DriverScanID' -Value $Inventory.DriverScan_id
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'UTCTime' -Value $DateTime.UtcDateTime
                                                $TempInventory | Add-Member -MemberType NoteProperty -Name 'LocalTime' -Value $DateTime.LocalDateTime

                                                $InventoryArray += $TempInventory
                                            }
      
                                        return $InventoryArray
                                                
                                    }
                                else 
                                    {
                                        Write-Host "No scan data"
                                        return $false
                                    }

                            }
                        else 
                            {
                                Write-Host "No Database exist" -ForegroundColor Red
                                Return False
                            }
                    }
            }
        else 
            {
                Write-Host "No PSSQLite exist"
                return "NoPSSQLite"
            }
    }

################################################################
###  Program Section                                         ###
################################################################

##########################################################
#### Check if Dell SupportAssist for Business is installed on device

If ((CheckForAppInstall -AppName "Dell SupportAssist for Business*") -eq $true)
    {
        $EventMessage = [PSCustomObject]@{
            Process = "Check installation Dell SupportAssist for Business"
            Installed = $true
            Success = "Starting collect informations from Dell SupportAssist for Business"
       } | ConvertTo-Json

       new-MSEventLog -EventId 11 -EntryType Information  -Message $EventMessage

    }
else 
    {
        $EventMessage = [PSCustomObject]@{
            Status = "Starting collect informations from Dell SupportAssist for Business"
            Installed = $false
            Success = "Stop script by Exit 1"
       } | ConvertTo-Json

       new-MSEventLog -EventId 12 -EntryType Error  -Message $EventMessage

       Exit 1
    }

##############################
#### get computer informations
#### select datas of the device for loging
$Username = ((Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName -ErrorAction SilentlyContinue).split("\"))[1]

$Vendor = ((Get-CimInstance -ClassName CIM_ComputerSystem).Manufacturer).Split(" ")[0]
$Model = (Get-CimInstance -ClassName CIM_ComputerSystem).Model
$DeviceSerie = ((Get-CimInstance -ClassName CIM_ComputerSystem).Model).Split(" ")[0]
$ServiceTag = (Get-CimInstance -ClassName CIM_BIOSElement).SerialNumber
$AssetTag = get-cimInstance -Namespace root\dcim\sysman\biosattributes -className StringAttribute | Where-Object{$_.AttributeName -eq "Asset"} | Select-Object -ExpandProperty CurrentValue
$DeviceSKU = (Get-CimInstance -Namespace root\wmi -ClassName MS_SystemInformation).SystemSKU
$OSVersion = (Get-CimInstance -ClassName CIM_OperatingSystem).Version
$WinEdition = (Get-CimInstance -ClassName CIM_OperatingSystem).Caption

##########################################################
#### getting missing drivers by Dell SupportAssist    ####
##########################################################

##############################################################
#### checking if updates availible by Dell SupportAssist  ####
$DriverUpdate = get-SATDUpdateStatus -Modus MissingDriverAllScan
$LastUpdateID = $DriverUpdate | Sort-Object ID | Select-Object -ExpandProperty ID -Last 1

#############################################
#### Checking if $DriverUpdate includes datas
if ($null -eq $DriverUpdate)
    {      
        # for Devices without updates write data with resulte no updates

        #generate a new Temp object
        $DriverArrayTemp = New-Object PSObject
        
        # build a temporary array
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'AssetTag' -Value $AssetTag -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingID' -Value "NOUPD" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingName' -Value "no updates" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingCategory' -Value "no updates" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingSeverity' -Value "NoUpdate" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingType' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDescription' -Value "This device has no updates" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingReleaseDate' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingVendorVersion' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDellVersion' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingPath' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDetails' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingComponentID' -Value "" -Force
    
        #Create the object
        [Array]$DriverArray += $DriverArrayTemp  
    }
Else
    {  
        # for Devices with updates     

        #Prepare the Table Array for log analytics
        $DriverArray = @()

        foreach ($Update in $DriverUpdate)
            {
    
            #generate a new Temp object
            $DriverArrayTemp = New-Object PSObject

            if($LastUpdateID -eq $Update.ID)
                {
                    If($update.InstallationStatus -ne "Installed")
                        {            
                                # build a temporary array
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'AssetTag' -Value $AssetTag -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingID' -Value $Update.DriverID -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingName' -Value $Update.DriverTitle -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingCategory' -Value $Update.DriverCategoryName -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingSeverity' -Value $Update.DriverImportanceLevel -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingType' -Value $Update.DriverTypeName -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDescription' -Value $Update.DriverDescription -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingReleaseDate' -Value $Update.DriverReleaseDate -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingVendorVersion' -Value $Update.DriverDellVersion -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDellVersion' -Value $Update.CatalogVersion -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingPath' -Value $Update.DownloadUrl -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDetails' -Value $Update.DriverID -Force
                                $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingComponentID' -Value $Update.ComponentIdMatchingInventory -Force

                                #Create the object
                                [Array]$DriverArray += $DriverArrayTemp
                        }
                }
                
            }
    }
   
# cover cases if varible is empty for API Upload   
If ($null -ne $DriverArray)
    {
        # Convert Array to JSON format
        $UpdateInfoJson = $DriverArray | ConvertTo-Json

        # Loging Informations to MS Event
        New-MSEventLog -EventID 11 -EntryType Information -Message $UpdateInfoJson

        $LogType = $LogTypeMissing

        #Submit the data to the API endpoint
        $params = @{
            CustomerId = $customerId
            SharedKey  = $sharedKey
            Body       = ([System.Text.Encoding]::UTF8.GetBytes($UpdateInfoJson))
            LogType    = $LogType
        }
        $LogResponse = Post-LogAnalyticsData @params
    }
else 
    {
        # for Devices without required updates

        #generate a new Temp object
        $DriverArrayTemp = New-Object PSObject
        
        # build a temporary array
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'AssetTag' -Value $AssetTag -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingID' -Value "NOUPD" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingName' -Value "no updates" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingCategory' -Value "no updates" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingSeverity' -Value "NoUpdate" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingType' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDescription' -Value "This device has no updates" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingReleaseDate' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingVendorVersion' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDellVersion' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingPath' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDetails' -Value "" -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingComponentID' -Value "" -Force
    
        #Create the object
        [Array]$DriverArray += $DriverArrayTemp

                # Convert Array to JSON format
                $UpdateInfoJson = $DriverArray | ConvertTo-Json

                # Loging Informations to MS Event
                New-MSEventLog -EventID 11 -EntryType Information -Message $UpdateInfoJson
        
                $LogType = $LogTypeMissing
        
                #Submit the data to the API endpoint
                $params = @{
                    CustomerId = $customerId
                    SharedKey  = $sharedKey
                    Body       = ([System.Text.Encoding]::UTF8.GetBytes($UpdateInfoJson))
                    LogType    = $LogType
                }
        $LogResponse = Post-LogAnalyticsData @params
    }


############################################################
#### getting installed drivers by Inventory Collector   ####
############################################################

# Get Installed base history
$DellInstalledDriver = get-SATDUpdateStatus InstalledAll

#cleanup to the lastest installbase
$InstalledArray = @()

$DellInstalledDriver = $DellInstalledDriver | Sort-Object DriverTitle, DriverScanID -Descending

#First round check
$ArrayCheck = $false

foreach ($InstDriver in $DellInstalledDriver)
    {

        if($InstalledArray.Count -gt 0)
            {
                # Check if driver exist in Array
                $ArrayCheck = $InstalledArray.DriverName.Contains($InstDriver.DriverTitle)
            }

        if ($ArrayCheck -eq $false )
            {
                #generate a new Temp object
                $InstalledArrayTemp  = New-Object PSObject

                # build a temporary array
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'AssetTag' -Value $AssetTag -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemSKU' -Value $DeviceSKU -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'OSEdition' -Value $WinEdition -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'OSVersion' -Value $OSVersion -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverName' -Value $InstDriver.DriverTitle -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverVersion' -Value $InstDriver.InventoryVersion -Force
                $InstalledArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverCategory' -Value $InstDriver.DriverCategoryName -Force

                #Create the object
                [Array]$InstalledArray  += $InstalledArrayTemp
            }
    }

# Convert Array to JSON format
$InstalledInfoJson = $InstalledArray | ConvertTo-Json

# Loging Informations to MS Event
New-MSEventLog -EventID 11 -EntryType Information -Message $InstalledInfoJson

$LogType = $LogTypeInstalled

#Submit the data to the API endpoint
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($InstalledInfoJson))
    LogType    = $LogType
}
$LogResponse = Post-LogAnalyticsData @params


##################################
#### Getting CIM UpdateEvents ####
##################################
$CIMUpdateEvents = $DriverUpdate

#Prepare the Table Array for log analytics
$CIMUpdateArray = @()

foreach ($UpdateEvent in $CIMUpdateEvents)
        {
            If($UpdateEvent.InstallationStatus -eq "Installed")
                {
                    #generate a new Temp object
                    $CIMUpdateTemp = New-Object PSObject

                    # build a temporary array
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'AssetTag' -Value $AssetTag -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ComponentType' -Value $UpdateEvent.DriverTypeName -Force

                    #adjusting output depends on Restart is required or not
                    If($UpdateEvent.InstallationReturnCode -eq "RequiresReboot")
                        {
                            If($UpdateEvent.DriverType -eq "BIOS")
                                {
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventType' -Value $UpdateEvent.InstallationStatus -Force
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventTypeValue' -Value "BIOS Updated" -Force
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCode' -Value $UpdateEvent.InstallationStatus -Force
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCodeValue' -Value "REBOOT_REQUIRED" -Force
                                }
                            else 
                                {
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventType' -Value $UpdateEvent.InstallationStatus -Force
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventTypeValue' -Value "Update Completed" -Force
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCode' -Value $UpdateEvent.InstallationStatus -Force
                                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCodeValue' -Value "REBOOT_REQUIRED" -Force
                                }
                        }
                    else 
                        {
                            $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventType' -Value $UpdateEvent.InstallationStatus -Force
                            $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventTypeValue' -Value "Update Completed" -Force
                            $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCode' -Value $UpdateEvent.InstallationStatus -Force
                            $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCodeValue' -Value "SUCCESS" -Force
                        }

                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'SWBReleaseID' -Value $UpdateEvent.DriverId -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'DriverName' -Value $UpdateEvent.DriverTitle -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'Severity' -Value $UpdateEvent.ReclassifiedDriverImportance -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'DriverVersion' -Value $UpdateEvent.CatalogVersion -Force
                    $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ReleaseDate' -Value $UpdateEvent.DriverReleaseDate -Force
        
                    #Create the object
                    [Array]$CIMUpdateArray += $CIMUpdateTemp
                }        
        }

# Convert Array to JSON format
$EventInfoJson = $CIMUpdateArray | ConvertTo-Json

# Loging Informations to MS Event
New-MSEventLog -EventID 11 -EntryType Information -Message $EventInfoJson

$LogType = $LogTypeEvents

#Submit the data to the API endpoint
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($EventInfoJson))
    LogType    = $LogType
}
$LogResponse = Post-LogAnalyticsData @params

#####################################
#### Getting CIM PenetrationRate ####
#####################################

$CIMPenetrationRate =  [Math]::Round(($InstalledArray.Count - $DriverArray.Count) * 100 / $InstalledArray.Count,2)

#Prepare the Table Array for log analytics
$CIMPenetrationArray = New-Object PSObject

$CIMPenetrationArray | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
$CIMPenetrationArray | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
$CIMPenetrationArray | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
$CIMPenetrationArray | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
$CIMPenetrationArray | Add-Member -MemberType NoteProperty -Name 'AssetTag' -Value $AssetTag -Force
$CIMPenetrationArray | Add-Member -MemberType NoteProperty -Name 'SystemSKU' -Value $DeviceSKU -Force    
$CIMPenetrationArray | Add-Member -MemberType NoteProperty -Name 'PenetrationRate' -Value $CIMPenetrationRate -Force

# Convert Array to JSON format
$PenetrationRateInfoJson = $CIMPenetrationArray | ConvertTo-Json

# Loging Informations to MS Event
New-MSEventLog -EventID 11 -EntryType Information -Message $PenetrationRateInfoJson

$LogType = $LogTypePenetrationRate

#Submit the data to the API endpoint
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($PenetrationRateInfoJson))
    LogType    = $LogType
}
$LogResponse = Post-LogAnalyticsData @params


#######################################
#### Getting CIM NonComplianceList ####
#######################################
$CIMNonComplianceList = $DriverUpdate | Where-Object {$_.InstallationStatus -ne "not installed" -and ($_.InstallationReturnCode -ne "Succeeded" -and $_.InstallationReturnCode -ne "RequiresReboot")}

foreach ($Compliance in $CIMNonComplianceList)
    {
        #generate a new Temp object
        $CIMNonComplianceTemp = New-Object PSObject

        # build a temporary array
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'AssetTag' -Value $AssetTag -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'SystemSKU' -Value $DeviceSKU -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'ComponentType' -Value $Compliance.DriverTypeName
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'SWBReleaseID' -Value $Compliance.DriverId -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'DriverName' -Value $Compliance.DriverTitle -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'Severity' -Value $Compliance.DriverImportanceLevel -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'DriverVersion' -Value $Compliance.CatalogVersion -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'ReleaseDate' -Value $Compliance.DriverReleaseDate -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'InstallStatus' -Value $Compliance.InstallationStatus -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'ReturnCode' -Value $Compliance.InstallationReturnCode -Force

   
        #Create the object
        [Array]$CIMNonComplianceListArray += $CIMNonComplianceTemp
    }
# Convert Array to JSON format
$ComplianceInfoJson = $CIMNonComplianceListArray | ConvertTo-Json

# Loging Informations to MS Event
New-MSEventLog -EventID 11 -EntryType Information -Message $ComplianceInfoJson

$LogType = $LogTypeNonComplianceList

#Submit the data to the API endpoint
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($ComplianceInfoJson))
    LogType    = $LogType
}
$LogResponse = Post-LogAnalyticsData @params