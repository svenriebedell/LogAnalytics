<#
_author_ = Sven Riebe <sven_riebe@Dell.com>
_twitter_ = @SvenRiebe
_version_ = 1.0.0
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

1.0.0   inital version (relace Intune_1_Detection_Driver_Installed.ps1 and Intune_1_Detection_Driver_Missing.ps1)

Knowing Issues
-   tbd
#>

#>

<#
.Synopsis
   This PowerShell collecting data from Dell Command | Update like Drivers need to updated, installed drivers and update results. It will generate 3 custom table in Microsoft LogAnalytics missing/installed/Results and upload these informations to LogAnalytics (portal.azure.com)
   IMPORTANT: This script need to install Dell Command Update first otherwise you will get no details about installed/missing drivers
   IMPORTANT: LogAnalytics is a service from Microsoft and is NOT free of charge please checking your MS contracts if you have this service availible otherwise you need to order this service.
   IMPORTANT: This script does not reboot the system to apply or query system.
   IMPORTANT: This script is supporting Dell Business Devices only (Optiplex, Precision, Latitude and Mobile XPS)

.DESCRIPTION
   This PowerShell is starting the Dell Command Update driver scan and collect all installed Driver Informations Driver-Name, Driver-Version and Driver-Category, Driver-Severity and using the LogAnalytics API to upload all informations directly to portal.azure.com / LogAnalytics Service.
   
#>

################################################################
###  Variables Section                                       ###
################################################################

#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = "Your LogAnalytics ID"
$SharedKey = "your LogAnalytics Key"
$LogTypeInstalled = "DellDriverInstalled"                   # if you are using the Dell DCU Dashboard, do not change this as the queries will no longer run successfully
$LogTypeMissing = "DellDriverMissing"                       # if you are using the Dell DCU Dashboard, do not change this as the queries will no longer run successfully
$LogTypeEvents = "DellUpdateEvents"                         # if you are using the Dell DCU Dashboard, do not change this as the queries will no longer run successfully
$LogTypePenetrationRate = "DellUpdatePenetrationRate"       # if you are using the Dell DCU Dashboard, do not change this as the queries will no longer run successfully
$LogTypeNonComplianceList = "DellUpdateNonComplianceList"   # if you are using the Dell DCU Dashboard, do not change this as the queries will no longer run successfully
$TimeStampField = ""
#***********************************************************************************************************

# Temp folder used for some processes all files will be deleted later
$Temp_Folder = "C:\Temp\"

## Do not change ##
$DCUProgramName = ".\dcu-cli.exe"
$DCUPath = (Get-CimInstance -ClassName Win32_Product -Filter "Name like '%Dell%Command%Update%'").InstallLocation
$CIMNamespace = "root/Dell/PlatformUpdateEvents"
$MSEventLogName = "Dell"
$MSEventSource = "DCU LogAnalytics"


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

# Function using DCU to identify missings Updates
Function Get-MissingDriver
    {

        Set-Location -Path $DCUPath
        # DCU scan only generate a XML report with missing drivers
        Start-Process -FilePath $DCUProgramName -ArgumentList "/scan -report=$Temp_Folder" -Wait -WindowStyle Hidden

        # Get Catalog file name of Scan Report
        $ReportFileName = Get-ChildItem $Temp_Folder | Where-Object Name -Like "DCUApp*Update*xml" | Select-Object -ExpandProperty Name

        # read XML File in a variable
        [XML]$MissingDriver = Get-Content $Temp_Folder$ReportFileName

        $DriverArrayXML = $MissingDriver.updates.update

        foreach ($Driver in $DriverArrayXML) 
            {
                        
            # build a temporary array
            $DriverArrayTemp = New-Object -TypeName psobject
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverID' -Value $Driver.Release
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Name' -Value $Driver.name
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Severity' -Value $Driver.urgency
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Category' -Value $Driver.Category
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ReleaseDate' -Value $Driver.Date
            
            $DriverArrayTemp

            }
       
        #Delete temporary report file of dcu from temp folder
        Remove-Item -Path $Temp_Folder$ReportFileName -Force

        # Set folder to root
        Set-Location \

    }

# Function checking if DCU is installed on a device
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
          $regKeys = Get-ChildItem $uninstallKey | foreach { Get-ItemProperty $_.PsPath }


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

function get-DCUCIM 
    {
        param (
            [Parameter(Mandatory = $true)][ValidateSet("UpdateEvents", "NonComplianceList", "PenetrationRate")][string]$CIMClass
        )
        
        Get-CimInstance -Namespace $CIMNamespace -ClassName $CIMClass
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
                [Parameter(mandatory=$true)][ValidateSet('UpdateCounter','MissingDriverLastScan','MissingDriverAllScan')][String]$Modus
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
                    1.0.0 Initial Version
                    1.0.1 correct install check and add update function
        
        
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
                                        Write-Host "Module" $ModuleName "exist" -ForegroundColor Green
                                        Write-Host "Module" $ModuleName "will import now to powershell"
                                        
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
                                                Write-Host "Module" $ModuleName "will import now to powershell"
                                                
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

If (CheckForAppInstall -AppName "Dell SupportAssist for Business*" -eq $true)
    {
        $EventMessage = [PSCustomObject]@{
            Process = "Check installation Dell SupportAssist for Business"
            Installed = $true
            Status = "Starting collect informations from Dell SupportAssist for Business"
       } | ConvertTo-Json

       new-MSEventLog -EventId 11 -EntryType Information  -Message $EventMessage

    }
else 
    {
        $EventMessage = [PSCustomObject]@{
            Status = "Starting collect informations from Dell SupportAssist for Business"
            Installed = $false
            Status = "Stop script by Exit 1"
       } | ConvertTo-Json

       new-MSEventLog -EventId 12 -EntryType Error  -Message $EventMessage

       Exit 1
    }

###############################
#### Check Tempary Folder exist

if ((Test-Path -Path $Temp_Folder) -eq $false)
    {

        $EventMessage = [PSCustomObject]@{
            Process = "Check folder " + $Temp_Folder +" is available"
            Exist = $false
            Status = "Folder does not exist on device and will generated now"
        } | ConvertTo-Json

        new-MSEventLog -EventId 12 -EntryType Error -Message $EventMessage

        New-Item -Path $Temp_Folder -ItemType Directory

        if ((Test-Path -Path $Temp_Folder) -eq $false)
            {
                $EventMessage = [PSCustomObject]@{
                    Process = "Generate Folder " + $Temp_Folder
                    Exist = $false
                    Status = "Failure to make directory " + $Temp_Folder + "Script stops by Exit 1"
                } | ConvertTo-Json
        
                new-MSEventLog -EventId 12 -EntryType Error -Message $EventMessage

                Exit 1
            }
        else 
            {
                $EventMessage = [PSCustomObject]@{
                    Process = "Generate Folder " + $Temp_Folder
                    Exist = $true
                    Status = "Success to make directory " + $Temp_Folder
                } | ConvertTo-Json
        
                new-MSEventLog -EventId 11 -EntryType Information -Message $EventMessage
            }

    }
else 
    {
        $EventMessage = [PSCustomObject]@{
            Process = "Check folder " + $Temp_Folder +" is available"
            Exist = $true
            Status = "Starting with collecting ComputerInformations"
        } | ConvertTo-Json

        new-MSEventLog -EventId 11 -EntryType Information -Message $EventMessage
    }


##############################
#### get computer informations
$deviceData = Get-ComputerInfo

#### select datas of the device for loging
$Username = ($deviceData.CsUserName).Split("\")[-1]
$Vendor = ($deviceData.CsManufacturer).Split(" ")[0]
$Model = ($deviceData.CsModel)
$DeviceSerie = ($deviceData.CsModel).Split(" ")[0]
$ServiceTag = $deviceData.BiosSeralNumber
$DeviceSKU = $deviceData.CsSystemSKUNumber
$OSVersion = $deviceData.OsVersion
$WinEdition = $deviceData.OsName

##########################################################
#### getting missing drivers by Dell SupportAssist    ####
##########################################################

##############################################################
#### checking if updates availible by Dell SupportAssist  ####
$DriverUpdate = get-SATDUpdateStatus -Modus MissingDriverAllScan

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
        

            # build a temporary array
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingID' -Value $Update.DriverID -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingName' -Value $Update.DriverTitle -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingCategory' -Value $Update.DriverCategory -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingSeverity' -Value $Update.DriverImportanceLevel -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingType' -Value $Update.DriverType -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDescription' -Value $Update.DriverDescription -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingReleaseDate' -Value $Update.DriverReleaseDate -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingVendorVersion' -Value $Update.DriverDellVersion -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDellVersion' -Value $Update.CatalogVersion -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingPath' -Value $Update.DownloadUrl -Force
           # $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDetails' -Value $Update.DriverID -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingComponentID' -Value $Update.ComponentIdMatchingInventory -Force
    
<#
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

#>

            #Create the object
            [Array]$DriverArray += $DriverArrayTemp
                       
            }
    }

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

############################################################
#### getting installed drivers by Dell Command | Update ####
############################################################
$catalogPath = $env:ProgramData+'\Dell\UpdateService\Temp'
$CatalogFileName = Get-ChildItem $catalogPath | Where-Object Name -Like "*Inventory*xml" | Select-Object -ExpandProperty Name
[xml]$DriverInventory = Get-Content $catalogPath\$CatalogFileName
[Array]$DriverIST = $DriverInventory.SVMInventory.Device.application |Select-Object Display, Version, componentType | Sort-Object Display

#Prepare the Table Array for log analytics
$DriverArray = @()

foreach ($Driver in $DriverIST)
        {
        
        #generate a new Temp object
        $DriverArrayTemp = New-Object PSObject

        # build a temporary array
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemSKU' -Value $DeviceSKU -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'OSEdition' -Value $WinEdition -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'OSVersion' -Value $OSVersion -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverName' -Value $Driver.display -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverVersion' -Value $Driver.version -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverCategory' -Value $Driver.componentType -Force

        #Create the object
        [Array]$DriverArray += $DriverArrayTemp
                        
        }

# Convert Array to JSON format
$InstalledInfoJson = $DriverArray | ConvertTo-Json

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
$CIMUpdateEvents = $updat

#Prepare the Table Array for log analytics
$CIMUpdateArray = @()

foreach ($UpdateEvent in $CIMUpdateEvents)
        {
        
        # Temp Var to get XML Datas from Device Catalog
        $TempXMLCatalog = ($DeviceCatalog.Manifest.SoftwareComponent)| Where-Object {$_.releaseid -like $UpdateEvent.SWBReleaseID}

        # Switch code to value
        $ComponentTypeValue = switch ($UpdateEvent.componentType) 
            {
                1 {"BIOS"}
                2 {"Driver"}
                3 {"Firmware"}
                4 {"Applications"}
                5 {"Utilities"}

            }
        
        $ExecutionReturnCodeValue = switch ($UpdateEvent.ExecutionReturnCode ) 
            {
                0 {"SUCCESS"}
                1 {"ERROR"}
                2 {"REBOOT_REQUIRED"}
                3 {"DEP_SOFT_ERROR"}
                4 {"DEP_HARD_ERROR"}
                5 {"PLATFORM_UNSUPPORTED"}
                6 {"REBOOTING_SYSTEM"}
                7 {"PASSWORD_REQUIRED"}
                8 {"NO_DOWNGRADE"}
                9 {"REBOOT_UPDATE_PENDING"}
                10 {"INVALID_CMDLINE_SPEC"}
                11 {"UNKNOWN_OPTION"}
                12 {"AUTHORIZATION_LEVEL"}

            }

            $EventTypeValue = switch ($UpdateEvent.EventType) 
            {
                0 {"Update Completed"}
                1 {"Update Failed"}
                2 {"BIOS Updated"}

            }

        #generate a new Temp object
        $CIMUpdateTemp = New-Object PSObject

        # build a temporary array
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'SystemSKU' -Value $DeviceSKU -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ComponentType' -Value $UpdateEvent.componentType -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ComponentType' -Value $ComponentTypeValue -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventType' -Value $UpdateEvent.EventType -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'EventTypeValue' -Value $EventTypeValue -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCode' -Value $UpdateEvent.ExecutionReturnCode -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionReturnCodeValue' -Value $ExecutionReturnCodeValue -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'SWBReleaseID' -Value $UpdateEvent.SWBReleaseID -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'DriverName' -Value $TempXMLCatalog.Name.Display.'#cdata-section' -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'Severity' -Value $TempXMLCatalog.Criticality.Display.'#cdata-section' -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'DriverVersion' -Value $TempXMLCatalog.vendorVersion -Force
        $CIMUpdateTemp | Add-Member -MemberType NoteProperty -Name 'ReleaseDate' -Value $TempXMLCatalog.releaseDate -Force

        
        
        #Create the object
        [Array]$CIMUpdateArray += $CIMUpdateTemp
                        
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
$CIMPenetrationRate = get-DCUCIM -CIMClass PenetrationRate

#Prepare the Table Array for log analytics
$CIMUpdateArray = New-Object PSObject

$CIMUpdateArray | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
$CIMUpdateArray | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
$CIMUpdateArray | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
$CIMUpdateArray | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
$CIMUpdateArray | Add-Member -MemberType NoteProperty -Name 'SystemSKU' -Value $DeviceSKU -Force    
$CIMUpdateArray | Add-Member -MemberType NoteProperty -Name 'PenetrationRate' -Value $CIMPenetrationRate.UpToDateRate -Force

# Convert Array to JSON format
$PenetrationRateInfoJson = $CIMUpdateArray | ConvertTo-Json

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
$CIMNonComplianceList = get-DCUCIM -CIMClass NonComplianceList

#prepare data
[array]$NonComplianceList = @()
[array]$NonComplianceList = $CIMNonComplianceList.NCUpdateList.Split("},{")
$NonComplianceList = $NonComplianceList | Where-Object { $_ -ne "[" }
$NonComplianceList = $NonComplianceList | Where-Object { $_ -ne "]" }
$NonComplianceList = $NonComplianceList | Where-Object { $_ -ne "" }

foreach ($Non in $NonComplianceList)
    {
        #generate a new Temp object
        $NonTempArray = New-Object PSObject

        $NonTemp = $Non.Split("""")
        $NonTemp = $NonTemp | Where-Object { $_ -ne "" }
        $NonTemp = $NonTemp | Where-Object { $_ -ne ":" }

        # build a temporary array
        $NonTempArray | Add-Member -MemberType NoteProperty -Name 'Part' -Value $NonTemp[0] -Force
        $NonTempArray | Add-Member -MemberType NoteProperty -Name 'Value' -Value $NonTemp[1] -Force

        [Array]$NonComplianceList += $NonTempArray
    }


#Prepare the Table Array for log analytics
$CIMNonComplianceListArray = @()

foreach ($Compliance in $NonComplianceList)
    {
        If ($Compliance.Part -eq "SWB")
            {
        # Temp Var to get XML Datas from Device Catalog
        $TempXMLCatalog = ($DeviceCatalog.Manifest.SoftwareComponent)| Where-Object {$_.releaseid -like $Compliance.Value}

        #generate a new Temp object
        $CIMNonComplianceTemp = New-Object PSObject

        # build a temporary array
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'SystemSKU' -Value $DeviceSKU -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'ComponentType' -Value $TempXMLCatalog.ComponentType.Display.'#cdata-section'
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'SWBReleaseID' -Value $Compliance.Value -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'DriverName' -Value $TempXMLCatalog.Name.Display.'#cdata-section' -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'Severity' -Value $TempXMLCatalog.Criticality.Display.'#cdata-section' -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'DriverVersion' -Value $TempXMLCatalog.vendorVersion -Force
        $CIMNonComplianceTemp | Add-Member -MemberType NoteProperty -Name 'ReleaseDate' -Value $TempXMLCatalog.releaseDate -Force

        
        
        #Create the object
        [Array]$CIMNonComplianceListArray += $CIMNonComplianceTemp
                        
        }
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