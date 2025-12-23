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
function Get-DCU-Installed 
    {

    If($null -ne $DCUPath)
        {

        $true

        }
    else 
        {
        
        $false

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


################################################################
###  Program Section                                         ###
################################################################

##########################################################
#### Check if Dell Command | Update is installed on device

If (Get-DCU-Installed -eq $true)
    {
        $EventMessage = [PSCustomObject]@{
            Process = "Check installation Dell Command | Update"
            Installed = $true
            Status = "Starting collect informations from Dell Command | Update"
       } | ConvertTo-Json

       new-MSEventLog -EventId 11 -EntryType Information  -Message $EventMessage

    }
else 
    {
        $EventMessage = [PSCustomObject]@{
            Process = "Check installation Dell Command | Update"
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
#### getting missing drivers by Dell Command | Update ####
##########################################################

##############################################################
#### checking if updates availible by by Dell Command | Update
$DriverUpdate = Get-MissingDriver

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

        #Collect details from Dell Driver Device Catalog
        $catalogPath = $env:ProgramData+'\Dell\UpdateService\Temp'
        $CatalogFileName = Get-ChildItem $catalogPath | Where-Object Name -Like "*$DeviceSKU*xml" | Select-Object -ExpandProperty Name
        [XML]$DeviceCatalog = Get-Content $catalogPath\$CatalogFileName

        
        #Prepare the Table Array for log analytics
        $DriverArray = @()

        foreach ($Update in $DriverUpdate)
            {
    
            # Temp Var to get XML Datas from Device Catalog
            $TempXMLCatalog = ($DeviceCatalog.Manifest.SoftwareComponent)| Where-Object {$_.releaseid -like $Update.DriverID}

            # preselect xml values for new array
            [array]$TempDriverMissingNameTemp = $TempXMLCatalog.Name.Display | Select-Object -ExpandProperty '#cdata-section'
            [array]$TempDriverMissingCategoryTemp = $TempXMLCatalog.Category.Display | Select-Object -ExpandProperty '#cdata-section'
            [array]$TempDriverMissingSeverityTemp = $TempXMLCatalog.Criticality.Display | Select-Object -ExpandProperty '#cdata-section'
            [array]$TempDriverMissingTypeTemp = $TempXMLCatalog.ComponentType.Display | Select-Object -ExpandProperty '#cdata-section'
            [array]$TempDriverMissingDescriptionTemp = $TempXMLCatalog.Description.Display | Select-Object -ExpandProperty '#cdata-section'
            [array]$TempDriverMissingReleaseDateTemp = $TempXMLCatalog.releaseDate
            [array]$TempDriverMissingVendorVersionTemp = $TempXMLCatalog.vendorVersion
            [array]$TempDriverMissingDellVersionTemp = $TempXMLCatalog.dellVersion
            [array]$TempDriverMissingPathTemp = "dl.dell.com/"+$TempXMLCatalog.path
            [array]$TempDriverMissingDetailsTemp = $TempXMLCatalog.ImportantInfo | Select-Object -ExpandProperty URL
            [array]$TempDriverMissingComponentIDTemp = $TempXMLCatalog.SupportedDevices.Device

            # select first values in case of some Driver ID´s have more than one input in the catalog.
            $TempDriverMissingName = $TempDriverMissingNameTemp | Select-Object -First 1
            $TempDriverMissingCategory = $TempDriverMissingCategoryTemp | Select-Object -First 1
            $TempDriverMissingSeverity = $TempDriverMissingSeverityTemp | Select-Object -First 1
            $TempDriverMissingType = $TempDriverMissingTypeTemp | Select-Object -First 1
            $TempDriverMissingDescription = $TempDriverMissingDescriptionTemp | Select-Object -First 1
            $TempDriverMissingReleaseDate = $TempDriverMissingReleaseDateTemp | Select-Object -First 1
            $TempDriverMissingVendorVersion = $TempDriverMissingVendorVersionTemp | Select-Object -First 1
            $TempDriverMissingDellVersion = $TempDriverMissingDellVersionTemp | Select-Object -First 1
            $TempDriverMissingPath = $TempDriverMissingPathTemp | Select-Object -First 1
            $TempDriverMissingDetails = $TempDriverMissingDetailsTemp | Select-Object -First 1
            $TempDriverMissingComponentID = $TempDriverMissingComponentIDTemp | Select-Object -First 1
      
    
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
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingName' -Value $TempDriverMissingName -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingCategory' -Value $TempDriverMissingCategory -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingSeverity' -Value $TempDriverMissingSeverity -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingType' -Value $TempDriverMissingType -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDescription' -Value $TempDriverMissingDescription -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingReleaseDate' -Value $TempDriverMissingReleaseDate -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingVendorVersion' -Value $TempDriverMissingVendorVersion -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDellVersion' -Value $TempDriverMissingDellVersion -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingPath' -Value $TempDriverMissingPath -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingDetails' -Value $TempDriverMissingDetails -Force
            $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingComponentID' -Value $TempDriverMissingComponentID.componentID -Force
    

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
$CIMUpdateEvents = get-DCUCIM -CIMClass UpdateEvents

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