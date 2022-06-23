<#
_author_ = Sven Riebe <sven_riebe@Dell.com>
_twitter_ = @SvenRiebe
_version_ = 1.0
_Dev_Status_ = Test
Copyright © 2022 Dell Inc. or its subsidiaries. All Rights Reserved.

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
1.0.1   using Device Catalog XML to get more details for driver update

Knowing Issues
-   tbd
#>

#>

<#
.Synopsis
   This PowerShell collecting all missing drivers based on the Dell Command Update Scan and upload these informations to LogAnalytics (portal.azure.com)
   IMPORTANT: This script need to install Dell Command Update or Dell Support Assist for Business first otherwise you will get no details about installed drivers
   IMPORTANT: LogAnalytics is a service from Microsoft and is NOT free of charge please checking your MS contracts if you have this service availible otherwise you need to order this service.
   IMPORTANT: This script does not reboot the system to apply or query system.
   IMPORTANT: This script is supporting Dell Business Devices only (Optiplex, Precision, Latitude and Mobile XPS)

.DESCRIPTION
   This PowerShell is starting the Dell Command Update driver scan and collect all installed Driver Informations Driver-Name, Driver-Version and Driver-Category, Driver-Severity and using the LogAnalytics API to upload all informations directly to portal.azure.com / LogAnalytics Service.
   
#>

<#The functions Function Build-Signature and Function Post-LogAnalyticsData was developed by https://www.systanddeploy.com/2022/05/intune-reporting-with-log-analytics.html and used by me without any change #>

#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = "cb9801e8-b5b0-4dfe-ab1e-ff8a17642010"
$SharedKey = 'y15hSyg+5xekllOCyIxIW8LbuipepJCiR6ToGCfu5Umi5lqhaSCr19toWrGGtJQ5REcV1TeQCZaPvxfhwfgepw=='
$LogType = "DellDriverMissing"
$TimeStampField = ""
#***********************************************************************************************************

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


# Prepare Device basic datas

# get details of device
$deviceData = Get-ComputerInfo

$DCUPathCheck = Test-Path -Path 'C:\Program Files (x86)\Dell\CommandUpdate\'

If ($DCUPathCheck -eq 'True')
    {
    # run a driver scan with Dell Command Update (based on version 32/64)
    $DCUScan = & 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe' /scan
    }
Else
    {

    $DCUPathCheck = Test-Path -Path 'C:\Program Files\Dell\CommandUpdate\'
    
    If ($DCUPathCheck -eq 'True')
        {
        # run a driver scan with Dell Command Update (based on version 32/64)
        $DCUScan = & 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe' /scan
        }

    Else
        {

        Write-Host "No DCU installed. You need to install first"

        Exit = 1

        }

    }

# select datas of the device for loging
$Username = ($deviceData.CsUserName).Split("\")[-1]
$Vendor = ($deviceData.CsManufacturer).Split(" ")[0]
$Model = ($deviceData.CsModel)
$DeviceSerie = ($deviceData.CsModel).Split(" ")[0]
$ServiceTag = $deviceData.BiosSeralNumber
$DeviceSKU = $deviceData.CsSystemSKUNumber

# Spliting text strings in single values in one array
$DriverString = $DCUScan | Select-String ("--")
[Array]$DriverTemp1 = $DriverString -split ": "
[Array]$DriverTemp2 = $DriverTemp1 -split " -- "
[Array]$DriverTemp3 = $DriverTemp2 -split " - "

#Collect details from Dell Driver Device Catalog
$catalogPath = $env:ProgramData+'\Dell\UpdateService\Temp'
$CatalogFileName = Get-ChildItem $catalogPath | Where-Object Name -Like "*$DeviceSKU*xml" | select -ExpandProperty Name
[XML]$DeviceCatalog = Get-Content $catalogPath\$CatalogFileName



#Prepare the Table Array for log analytics
$DriverArray = @()

# check count of values in the array DriverTemp3
$count = $DriverTemp3.Count

# Index counter to get the array values and move these to differten Collums
$Index = 0

for ($i = 1; $i -le $count)
    {
    
    # Temp Var to get XML Datas from Device Catalog
    $TempXMLCatalog = ($DeviceCatalog.Manifest.SoftwareComponent)| Where-Object {$_.releaseid -like $DriverTemp3[$Index]}

    # preselect xml values for new array
    $TempDriverMissingName = $TempXMLCatalog.Name.Display | Select-Object -ExpandProperty '#cdata-section'
    $TempDriverMissingCategory = $TempXMLCatalog.Category.Display | Select-Object -ExpandProperty '#cdata-section'
    $TempDriverMissingSeverity = $TempXMLCatalog.Criticality.Display | Select-Object -ExpandProperty '#cdata-section'
    $TempDriverMissingType = $TempXMLCatalog.ComponentType.Display | Select-Object -ExpandProperty '#cdata-section'
    $TempDriverMissingDescription = $TempXMLCatalog.Description.Display | Select-Object -ExpandProperty '#cdata-section'
    $TempDriverMissingReleaseDate = $TempXMLCatalog.releaseDate
    $TempDriverMissingVendorVersion = $TempXMLCatalog.vendorVersion
    $TempDriverMissingDellVersion = $TempXMLCatalog.dellVersion
    $TempDriverMissingPath = "dl.dell.com/"+$TempXMLCatalog.path
    $TempDriverMissingDetails = $TempXMLCatalog.ImportantInfo | Select-Object -ExpandProperty URL
    $TempDriverMissingComponentID = $TempXMLCatalog.SupportedDevices.Device | select -ExpandProperty componentID

    
    
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
    $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingID' -Value $DriverTemp3[$Index] -Force
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
    $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverMissingComponentID' -Value $TempDriverMissingComponentID -Force
    

    #Create the object
    [Array]$DriverArray += $DriverArrayTemp

    #step up counter and index
    $i = $i+5
    $index = $Index +5
                        
    }

# Convert Array to JSON format
$DeviceInfoJson = $DriverArray | ConvertTo-Json

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($DeviceInfoJson))
    LogType    = $LogType 
}

$LogResponse = Post-LogAnalyticsData @params
