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

Knowing Issues
-   tbd
#>

#>

<#
.Synopsis
   This PowerShell collecting all setting details form Dell Optimizer and upload these informations to LogAnalytics (portal.azure.com)
   IMPORTANT: This script need to install Dell Optimizer or first otherwise you will get no details about installed drivers
   IMPORTANT: LogAnalytics is a service from Microsoft and is NOT free of charge please checking your MS contracts if you have this service availible otherwise you need to order this service.
   IMPORTANT: This script does not reboot the system to apply or query system.
   IMPORTANT: This script is supporting Dell Business Devices only (Optiplex, Precision, Latitude and Mobile XPS) which are support Dell Optimizer application

.DESCRIPTION
   This PowerShell is starting the Dell Optimizer and collect all application settings excl. Applications performance and using the LogAnalytics API to upload all informations directly to portal.azure.com / LogAnalytics Service.
   
#>

<#The functions Function Build-Signature and Function Post-LogAnalyticsData was developed by https://www.systanddeploy.com/2022/05/intune-reporting-with-log-analytics.html and used by me without any change #>

#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = "cb9801e8-b5b0-4dfe-ab1e-ff8a17642010"
$SharedKey = 'y15hSyg+5xekllOCyIxIW8LbuipepJCiR6ToGCfu5Umi5lqhaSCr19toWrGGtJQ5REcV1TeQCZaPvxfhwfgepw=='
$LogType = "DellOptimizerSettings"
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

# Test if Dell Optimizer is installed on the machine
$DOPath = $env:ProgramFiles + "\Dell\DellOptimizer"
$DOFile = $DOPath + "\do-cli.exe"
$DOPathCheck = Test-Path -Path $DOPath

If ($DOPathCheck -eq 'True')
    {
    # run a query to collect the Dell Optimizer settings of a device
    $DOConfigScan = & $DOFile /get
    }
Else
    {

    Write-Host "No Dell Optimier installed. You need to install first"

    Exit = 1

    }

# select datas of the device for loging
$Username = ($deviceData.CsUserName).Split("\")[-1]
$Vendor = ($deviceData.CsManufacturer).Split(" ")[0]
$Model = ($deviceData.CsModel)
$DeviceSerie = ($deviceData.CsModel).Split(" ")[0]
$ServiceTag = $deviceData.BiosSeralNumber
$DeviceSKU = $deviceData.CsSystemSKUNumber

$DOConfigScanTemp = ($DOConfigScan.split(":")).trim(" ")
$DOConfigScanTempCounter = $DOConfigScanTemp.count - 5 #-5 kills empty lines at the end of this array

# Index counter to get the array values and move these to differten Collums
$Index = 0

#Prepare the Table Array for log analytics
$DOArray = @()

for ($i = 1; $i -le $DOConfigScanTempCounter)
    {
  
    #generate a new Temp object
    $DOArrayTemp = New-Object PSObject
        
    # build a temporary array
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Number' -Value $DOConfigScanTemp[$index + 0] -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Name' -Value $DOConfigScanTemp[$index + 3] -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Value' -Value $DOConfigScanTemp[$index + 5] -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Description' -Value $DOConfigScanTemp[$index + 7] -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'SupportedValues' -Value $DOConfigScanTemp[$index + 9] -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'IsReadOnly' -Value $DOConfigScanTemp[$index + 11] -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'IsLocked' -Value $DOConfigScanTemp[$index + 13] -Force
    
    #Create the object
    [Array]$DOArray += $DOArrayTemp
    
    #step up counter and index
    $i = $i+15
    $index = $Index +15
                        
    }

# Convert Array to JSON format
$DOInfoJson = $DOArray | ConvertTo-Json

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($DOInfoJson))
    LogType    = $LogType 
}

$LogResponse = Post-LogAnalyticsData @params
