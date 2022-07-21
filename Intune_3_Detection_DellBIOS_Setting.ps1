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
-   If a app in learning modus without process path the app fields for upload are not correct. The reason for app without process path are e.g. configure learning app by script without check if app is installed on the device.
#>

#>

<#
.Synopsis
   This PowerShell collecting App Learing and App Profile form Dell Optimizer and upload these informations to LogAnalytics (portal.azure.com)
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
$LogType = "DellBIOSSetting"
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


# select datas of the device for loging
$Username = ($deviceData.CsUserName).Split("\")[-1]
$Vendor = ($deviceData.CsManufacturer).Split(" ")[0]
$Model = ($deviceData.CsModel)
$DeviceSerie = ($deviceData.CsModel).Split(" ")[0]
$ServiceTag = $deviceData.BiosSeralNumber
$DeviceSKU = $deviceData.CsSystemSKUNumber

# select BIOS settings

$BIOSData = Get-CimInstance -Namespace root/DCIM/SYSMAN/biosattributes -ClassName EnumerationAttribute
$BIOSInteger = Get-CimInstance -Namespace root/DCIM/SYSMAN/biosattributes -ClassName IntegerAttribute
$BIOSString = Get-CimInstance -Namespace root/DCIM/SYSMAN/biosattributes -ClassName StringAttribute



#Prepare the Table Array for log analytics
$BIOSArray = @()


# select $BIOSData values
foreach ($Setting in $BIOSData)
    {
  
    #generate a new Temp object
    $BIOSArrayTemp = New-Object PSObject
        
    # build a temporary array
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
    # select BIOS settings on Device
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'AttributeName' -Value $Setting.AttributeName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'CurrentValue' -Value $Setting.CurrentValue -Force                    
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DefaultValue' -Value $Setting.DefaultValue -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $Setting.DisplayName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $Setting.InstanceName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Modifiers' -Value $Setting.Modifiers -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'PossibleValue' -Value $Setting.PossibleValue -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'PossibleValueCount' -Value $Setting.PossibleValueCount -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ReadOnly' -Value $Setting.ReadOnly -Force                    
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ValueModifierCount' -Value $Setting.ValueModifierCount -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ValueModifiers' -Value $Setting.ValueModifiers -Force

    $BIOSArray = $BIOSArray + $BIOSArrayTemp


    }


# select $BIOSInteger values
foreach ($Setting in $BIOSInteger)
    {
  
    #generate a new Temp object
    $BIOSArrayTemp = New-Object PSObject
        
    # build a temporary array
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
    # select BIOS settings on Device
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'AttributeName' -Value $Setting.AttributeName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'CurrentValue' -Value $Setting.CurrentValue -Force                    
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DefaultValue' -Value $Setting.DefaultValue -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $Setting.DisplayName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $Setting.InstanceName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'LowerBound' -Value $Setting.LowerBound -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Modifiers' -Value $Setting.Modifiers -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ReadOnly' -Value $Setting.ReadOnly -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ScalarIncrement' -Value $Setting.ScalarIncrement -Force                    
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'UpperBound' -Value $Setting.UpperBound -Force
                  

    # Transfer temp date to array
    $BIOSArray = $BIOSArray + $BIOSArrayTemp


    }


# select $BIOSCollection values
foreach ($Setting in $BIOSString)
    {
  
    #generate a new Temp object
    $BIOSArrayTemp = New-Object PSObject
        
    # build a temporary array
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
    # select BIOS settings on Device
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'AttributeName' -Value $Setting.AttributeName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'CurrentValue' -Value $Setting.CurrentValue -Force                    
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DefaultValue' -Value $Setting.DefaultValue -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $Setting.DisplayName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $Setting.InstanceName -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'MaxLength' -Value $Setting.MaxLength -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'MinLength' -Value $Setting.MinLength -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Modifiers' -Value $Setting.Modifiers -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ReadOnly' -Value $Setting.ReadOnly -Force
             

    # Transfer temp date to array
    $BIOSArray = $BIOSArray + $BIOSArrayTemp


    }


# Convert Array to JSON format
$BIOSInfoJson = $BIOSArray | ConvertTo-Json

<#
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($BIOSInfoJson))
    LogType    = $LogType 
}

$LogResponse = Post-LogAnalyticsData @params
#>