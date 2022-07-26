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
-  tbd
#>

#>

<#
.Synopsis
   This PowerShell collecting BIOS settings by WMI request and upload these informations to LogAnalytics (portal.azure.com)
   IMPORTANT: This script need Dell Business Device from 2018 or younger otherwise WMI is not supported
   IMPORTANT: LogAnalytics is a service from Microsoft and is NOT free of charge please checking your MS contracts if you have this service availible otherwise you need to order this service.
   IMPORTANT: This script does not reboot the system to apply or query system.
   IMPORTANT: This script is supporting Dell Business Devices only (Optiplex, Precision, Latitude and Mobile XPS) which are support Dell Optimizer application

.DESCRIPTION
   This PowerShell make WMI request to get all BIOS Settings of this Device and using the LogAnalytics API to upload all informations directly to portal.azure.com / LogAnalytics Service.
   
#>

<#The functions Function Build-Signature and Function Post-LogAnalyticsData was developed by https://www.systanddeploy.com/2022/05/intune-reporting-with-log-analytics.html and used by me without any change #>

#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = "cb9801e8-b5b0-4dfe-ab1e-ff8a17642010"
$SharedKey = 'y15hSyg+5xekllOCyIxIW8LbuipepJCiR6ToGCfu5Umi5lqhaSCr19toWrGGtJQ5REcV1TeQCZaPvxfhwfgepw=='
$LogType1 = "DellBIOSSetting"   # Table for WMI BIOS Settings
$LogType2 = "DellBIOSPassword"  # Table for WMI BIOS Password Security
$LogType3 = "DellSafeBIOS"      # Table for MS Event for Dell SafeBIOS
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

####### Section Log Analytics DellBIOSSetting custom Table ##########
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

####### End of collect Data for DellBIOSSetting Table ##########
################################################################

####### Section Log Analytics DellBIOSSetting custom Table ##########
# select BIOS Password Settings

$BIOSPassword = Get-CimInstance -Namespace root/DCIM/SYSMAN/wmisecurity -ClassName PasswordObject


#Prepare the Table Array for log analytics
$BIOSArray = @()


# select $BIOSData values
foreach ($Setting in $BIOSPassword)
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
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Active' -Value $Setting.Active -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $Setting.InstanceName -Force
    # Change 0 and 1 to disabled / enabled for better view later
    $IsPasswordSet = Switch ($Setting.IsPasswordSet)
        {
        0 {"Disabled"}
        1 {"Enabled"}
        }
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'IsPasswordSet' -Value $IsPasswordSet -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'MaximumPasswordLength' -Value $Setting.MaximumPasswordLength -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'MinimumPasswordLength' -Value $Setting.MinimumPasswordLength -Force
    $BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'NameId' -Value $Setting.NameId -Force

    $BIOSArray = $BIOSArray + $BIOSArrayTemp


    }

    
# Convert Array to JSON format
$BIOSPasswordJson = $BIOSArray | ConvertTo-Json

####### End of collect Data for DellBIOSPassword Table ##########
################################################################

####### Section Log Analytics DellSafeBIOS custom Table ##########
# select SafeBIOS Risk Assessment from last check

# Function for snipping SafeBIOS values from the MS Event
function Get-SafeBIOSValue{
    
    # Parameter
    param(
        [string]$Value
        
         )

    # Collect last MS Event for Trusted Device | Security Assessment
    $SelectLastLog = Get-EventLog -LogName Dell -Source "Trusted Device | Security Assessment" -Newest 1 | select -ExpandProperty message
    
    # Prepare value for single line and value
     
    $ScoreValue = ($SelectLastLog.Split([Environment]::newline) | Select-String $Value)
    $ScoreLine = ($ScoreValue.Line).Split(':')
    $ScoreLine = ($ScoreLine.Split(':'))[-1].Trim()

    $ScoreValue = $ScoreLine

    Return $ScoreValue
     
}

#Prepare variables
$OutputStatement = "Device Details: "
$Safe_Score = "Security Score: "
$Safe_Antivirus = "Antivirus: "
$Safe_AdminPW = "BIOS PW: "
$Safe_BIOSVerify = "BIOS Verification: "
$Safe_MEVerify = "ME Verification: "
$Safe_DiskEncrypt = "Disk Encryption: "
$Safe_Firewall = "Firewall: "
$Safe_IoA = "Indicators of Attack: "
$Safe_TPM = "TPM: "
$Safe_Assessment = "Assessment Result: "

#Select score values
$Safe_Score_Value = Get-SafeBIOSValue -Value 'Score'
$Safe_Antivirus_Value = Get-SafeBIOSValue -Value 'Antivirus'
$Safe_AdminPW_Value = Get-SafeBIOSValue -Value 'BIOS Admin'
$Safe_BIOSVerify_Value = Get-SafeBIOSValue -Value 'BIOS Verification'
$Safe_MEVerify_Value = Get-SafeBIOSValue -Value 'ME Verification'
$Safe_DiskEncrypt_Value = Get-SafeBIOSValue -Value 'Disk Encryption'
$Safe_Firewall_Value = Get-SafeBIOSValue -Value 'Firewall solution'
$Safe_IOA_Value = Get-SafeBIOSValue -Value 'Indicators of Attack'
$Safe_TPM_Value = Get-SafeBIOSValue -Value 'TPM enabled'
$Safe_Assessment_Value = Get-SafeBIOSValue -Value 'Result:' 

#Prepare the Table Array for log analytics
$BIOSArray = @()

#generate a new Temp object
$BIOSArrayTemp = New-Object PSObject

# Prepare output string
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $env:computername -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'UserName' -Value $Username -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Manufacturer' -Value $Vendor -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DeviceModel' -Value $Model -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProductLine' -Value $DeviceSerie -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SerialNo' -Value $ServiceTag -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'SystemID' -Value $DeviceSKU -Force
# select BIOS settings on Device
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Score' -Value $Safe_Score_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Antivirus' -Value $Safe_Antivirus_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'AdminPWD' -Value $Safe_AdminPW_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'BIOSVerification' -Value $Safe_BIOSVerify_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'MEVerification' -Value $Safe_MEVerify_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'DiskEncryption' -Value $Safe_DiskEncrypt_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Firewall' -Value $Safe_Firewall_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'IOA' -Value $Safe_IOA_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'TPM' -Value $Safe_TPM_Value -Force
$BIOSArrayTemp | Add-Member -MemberType NoteProperty -Name 'Result' -Value $Safe_Assessment_Value -Force

$BIOSArray = $BIOSArray + $BIOSArrayTemp

# Convert Array to JSON format
$SafeBIOSJson = $BIOSArray | ConvertTo-Json

####### End of collect Data for DellSafeBIOS Table    ##########
################################################################



################################################################
#######        Transfer Data to log Analytics         ##########

##### Table DellBIOSSettings
$LogType = $LogType1

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($BIOSInfoJson))
    LogType    = $LogType 
}

$LogResponse = Post-LogAnalyticsData @params

##### End Table DellBIOSSettings

##### Table DellBIOSPassword
$LogType = $LogType2

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($BIOSPasswordJson))
    LogType    = $LogType 
}

$LogResponse = Post-LogAnalyticsData @params

##### End Table DellBIOSPassword

##### Table DellSafeBIOS
$LogType = $LogType3

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($SafeBIOSJson))
    LogType    = $LogType 
}

$LogResponse = Post-LogAnalyticsData @params

##### End Table DellSafeBIOS
