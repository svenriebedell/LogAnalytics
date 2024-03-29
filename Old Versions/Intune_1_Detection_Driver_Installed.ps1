<#
_author_ = Sven Riebe <sven_riebe@Dell.com>
_twitter_ = @SvenRiebe
_version_ = 1.0.1
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
#>

<#Version Changes

1.0.0   inital version
1.0.1   correction if folder c:\temp is missing on device

Knowing Issues
-   tbd
#>


<#
.Synopsis
   This PowerShell collecting all installed drivers and upload these informations to LogAnalytics (portal.azure.com)
   IMPORTANT: This script need to install Dell Command Update or Dell Support Assist for Business first otherwise you will get no details about installed drivers
   IMPORTANT: LogAnalytics is a service from Microsoft and is NOT free of charge please checking your MS contracts if you have this service availible otherwise you need to order this service.
   IMPORTANT: This script does not reboot the system to apply or query system.
   IMPORTANT: This script is supporting Dell Business Devices only (Optiplex, Precision, Latitude and Mobile XPS)

.DESCRIPTION
   This PowerShell is starting the Dell Inventory Agent and collect all installed Driver Informations Driver-Name, Driver-Version and Driver-Category and using the LogAnalytics API to upload all informations directly to portal.azure.com / LogAnalytics Service.
   
#>

<#The functions Function Build-Signature and Function Post-LogAnalyticsData was developed by https://www.systanddeploy.com/2022/05/intune-reporting-with-log-analytics.html and used by me without any change #>

#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = "Your LogAnalytics ID"
$SharedKey = "your LogAnalytics Key"
$LogType = "DellDriverInstalled"
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

function get-folderstatus 
    {
        param 
            (
                [string]$FolderPath
            )
        
        Test-Path -Path $FolderPath
    }

# Prepare Device basic datas
$deviceData = Get-ComputerInfo

# select datas
$Username = ($deviceData.CsUserName).Split("\")[-1]
$Vendor = ($deviceData.CsManufacturer).Split(" ")[0]
$Model = ($deviceData.CsModel)
$DeviceSerie = ($deviceData.CsModel).Split(" ")[0]
$ServiceTag = $deviceData.BiosSeralNumber
$DeviceSKU = $deviceData.CsSystemSKUNumber
$OSVersion = $deviceData.OsVersion
$WinEdition = $deviceData.OsName

# Checking if C:\Temp is available and if not generate the folder.
$CheckTempFolder = get-folderstatus -FolderPath C:\Temp

If ($CheckTempFolder -eq $true)
    {

        Write-Host "Folder c:\temp exist" -BackgroundColor Green
        
    }
else 
    {
        
        Write-Host "Folder c:\temp does not exist" -BackgroundColor red
        New-Item -Path 'C:\Temp' -ItemType Directory

    }

# Checking if program InvColPC.exe is available
$CheckInvColPC = get-folderstatus -FolderPath 'C:\Program Files (x86)\Dell\UpdateService\Service\InvColPC.exe'

If ($CheckInvColPC -eq $true)
    {

        Write-Host "Program InvColPC.exe is ready to use" -BackgroundColor Green
        
    }
else 
    {
        
        Write-Host "Program InvColPC.exe is missing. Starting Dell Command | Update to download program in background" -BackgroundColor red
        
        # Checking installation of UWP or classic of Dell Command | Update and start a standard scan if application is available.
        $DCUPathCheck = get-folderstatus -FolderPath 'C:\Program Files (x86)\Dell\CommandUpdate\'

        If ($DCUPathCheck -eq 'True')
            {
            # run a driver scan with Dell Command Update (based on version 32/64)
            Write-Host "Start Dell Command | Update Classic scan"
            $DCUScan = & 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe' /scan
            }
        Else
            {

            $DCUPathCheck = get-folderstatus -FolderPath 'C:\Program Files\Dell\CommandUpdate\'
            
            If ($DCUPathCheck -eq 'True')
                {
                # run a driver scan with Dell Command Update (based on version 32/64)
                Write-Host "Start Dell Command | Update UWP scan"
                $DCUScan = & 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe' /scan
                }

            Else
                {

                Write-Host "No DCU installed. You need to install first" -BackgroundColor red

                Exit = 1

                }

    }

    }

# Collecting driver datas for uplaod to MS Log Analytics
Start-Process 'C:\Program Files (x86)\Dell\UpdateService\Service\InvColPC.exe' -ArgumentList '-outc=c:\Temp\inventory' -Wait -NoNewWindow
[xml]$DriverInventory = Get-Content C:\Temp\inventory
[Array]$DriverIST = $DriverInventory.SVMInventory.Device.application |Select-Object Display, Version, componentType | Sort-Object Display
Start-Sleep -Seconds 5
Remove-Item C:\Temp\inventory


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
$DeviceInfoJson = $DriverArray | ConvertTo-Json

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($DeviceInfoJson))
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params