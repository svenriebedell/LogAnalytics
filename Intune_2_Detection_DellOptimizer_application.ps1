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
$LogType = "DellOptimizerApp"
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
$DOScanXML = $DOPath + "\Temp.xml.exe"
$DOPathCheck = Test-Path -Path $DOPath

If ($DOPathCheck -eq 'True')
    {
    # run a query to collect the Dell Optimizer Application Performance settings
    $learningArray = & $DOFile /appperformance -listlearningapps
    $ProfileArray = & $DOFile /appperformance -listprofiles
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

# Prepare scan data for using
$learningArrayTemp = $learningArray.split(":").trim(" ")
$ProfileArrayTemp = $ProfileArray.split(":").trim(" ")

# reducing counter for i loops to ignore the last lines of scan arrays
$learningArrayTempCounter = $learningArrayTemp.count - 3 #-3 kills empty lines at the end of this array
$ProfileArrayTempCounter = $ProfileArrayTemp.count - 4 #-4 kills empty lines at the end of this array

#generate temp XML to merge Profile and Learning Arrays of Dell Optimizer

#Prepare XML file for loging
$xmlMergeArray = New-Object System.Xml.XmlTextWriter($DOScanXML,$null) 

#Formating XML File
$xmlMergeArray.Formatting = "Indented"
$xmlMergeArray.Indentation = "1"
$xmlMergeArray.IndentChar = "`t"

#writing datas header
$xmlMergeArray.WriteStartDocument()
$xmlMergeArray.WriteStartElement("OptimizerAppInformations")
$xmlMergeArray.WriteStartElement("ScriptRuntime")
$xmlMergeArray.WriteAttributeString("StartTime",(Get-Date).ToString())
$xmlMergeArray.WriteEndElement()
$xmlMergeArray.WriteStartElement("Lerning")

## Transfer learning apps details to temp.xml

# Index counter to get the array values and move these to differten Collums
$Index = 0

#Prepare the Table Array for log analytics

for ($i = 1; $i -le $learningArrayTempCounter)
    {
    
    $xmlMergeArray.WriteStartElement("App")
    $xmlMergeArray.WriteAttributeString("Name",$learningArraytemp[$Index + 4])
    $xmlMergeArray.WriteAttributeString("ProfileGuid",$learningArraytemp[$Index + 6])
    $xmlMergeArray.WriteAttributeString("ProcessName",$learningArraytemp[$Index + 8])
    $TempProcessPath = $learningArraytemp[$Index + 10] + ":" + $learningArraytemp[$Index + 11]
    $xmlMergeArray.WriteAttributeString("ProcessPath",$TempProcessPath)
    $xmlMergeArray.WriteAttributeString("Priority",$learningArraytemp[$Index + 13])
    $xmlMergeArray.WriteAttributeString("Status",$learningArraytemp[$Index + 15])
    $xmlMergeArray.WriteAttributeString("PercentLearned",$learningArraytemp[$Index + 17])
    $xmlMergeArray.WriteAttributeString("IsBenchmarkFinished",$learningArraytemp[$Index + 19])
    $xmlMergeArray.WriteAttributeString("CpuPercentScore",$learningArraytemp[$Index + 21])
    $xmlMergeArray.WriteAttributeString("StoragePercentScore",$learningArraytemp[$Index + 23])
    $xmlMergeArray.WriteAttributeString("OverallPercentScore",$learningArraytemp[$Index + 25])
    $xmlMergeArray.WriteEndElement()
         
    #step up counter and index
    $i = $i+27
    $index = $Index +27
                        
    }

$xmlMergeArray.WriteEndElement()
$xmlMergeArray.WriteStartElement("Profile")

## Transfer learning apps details to temp.xml

# Index counter to get the array values and move these to differten Collums
$Index = 0

#Prepare the Table Array for log analytics

for ($i = 1; $i -le $ProfileArrayTempCounter)
    {
    
    $xmlMergeArray.WriteStartElement("App")
    $xmlMergeArray.WriteAttributeString("Name",$ProfileArrayTemp[$Index + 8])
    $xmlMergeArray.WriteAttributeString("Type",$ProfileArrayTemp[$Index + 4])
    $xmlMergeArray.WriteAttributeString("ProfileGuid",$ProfileArrayTemp[$Index + 6])
    $xmlMergeArray.WriteAttributeString("Enabled",$ProfileArrayTemp[$Index + 10])
    $xmlMergeArray.WriteAttributeString("Imported",$ProfileArrayTemp[$Index + 12])
    $xmlMergeArray.WriteAttributeString("ExecutionState",$ProfileArrayTemp[$Index + 14])
    $xmlMergeArray.WriteAttributeString("NeedsReboot",$ProfileArrayTemp[$Index + 16])
    $xmlMergeArray.WriteAttributeString("Priority",$ProfileArrayTemp[$Index + 18])
    $xmlMergeArray.WriteAttributeString("Description",$ProfileArrayTemp[$Index + 20])
    $xmlMergeArray.WriteAttributeString("Generic",$ProfileArrayTemp[$Index + 22])
    $xmlMergeArray.WriteAttributeString("ProcessName",$ProfileArrayTemp[$Index + 24])
    $TempProcessPath = $ProfileArrayTemp[$Index + 26] + ":" + $ProfileArrayTemp[$Index + 27]
    $xmlMergeArray.WriteAttributeString("ProcessPath",$TempProcessPath)
    $xmlMergeArray.WriteEndElement()

    #step up counter and index
    $i = $i+29
    $index = $Index +29
                        
    }

$xmlMergeArray.WriteEndElement()
$xmlMergeArray.Close()

[XML]$TempXMLData = Get-Content $DOScanXML



#Prepare the Table Array for log analytics
$DOArray = @()

foreach ($App in $TempXMLData.OptimizerAppInformations.Lerning.App)
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
    # select DO Version on Device
    $DOVersion= (Get-ChildItem -Path $DOPath .\do-cli.exe).VersionInfo | select -ExpandProperty ProductVersion
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Version' -Value $DOVersion -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Name' -Value $App.Name -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProfileGuid' -Value $App.ProfileGuid -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProcessName' -Value $App.ProcessName -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'ProcessPath' -Value $App.ProcessPath -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Priority' -Value $App.Priority -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Status' -Value $App.Status -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'PercentLearned' -Value $App.PercentLearned -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'IsBenchmarkFinished' -Value $App.IsBenchmarkFinished -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'CpuPercentScore' -Value $App.CpuPercentScore -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'StoragePercentScore' -Value $App.StoragePercentScore -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'OverallPercentScore' -Value $App.OverallPercentScore -Force

          
    #add App Profile datas to table

    # request missing information from XML
    $TempType = $TempXMLData.OptimizerAppInformations.Profile.App | Where-Object{$_.ProfileGuid -eq $App.ProfileGuid} | Select-Object -ExpandProperty Type
    $TempEnabled = $TempXMLData.OptimizerAppInformations.Profile.App | Where-Object{$_.ProfileGuid -eq $App.ProfileGuid} | Select-Object -ExpandProperty Enabled
    $TempImported = $TempXMLData.OptimizerAppInformations.Profile.App | Where-Object{$_.ProfileGuid -eq $App.ProfileGuid} | Select-Object -ExpandProperty Imported
    $TempExecutionState = $TempXMLData.OptimizerAppInformations.Profile.App | Where-Object{$_.ProfileGuid -eq $App.ProfileGuid} | Select-Object -ExpandProperty ExecutionState
    $TempNeedsReboot = $TempXMLData.OptimizerAppInformations.Profile.App | Where-Object{$_.ProfileGuid -eq $App.ProfileGuid} | Select-Object -ExpandProperty NeedsReboot
    $TempDescription = $TempXMLData.OptimizerAppInformations.Profile.App | Where-Object{$_.ProfileGuid -eq $App.ProfileGuid} | Select-Object -ExpandProperty Description
    $TempGeneric = $TempXMLData.OptimizerAppInformations.Profile.App | Where-Object{$_.ProfileGuid -eq $App.ProfileGuid} | Select-Object -ExpandProperty Generic

    #add Profile datas of ProfileGUID to array       
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Type' -Value $TempType -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Enabled' -Value $TempEnabled -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Imported' -Value $TempImported -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'ExecutionState' -Value $TempExecutionState -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'NeedsReboot' -Value $TempNeedsReboot -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Description' -Value $TempDescription -Force
    $DOArrayTemp | Add-Member -MemberType NoteProperty -Name 'Generic' -Value $TempGeneric -Force
        
    
    #Create the object
    [Array]$DOArray += $DOArrayTemp
    
                        
    }

# Delete temp.xml
Remove-Item $DOScanXML

# Convert Array to JSON format
$DOInfoJson = $DOArray | ConvertTo-Json

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($DOInfoJson))
    LogType    = $LogType 
}

$LogResponse = Post-LogAnalyticsData @params