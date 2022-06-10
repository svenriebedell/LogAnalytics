#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = "cb9801e8-b5b0-4dfe-ab1e-ff8a17642010"
$SharedKey = 'y15hSyg+5xekllOCyIxIW8LbuipepJCiR6ToGCfu5Umi5lqhaSCr19toWrGGtJQ5REcV1TeQCZaPvxfhwfgepw=='
$LogType = "DellDriverStatus"
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
$deviceData = Get-ComputerInfo

# select datas
$Username = ($deviceData.CsUserName).Split("\")[-1]
$Vendor = ($deviceData.CsManufacturer).Split(" ")[0]
$Model = ($deviceData.CsModel)
$DeviceSerie = ($deviceData.CsModel).Split(" ")[0]
$ServiceTag = $deviceData.BiosSeralNumber
$DeviceSKU = $deviceData.CsSystemSKUNumber
$OSVersion = $deviceData.OSDisplayVersion
$WinEdition = $deviceData.WindowsProductName

Start-Process 'C:\Program Files (x86)\Dell\UpdateService\Service\InvColPC.exe' -ArgumentList '-outc=c:\Temp\inventory' -Wait
[xml]$DriverInventory = Get-Content C:\Temp\inventory
[Array]$DriverIST = $DriverInventory.SVMInventory.Device.application |Select-Object Display, Version, componentType | sort Display
Start-Sleep -Seconds 5
Remove-Item C:\Temp\inventory



$missingDriver = & 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe' /scan

#checking if drivers are availible or not
$checkMissingDriver = ($missingDriver | Select-String "Number of applicable updates for the current system configuration: ").Line.TrimStart('Number of applicable updates for the current system configuration: ')

If ($checkMissingDriver -ne 0)
    {
    
    $missingDriverSelect = $missingDriver | Select-String "--"

    }

Else
    {

    $missingDriverSelect = "No updates availible"

    }
	
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
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'OSEditon' -Value $WinEdition -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'OSVersion' -Value $OSVersion -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverName' -Value $Driver.display -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverVersion' -Value $Driver.version -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'DriverCategory' -Value $Driver.componentType -Force
        $DriverArrayTemp | Add-Member -MemberType NoteProperty -Name 'MissingUpdates' $missingDriver

        $DriverArrayTemp

        [Array]$DriverArray += $DriverArrayTemp
                        
        }



# Create the object
$Properties = [Ordered] @{
    
        "Computer"    = $DriverArray.Computername
        "UserName"    = $DriverArray.UserName
        "Vendor"      = $DriverArray.Manufacturer
        "DeviceModel" = $DriverArray.DeviceModel
        "ProductLine" = $DriverArray.ProductLine
        "SerialNumber"= $DriverArray.SerialNo
        "SystemSKU"   = $DriverArray.SystemSKU
        "OSEdition"   = $DriverArray.OSEditon
        "OSVersion"   = $DriverArray.OSVersion
        "DriverTodayName" = $DriverArray.DriverName
        "DriverTodayVersion" = $DriverArray.DriverVersion
        "DriverTodayType" = $DriverArray.DriverCategory
        "MissingDriverUpdates" = $DriverArray.MissingUpdates
         				
}
$DeviceInfo = New-Object -TypeName "PSObject" -Property $Properties

$DeviceInfoJson = $DeviceInfo | ConvertTo-Json

$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($DeviceInfoJson))
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params