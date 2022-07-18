# LogAnalytics
This site showing examples how you can monitor Dell Client Hardware with Microsoft Log Analytics.

We cover the following applications and Dell Client functions

- Dell Command Update
    + Status of missing Drivers (Firmware, BIOS, Dell Applications, etc.)
    + Assessment of installed Drivers on devices
- Dell Optimizer
    + Monitoring Learned and Optimized Applications
    + Assessment of Dell Optimizer settings on devices
    + Compliance check of settings and applications learning/optimized
- BIOS
    + Dell Safe BIOS Security monitoring
    + BIOS PW check
    + BIOS settings on device
    + Compliance check of settings on devices

### Requirments
- Microsoft Log Analytics license
- Storing of log will be payed by use (please check with your Microsoft license team)

### Preparations
- Run the powershell scripts on a regular base. (I am using the Remediation option form Microsoft Endpoint manager, but Taskplaner or other solutions are also working)
- Copy and Paste text of JSON file in to a new create Workbook

## Dell Command Update Dashboard

The PowerShell Script are using Dell Command Update (Scan and InvPC) to collect all update and installed datas.

Download Dell Command Update:
https://www.dell.com/support/kbdoc/en-us/000177325/dell-command-update


Video:


## Dell Optimizer Dashboard

The PowerShell Script are using Dell Optimizer to collect all application optimized running processes and Dell Optimizer settings.

Download Dell Optimizer:
https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=x7c54&oscode=wt64a&productcode=latitude-14-9430-laptop


Video:


## Dell BIOS Dashboard

The PowerShell Script are using Dell WMI queries and Dell Trusted Device Agenten to collect all BIOS Settings and check status of BIOS security features.

Download Trusted Device:
https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=nmtdh&oscode=wt64a&productcode=trusted-device


Video:
