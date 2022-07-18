# LogAnalytics
This page shows some examples of how to use Dell tools in conjunction with Microsoft Log Analytics. The examples cover BIOS settings, device updates and AI applications like Dell Optimizer. The PowerShell scripts collect the data from the devices, there is a JSON file which configures the dashboard view. This must be copied into Log Analytics.

### Legal disclaimer: 
**THE INFORMATION IN THIS PUBLICATION IS PROVIDED 'AS-IS.' DELL MAKES NO REPRESENTATIONS OR WARRANTIES OF ANY KIND WITH RESPECT TO THE INFORMATION IN THIS PUBLICATION, AND SPECIFICALLY DISCLAIMS IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.** In no event shall Dell Technologies, its affiliates or suppliers, be liable for any damages whatsoever arising from or related to the information contained herein or actions that you decide to take based thereon, including any direct, indirect, incidental, consequential, loss of business profits or special damages, even if Dell Technologies, its affiliates or suppliers have been advised of the possibility of such damages.

This script will be used for testing modifications that could have impact of running without issues

We cover the following applications and Dell Client functions 


- **Dell Command Update** 
    + Status of missing Drivers (Firmware, BIOS, Dell Applications, etc.) 
    + Assessment of installed Drivers on devices 

- **Dell Optimizer** 
    + Monitoring Learned and Optimized Applications 
    + Assessment of Dell Optimizer settings on devices 
    + Compliance check of settings and applications learning/optimized 

- **Dell BIOS** 
    + Dell Safe BIOS Security monitoring 
    + BIOS PW check 
    + BIOS settings on device 
    + Compliance check of settings on devices 

### Requirements 
- Microsoft Log Analytics license 
- Storing of log will be paid by use (please check with your Microsoft license team) 

### Preparations 
- Run the PowerShell scripts on a regular basis. (I am using the Remediation option form Microsoft Endpoint manager, but Task Planer or other solutions are also working) 
- Copy and Paste text of JSON (Java Script Object Notation) file into a new created Workbook 

## Dell Command Update Dashboard 

The PowerShell Script uses Dell Command Update (Scan and InvPC) to collect all updates and installed data. 

Download Dell Command Update: 
https://www.dell.com/support/kbdoc/en-us/000177325/dell-command-update


Video:

![A73895E2-11E0-4B39-BC61-F3ACE63A6C1B](https://user-images.githubusercontent.com/99394991/179505164-7876e9c8-8520-4396-b98a-774c5d863ec5.GIF)


## Dell Optimizer Dashboard 
 
The PowerShell Script uses Dell Optimizer to collect all application optimized running processes and Dell Optimizer settings. 

Download Dell Optimizer: 
https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=x7c54&oscode=wt64a&productcode=latitude-14-9430-laptop

Video:
![4B2FF917-2ECC-4B62-A6CE-CEC15CEF47ED](https://user-images.githubusercontent.com/99394991/179505666-a428cf75-8561-4bf8-8e6d-c330801b61b3.GIF)


## Dell BIOS Dashboard (is following)

The PowerShell Script uses Dell WMI (Windows Management Instrumentation) queries and Dell Trusted Device Agent to collect all BIOS Settings and check status of BIOS security features. 

Download Trusted Device: 
https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid=nmtdh&oscode=wt64a&productcode=trusted-device

Video:
