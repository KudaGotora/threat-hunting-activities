# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the PowerShell Script:

Invoke-WebRequest downloads portscan.ps1 from a GitHub URL.

The file is saved locally to C:\programdata\portscan.ps1.


2. Execute the PowerShell Script:

cmd /c launches a new command prompt instance.

It runs PowerShell with:

-ExecutionPolicy Bypass to ignore script execution restrictions.

-File C:\programdata\portscan.ps1 to execute the downloaded script.



---

## Tables Used to Detect IoCs:


| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
DeviceNetworkEvents
| where DeviceName == "kd-threat-hunt"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount

// Observe all failed connections for the IP in question. Notice anything?
let IPInQuestion = "10.0.0.149";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc

// Observe DeviceProcessEvents for the past 10 minutes of the unusual activity found
let VMName = "kd-threat-hunt";
let specificTime = datetime(2025-04-24T14:58:47.3810703Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine

```

---

## Created By:
- **Author Name**: Kudakwashe Gotora

- **Date**: April 24, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 24, 2025`  | `Kudakashe Gotora`   
