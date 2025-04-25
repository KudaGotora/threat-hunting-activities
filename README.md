# threat-hunting-activities

# Threat Hunt Report: Sudden Network Slowdowns
- [Scenario Creation](https://github.com/KudaGotora/threat-hunting-activities/blob/main/Network%20Slowdown%20Event%20creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


##  Scenario

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

### Sudden Network Slowdowns IoC Discovery Plan

- **Check `DeviceNetworkEvents`** for any signs of connection failures.
- **Check `DeviceProcessEvents`** to see if we could see anything that was suspicious around the time the portscan started.

---

## Steps Taken

### 1. Searched the `DeviceNetworkEvents` Table

Searched to see if 'kd-threat-hunt'  was found failing several connection requests against itself

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName startswith "kd-threat-hunt"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount

```
![Screenshot (14)](https://github.com/user-attachments/assets/7436c4bc-90f5-44bd-b942-e95638ced515)


---

### 2. Searched the `DeviceNetworkEvents` Table

After observing failed connection requests from suspected host in sequential order, i noticed a port scan take place due to the sequential order of the ports. There were several port scans being conducted

**Query used to locate event:**

```kql

// Observe all failed connections for the IP in question. Notice anything?
let IPInQuestion = "10.0.0.149";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc

```
![Screenshot (15)](https://github.com/user-attachments/assets/5c3772e3-ccd9-46be-a53d-63cda33c0e91)


---

### 3. Searched the `DeviceProcessEvents` Table 

I pivoted to the DeviceProcessEvents table to see if we could see anything that was suspicious around the time the portscan started

**Query used to locate events:**

```kql
Time = datetime(2025-04-24T14:58:47.3810703Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desclet VMName = "kd-threat-hunt";
let specific
| project Timestamp, FileName, InitiatingProcessCommandLi

```

![Screenshot (16)](https://github.com/user-attachments/assets/2888ba76-b81b-4612-98e1-53e1b82becb5)


---



## Summary

An internal port scan was likely executed from kd-threat-hunt using a PowerShell script, possibly to enumerate open services or conduct reconnaissance. This behavior is often linked to lateral movement attempts or vulnerability discovery within the local system.


---

## Response Taken

An internal port scan was likely executed from kd-threat-hunt using a PowerShell script. The device was isolated, and the user's direct manager was notified.

---
