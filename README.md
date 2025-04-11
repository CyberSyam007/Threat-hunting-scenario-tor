# Threat-hunting-scenario-tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/CyberSyam007/Threat-hunting-scenario-tor/blob/main/event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `8:30 AM, April 10th,2025`. These events began at `8:15 AM, April 10th,2025`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "first-test"
| where FileName startswith "tor"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,Account=InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/CyberSyam007/Threat-hunting-scenario-tor/blob/main/Media/1.png">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "first-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/CyberSyam007/Threat-hunting-scenario-tor/blob/main/Media/2.png">


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "first-test"
| where FileName has_any('tor.exe', 'tor-browser.exe')
```
<img width="1212" alt="image" src="https://github.com/CyberSyam007/Threat-hunting-scenario-tor/blob/main/Media/3.png">


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
let codes = dynamic([9001, 9030, 9040, 9050, 9051, 9150]);
DeviceNetworkEvents
| where DeviceName == "first-test"
| where RemotePort in (codes)
| project Timestamp, DeviceName,ActionType, InitiatingProcessFileName, RemoteIP,RemotePort
```
<img width="1212" alt="image" src="https://github.com/CyberSyam007/Threat-hunting-scenario-tor/blob/main/Media/4.png">

---

## Chronological Event Timeline 

### 08:15:06 AM – Tor Installer Execution Confirmed
  #### Query against DeviceProcessEvents revealed:


    Execution of the file : tor-browser-windows-x86_64-portable-14.0.9.exe


#### Indicates user actively ran the installer
**File path**: 'C:\Users\shyam\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe'



### Shortly After 08:17 AM – Tor Browser Opened

 #### Processes tor.exe and several instances of firefox.exe spawned.


 **Confirms that the Tor browser was launched successfully.**
**File path**:  'C:\Users\shyam\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe'


 
### 08:29:37 AM – Network Connection to Known Tor Node

 **A successful outbound connection from tor.exe**


**Remote** IP: '185.82.217.49'


**Port**: '9001' (known Tor network port)


**Confirms actual communication over the Tor network.**

### 08:30:06 AM – Suspicious File Activity Detected
**Query against DeviceFileEvents revealed multiple files with names containing "tor".**


- **Key file identified**:


      'tor-browser-windows-x86_64-portable-14.0.9.exe'


        'tor-shopping-list'


The employee created a file named “tor-shopping-list” on the desktop, potentially indicating a list or notes related to their Tor browser activities.

**Filepath**: 'C:\Users\shyam\Documents\tor-shopping-list.txt`

---

## Summary

The user on the "first-test" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `first-test` by the user. The device was isolated, and the user's direct manager was notified.

---
