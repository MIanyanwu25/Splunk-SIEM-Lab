# Splunk-SIEM-Lab# Lab 3 — Splunk SIEM & Log Analysis
### Splunk Free · Azure VM · SOC Skills · Security Monitoring

![Splunk](https://img.shields.io/badge/Splunk-Free_Licence-000000?style=flat&logo=splunk&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-Compatible-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Cost](https://img.shields.io/badge/Cost-%240-brightgreen?style=flat)
![Duration](https://img.shields.io/badge/Time-4--6_hours-yellow?style=flat)

---

## Overview

| Field | Value |
|---|---|
| **Certification Alignment** | CompTIA Security+ · CySA+ · Splunk Core Certified User |
| **Tools Used** | Splunk Enterprise (free) · Azure Ubuntu VM · Windows Server VM (Lab 1) |
| **Time to Complete** | 4–6 hours across multiple sessions |
| **Estimated Cost** | $0 — Splunk Free licence covers everything in this lab |
| **Career Relevance** | SOC Analyst (Tier 1–3) · Security Engineer · Incident Responder · Cloud Security Engineer |

A medium-sized organisation generates millions of log events every day. Without a SIEM, those logs sit in separate systems and nobody can search across them, correlate events, or identify patterns that indicate an attack. This lab deploys a fully functional Splunk SIEM, ingests real Windows security logs from the Active Directory environment built in Lab 1, and teaches you to write SPL queries, build dashboards, and automate detection alerts — the exact workflow used by SOC analysts in enterprise environments.

---

## Architecture

```
┌─────────────────────────────────────┐      Port 9997       ┌──────────────────────────────────┐
│   Windows Server VM (Lab 1)         │ ──────────────────►  │   Ubuntu VM                      │
│   Active Directory Domain Controller│                       │   Splunk Enterprise              │
│   Splunk Universal Forwarder        │                       │   Indexer + Web UI (port 8000)   │
│                                     │                       │                                  │
│   Forwards:                         │                       │   Indexes:                       │
│   • Security Event Log              │                       │   • windows_logs                 │
│   • System Event Log                │                       │                                  │
│   • Application Event Log           │                       │   Searched via SPL               │
└─────────────────────────────────────┘                       └──────────────────────────────────┘
         Both VMs in the same Azure VNet (recommended)
```

---

## Career Relevance by Role

| Role | How This Lab Applies |
|---|---|
| **SOC Analyst Tier 1** | Monitoring dashboards for alerts, searching logs for suspicious activity, escalating findings |
| **SOC Analyst Tier 2–3** | Building detection rules, correlating events across data sources, threat hunting |
| **Cloud Security Engineer** | Microsoft Sentinel and AWS Security Hub use the same SIEM concepts — this lab teaches the mental model |
| **Incident Responder** | Searching logs during an active incident, building an event timeline, identifying scope of compromise |

---

## Key Concepts

### What is a SIEM?
SIEM stands for Security Information and Event Management. A SIEM collects log data from across your entire environment — servers, workstations, firewalls, cloud services, applications — and makes it all searchable in one place. The two core jobs of a SIEM are **correlation** (connecting events across different systems to identify patterns no single system would reveal alone) and **alerting** (automatically notifying analysts when suspicious conditions are met).

### What is SPL?
SPL (Splunk Processing Language) is the query language used to ask Splunk questions. It works as a pipeline — you start with a search, then pipe the results through commands that filter, transform, and visualise the data. Every SPL search follows the same pattern: **find the events, then shape the results.** Each search in this lab is explained line by line.

### What is a Splunk Index?
An index in Splunk is like a database table — a named storage bucket where events are kept. When logs arrive, they are stored in an index. When you search, you specify which index with `index=name`. In this lab you create one index called `windows_logs`.

### What is the Universal Forwarder?
A lightweight free agent installed on any machine whose logs you want to send to Splunk. It monitors log files and Windows Event Logs, compresses and encrypts the data, and forwards it to your Splunk indexer over port 9997. Designed to run invisibly with minimal CPU and RAM impact.

### Key Windows Event IDs

| Event ID | What It Means | Security Relevance |
|---|---|---|
| **4624** | Successful logon | Baseline authentication activity — after-hours logins, unusual accounts |
| **4625** | Failed logon | Brute force detection — high counts from one account or IP |
| **4648** | Logon with explicit credentials | Lateral movement indicator — `runas`, pass-the-hash |
| **4672** | Special privileges assigned at logon | Admin-level access — unexpected accounts with privileges |
| **4688** | New process created | Execution detection — malware, ransomware, suspicious parent-child process chains |
| **4697** | Service installed | Persistence mechanism — malware frequently installs as a service |
| **4740** | Account locked out | Password spray indicator — multiple lockouts across accounts |

---

## Prerequisites

- An Azure free account — [create one here](https://azure.microsoft.com/free)
- **Lab 1 completed** — the Windows Server / Active Directory VM is the log source for this lab
- A temporary email address for Splunk registration — use [temp-mail.org](https://temp-mail.org/en/) (no personal details required)
- SSH client: Terminal (macOS/Linux built-in) or [PuTTY](https://putty.org) (Windows)

> 💡 **Best practice:** Put all your lab VMs in the same Azure VNet from the start — one shared VNet (e.g. `lab-vnet`, `10.0.0.0/16`) with a subnet per environment (`10.0.1.0/24` for AD, `10.0.2.0/24` for Splunk). VMs in the same VNet communicate freely and you only manage NSG rules at the subnet level — no VNet Peering required.

---

## What You'll Learn

| Skill | Real-World Application |
|---|---|
| Deploy Splunk and configure a data input | Every Splunk deployment starts with getting data in — the Universal Forwarder is how most enterprises feed logs to Splunk |
| Navigate the Splunk interface | Search, dashboards, alerts, reports — table stakes for any SOC role |
| Write SPL searches | SPL separates analysts who find threats from analysts who stare at dashboards |
| Build security dashboards | Visualise login failures over time, top source IPs, failed authentication by user |
| Identify failed login attempts | Distinguish normal user error from brute force — one of the most common security investigations |
| Build an automated alert | Splunk fires when conditions you define are met, rather than waiting for a human to notice |
| Search for account lockout events | A pattern of lockouts can indicate a password spray attack in progress |

---

## Step 1 — Get Splunk and Deploy the Ubuntu VM

### Download Splunk Enterprise (Free)

Splunk Enterprise is free. You get a 60-day full trial, after which it converts to the free licence. The free licence covers 500MB/day of indexing — more than enough for a lab.

1. Get a temporary email at [temp-mail.org](https://temp-mail.org/en/) — copy the address shown on screen
2. Go to [splunk.com/en_us/download/splunk-enterprise.html](https://www.splunk.com/en_us/download/splunk-enterprise.html)
3. Register with the temp-mail address and dummy info (First Name, Last Name, Company — none are verified)
4. Confirm your account via the email that arrives in the temp-mail inbox
5. Download **Splunk Enterprise for Linux** (`.deb` package)

### Deploy the Ubuntu VM in Azure

| VM Setting | Value | Why |
|---|---|---|
| OS | Ubuntu 22.04 LTS | Free tier eligible; Splunk .deb package supports it natively |
| Size | Standard_B2s (2 vCPU, 4GB RAM) | Splunk requires minimum 4GB RAM |
| Disk | 30GB minimum | Index storage for log data |
| Inbound NSG — port 8000 | Your IP only | Splunk web UI — restrict to your IP, not the internet |
| Inbound NSG — port 9997 | VNet range only (e.g. `10.0.0.0/16`) | Forwarder input — only your other Azure VMs should reach this |
| Inbound NSG — port 22 | Your IP only | SSH access |

> ⚠️ **Static IP:** Go to your VM → Public IP address → Configuration and set Assignment from **Dynamic** to **Static**. Azure reassigns dynamic public IPs when a VM stops — a static IP means your browser bookmarks and NSG rules never need updating.

---

## Step 2 — Install Splunk on the Ubuntu VM

### Connect via SSH

**macOS / Linux:**
Visual Studio Code was used to run this command. Make sure your terminal is set to bash and NOT Powershell. Avoids the need for using going anywhere else to run commands used in the lab.
<img width="1113" height="938" alt="01  VS must have terminal as Bash not Powershell" src="https://github.com/user-attachments/assets/19aa23c2-f0f4-45b1-b879-f852c955b10a" />


```bash
# Fix key file permissions first (required — SSH will refuse connection without this)
cd ~/location_of_pem_file
chmod 400 yourkey.pem

# Connect
ssh -i yourkey.pem azureuser@YOUR_VM_PUBLIC_IP
```

**Windows (PuTTY):**
1. Open PuTTY → enter your VM's public IP in Host Name
2. Port: `22`, Connection type: SSH → click Open
3. Accept the host key fingerprint → enter your username and password

> 💡 When typing your password in PuTTY, nothing appears on screen — no dots, no asterisks. This is normal Linux behaviour. Type your password and press Enter.

### Install Splunk

Run each command in order inside your SSH session:

```bash
# Command 1 — Download the Splunk installer
wget -O splunkforwarder-10.4.1-5a009d941268-linux-arm64.deb "https://download.splunk.com/products/universalforwarder/releases/10.4.1/linux/splunkforwarder-10.4.1-5a009d941268-linux-arm64.deb"

# NOTE: if this returns 404, Splunk has released a newer version.
# Log into splunk.com → Free Trials and Downloads → Linux .deb
# Copy the wget command shown on the current download page.
```

```bash
# Command 2 — Install the package
# A warning about missing Python 3.7 path is expected and harmless on Ubuntu 22.04
sudo dpkg -i splunkforwarder-10.4.1-5a009d941268-linux-arm64.deb
```

```bash
# Command 3 — Start Splunk and accept the licence
# You will be prompted to create an admin username and password — write these down
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root
```

```bash
# Command 4 — Enable Splunk to start on every VM boot
sudo /opt/splunk/bin/splunk enable boot-start
```

### Access the Splunk Web UI

Once the start command completes, open a browser on your local machine:

```
http://YOUR_VM_PUBLIC_IP:8000
```

**If the browser shows "This site can't be reached" — work through these checks in order:**

| Check | Action |
|---|---|
| **1. NSG rule for port 8000** | Azure portal → your Splunk VM → Networking → Inbound port rules → Add rule: port `8000`, source = My IP address, priority `310`, name `Allow-SplunkWebUI-MyIP` |
| **2. Splunk is running** | SSH in and run: `sudo /opt/splunk/bin/splunk status` — expected output: `splunkd is running` |
| **3. Splunk is listening on 8000** | Run: `sudo ss -tlnp \| grep 8000` — expected: a line showing `0.0.0.0:8000` with `splunkd` |
| **4. Correct public IP** | Get the current IP from Azure portal → VM Overview. Dynamic IPs change when a VM is stopped — always check the portal |
| **5. Port 9997 NSG rule** | Add inbound rule to Splunk VM NSG: port `9997`, priority `320`, name `Allow-SplunkForwarder-WindowsVM` |
| **6. VNet Peering (if VMs are in different VNets)** | Azure portal → Your Splunk VM → Resource group → your Splunk VNet → Peerings → Add. Name the links descriptively: `splunk-vnet-to-ad-vnet` and `ad-vnet-to-splunk-vnet`. In first virtual network setting select the one associated with your windows VM.  Wait for both to show status **Connected** before continuing. Go to Powershell and restart Forwarder with command `Restart-Service SplunkForwarder` |

---

## Step 3 — Configure Data Inputs

### Part A — Enable Receiving in Splunk

Do this in the Splunk web UI before installing the forwarder:

1. Log into `http://YOUR_VM_IP:8000`
2. Click **Settings** → Forwarding and Receiving → Configure Receiving → New Receiving Port → enter `9997` → Save
3. Click **Settings** → Indexes → Create New Index → name it `windows_logs` → Save

### Part B — Install the Universal Forwarder on Windows Server

Do this on your **Windows Server VM from Lab 1** — not the Ubuntu VM.

1. On the Windows Server VM, go to [splunk.com/en_us/download/universal-forwarder.html](https://www.splunk.com/en_us/download/universal-forwarder.html)
2. Download the **Windows 64-bit** `.msi` installer
3. Run the installer — follow each screen exactly:

| Screen | Setting |
|---|---|
| Installation Options | Check the licence box. Select **An on-premises Splunk Enterprise instance**. Do NOT select Splunk Cloud |
| Administrator credentials | Username: `admin`. Uncheck Generate random password. Set a password and write it down |
| Deployment Server | **Leave completely blank.** Do not enter your Splunk VM IP here |
| Receiving Indexer | Enter your Splunk VM's **private IP** (from the Azure portal in the Overview section under Networking) and port `9997` |

> ⚠️ The Deployment Server field is a common mistake. Entering your Splunk VM IP here causes the forwarder to phone home to the wrong address and no data will flow. Leave it blank.

### Part C — Configure inputs.conf

If VS code is installed, after going to file path type below, type 'code .' in the file directory section and it will open VS Code at this exact directory.
Create this file on your **Windows Server VM** using VS Code (Run as Administrator):

**File path:** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`

> If the `local` folder does not exist, create it in Windows Explorer first.

Create a new file in VS Code called inputs.conf and insert this script:

```ini
# Each section in square brackets defines one log source to collect

[WinEventLog://Security]
# Security log — all authentication events: logins, failures, lockouts
disabled = 0
# disabled=0 means enabled
start_from = oldest
# Collect historical events, not just new ones going forward
current_only = 0
evt_resolve_ad_obj = 1
# Resolve AD object names so usernames appear instead of SIDs
index = windows_logs
# Required — without this, data goes to the main index not windows_logs

[WinEventLog://System]
# System log — OS-level events: service starts/stops, driver failures
disabled = 0
index = windows_logs

[WinEventLog://Application]
# Application log — events from installed applications
disabled = 0
index = windows_logs
```

After saving, restart the forwarder in PowerShell (run as Administrator):

```powershell
Restart-Service SplunkForwarder
```

---

## Step 4 — Generate Test Log Data

A fresh Windows Server VM has mostly empty Security logs. Run this script to generate realistic security events before running SPL searches.

> This script creates a temporary local user account called `labtest.user`, generates login activity against it, then deletes it. Nothing is installed or changed permanently on the VM.

**Open PowerShell ISE as Administrator** (right-click Start → Windows PowerShell ISE (Admin)) and paste the entire script:

```powershell
# ============================================================
# Lab 3 Log Generator — Run as Administrator on the Windows VM
# Output saved to C:\lab3-log-output.txt
# ============================================================

$logFile = 'C:\lab3-log-output.txt'
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function Log($message, $color = 'White') {
    Write-Host $message -ForegroundColor $color
    Add-Content -Path $logFile -Value "[$timestamp] $message"
}

if (Test-Path $logFile) { Remove-Item $logFile }
Add-Content -Path $logFile -Value "Lab 3 Log Generator - Run started at $timestamp"
Add-Content -Path $logFile -Value '============================================='

Log 'Starting log generation...' Green

# Create a temporary test user account
$testUser = 'labtest.user'
$testPass = ConvertTo-SecureString 'TempPass123!' -AsPlainText -Force
New-LocalUser -Name $testUser -Password $testPass -Description 'Splunk lab test account' -ErrorAction SilentlyContinue
Log "Created test user: $testUser" Gray

# Generate failed logon attempts (Security log - Event ID 4625)
Log 'Generating failed logon attempts...' Yellow
$wrongPass = ConvertTo-SecureString 'WrongPassword!' -AsPlainText -Force
1..15 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($testUser, $wrongPass)
    Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}
Log '  Generated 15 failed logon attempts' Gray

# Generate successful login (Event ID 4624)
Log 'Generating successful login event (4624)...' Yellow
$correctPass = ConvertTo-SecureString 'TempPass123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($testUser, $correctPass)
Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c whoami' -Wait -ErrorAction SilentlyContinue
Log '  Generated successful login (Event ID 4624)' Gray

# Generate service start/stop events (Event ID 7036)
Log 'Generating service events...' Yellow
$services = @('Spooler','Schedule','Netlogon')
$services | ForEach-Object {
    Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name $_ -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Log "  Stopped and restarted service: $_" Gray
}

# Generate application log entries
Log 'Generating application log events...' Yellow
$eventSource = 'SplunkLabTest'
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName Application -Source $eventSource -ErrorAction SilentlyContinue
}
1..5 | ForEach-Object {
    Write-EventLog -LogName Application -Source $eventSource -EventId 1001 `
        -EntryType Warning -Message 'Splunk lab test event - application warning'
    Start-Sleep -Milliseconds 300
}
Log '  Generated 5 application log entries (Event ID 1001)' Gray

# Lock out the test account (Event ID 4740)
Log 'Generating account lockout event (4740)...' Yellow
$badCred = ConvertTo-SecureString 'BadPass!' -AsPlainText -Force
1..20 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($testUser, $badCred)
    Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 200
}
Log '  Account lockout triggered (Event ID 4740)' Gray

# Clean up the test account
Start-Sleep -Seconds 3
Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue
Log "Removed test user: $testUser" Gray

# Restart the forwarder to ship events to Splunk
Log 'Restarting forwarder to ship events to Splunk...' Yellow
Restart-Service SplunkForwarder -ErrorAction SilentlyContinue
Log '  SplunkForwarder restarted' Gray

$endTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content -Path $logFile -Value '============================================='
Add-Content -Path $logFile -Value "Run completed at $endTime"

Write-Host ''
Write-Host '=============================================' -ForegroundColor Green
Write-Host 'Done. Output saved to C:\lab3-log-output.txt' -ForegroundColor Green
Write-Host 'Wait 60 seconds then search Splunk.' -ForegroundColor Green
Write-Host '=============================================' -ForegroundColor Green
```

> ⏱️ After the script finishes, wait **60 seconds** for the forwarder to ship the events. Then set the Splunk time range to **All Time** and run: `index=windows_logs | head 100`. If you see events, you are ready for Step 5.

---

## Step 5 — Essential SPL Searches

All searches are typed into the search bar at the top of the Search & Reporting app. Select a time range using the picker on the right side of the search bar.

### Confirm Data is Flowing
```spl
index=windows_logs | head 100
```
If this returns results, your forwarder is working. If it returns nothing, check that the `SplunkForwarder` service is running on the Windows VM.
Here is an example of how it should look
<img width="1902" height="1016" alt="image" src="https://github.com/user-attachments/assets/b43ac3ac-8dbd-4b7a-9933-a325c7948647" />

### Find Successful Logins (Event ID 4624)
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name
| sort -count

# stats count by Account_Name  — count events grouped by each account
# sort -count                  — highest count first
# Account names ending in $ are computer accounts — normal and expected
```
Here is an example of how it should look:
<img width="1909" height="895" alt="image" src="https://github.com/user-attachments/assets/9c2de698-dee6-44d0-bb0e-76f9717134ba" />

### Detect After-Hours Logins
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, Account_Name, Account_Domain, ComputerName
| sort -_time

# eval hour=strftime(_time, "%H")  — extract just the hour from the timestamp
# where hour < 7 OR hour > 19     — keep only events outside 7am–7pm
# Human accounts (no $) logging in after hours warrant review
```
Here is an example of how it should look:
<img width="1904" height="1021" alt="image" src="https://github.com/user-attachments/assets/24b6ff02-c9d2-4a4c-9ce3-ecaecbca8960" />

### Detect Logon with Explicit Credentials (Event ID 4648)
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4648
| table _time, Account_Name, Target_Server_Name, Process_Name
| sort -_time

# Fires when credentials are explicitly passed — runas, pass-the-hash, lateral movement
# Legitimate uses: scheduled tasks, backup agents
# Suspicious uses: lateral movement, credential stuffing
```
Here is an example of how it should look:
<img width="1907" height="1000" alt="image" src="https://github.com/user-attachments/assets/4af2c4bd-4365-4495-96df-464ff89e24a5" />

### Detect Process Creation (Event ID 4688)
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4688
| stats count by Creator_Process_Name
| sort -count
| head 20

# Processes run from temp folders, AppData, or unusual paths are suspicious
# cmd.exe and powershell.exe spawned by unexpected parents are red flags
```
Here is an example of how it should look:
<img width="1901" height="988" alt="image" src="https://github.com/user-attachments/assets/60542349-ee0d-4141-b5a0-8d991434284e" />

### Detect Service Installations (Event ID 4697)
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4697
| table _time, Account_Name, Service_Name, Service_File_Name
| sort -_time

# Services are a favourite persistence mechanism for malware
# Services with random names or pointing to temp directories are suspicious
```
Here is an example of how it should look:
<img width="1904" height="980" alt="image" src="https://github.com/user-attachments/assets/a11bf5d3-2998-4aff-93eb-377828860dd3" />

---

## Step 6 — Build a Security Dashboard
How instead of searching these previous indexes individually, you can build a dashboard of them all so you don't have to keep searching this every time.

1. In Splunk, click **Dashboards** (it's on the left hand side) → **Create New Dashboard**
2. Title: `Windows Security Overview` · Type: **Classic Dashboards** · click **Create Dashboard**
3. Add each panel below using **Add Panel → New Search**

| Panel | Search | Visualization (click first under "New") |
|---|---|---|
| Account Activity — Last 24h | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| stats count by Account_Name \| sort -count` | Bar chart |
| Top Processes — Last 24h | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4688 \| stats count by Creator_Process_Name \| sort -count \| head 20` | Events list |
| Login Activity Over Time | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| timechart count` | Line chart |
| After-Hours Logins | `index=windows_logs sourcetype=WinEventLog:Security EventCode=4624 \| eval hour=strftime(_time, "%H") \| where hour < 7 OR hour > 19 \| table _time, Account_Name, Account_Domain, ComputerName \| sort -_time` | Events list |

---

## Step 7 — Create an Automated Alert

Alerts automate detection. Splunk runs a search on a schedule and notifies you when conditions are met — this is how real SOC detection works.

**Run this search first to confirm it works:**
```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4672
| stats count as privilege_logons by Account_Name, ComputerName
| where privilege_logons > 50

# Event 4672 fires when admin-level rights are assigned at logon
# > 50 privilege logons from an unexpected account is worth investigating
```

**Then save it as an alert:**

1. Click **Save As → Alert**
2. Name: `High Privileged Logon Count`
3. Alert type: **Scheduled**
4. Cron expression: `*/15 * * * *` (runs every 15 minutes)
5. Trigger condition: Number of Results **is greater than 0**
6. Trigger actions: **Add to Triggered Alerts** (logs to Activity → Triggered Alerts)
7. Click **Save**

> 💡 Alert quality determines monitoring quality. An alert that fires too broadly creates alert fatigue — analysts stop paying attention. An alert that is too narrow misses real threats. Tune thresholds based on false positive rates over time.

---

## Verification

| Check | How to Verify |
|---|---|
| Data is flowing | `index=windows_logs \| head 10` returns recent events |
| Login search works | EventCode=4624 search returns results |
| Dashboard is populated | Windows Security Overview shows charts with data |
| Alert is active | Settings → Searches, Reports, and Alerts — alert appears as Enabled |

> 📸 **Portfolio tip:** Take screenshots of your dashboard and alert configuration. Export a few interesting searches as reports. Write a one-paragraph summary of what each panel shows and why it matters. This is concrete, demonstrable SIEM experience before your first SOC job.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Browser can't reach port 8000 | Add NSG inbound rule for port 8000 from your IP — this is the most common cause |
| Splunk shows stopped | SSH in and run: `sudo /opt/splunk/bin/splunk start --accept-license --run-as-root` |
| No events in `windows_logs` after forwarder install | Check `inputs.conf` has `index = windows_logs` in every section. Restart forwarder: `Restart-Service SplunkForwarder` |
| Forwarder installed but data not flowing | Verify port 9997 NSG rule on Splunk VM allows traffic from Windows VM private IP |
| VMs can't communicate | Configure VNet Peering if VMs are in different VNets. Wait for both peering links to show **Connected** |
| `inputs.conf` changes not taking effect | Restart the forwarder after every `inputs.conf` edit: `Restart-Service SplunkForwarder` |
| Splunk download returns 404 | Log into splunk.com → Free Trials and Downloads → Linux .deb → copy the wget command for the current version |
| SPL search returns no results | Set the time range to **All Time** — the default time picker may be excluding your events |

---

## How This Transfers to Azure

| Splunk Concept | Azure Equivalent |
|---|---|
| Splunk index | Log Analytics workspace |
| Universal Forwarder | Azure Monitor Agent (AMA) |
| SPL search | KQL (Kusto Query Language) in Log Analytics |
| Splunk dashboard | Azure Monitor Workbook |
| Splunk alert | Microsoft Sentinel Analytics Rule |
| Event ID correlation | Sentinel UEBA and Fusion detection |

---

## Lab Series

| Lab | Topic | Status |
|---|---|---|
| Lab 1 | Active Directory | ✅ Complete |
| Lab 2 | Network Traffic Analysis with Wireshark | ✅ Complete |
| Lab 3 | Splunk SIEM & Log Analysis | ✅ Complete |
| Lab 4 | Coming soon | 🔄 In progress |

---

## Connect

Follow along — more labs covering Azure networking, Infrastructure as Code (Bicep/Terraform), and Azure DevOps pipelines are coming.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/michaelianyanwu)
