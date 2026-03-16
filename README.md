# 🛡 SentinelScope

> **Azure SIEM-based RDP Brute Force Attack Monitoring & Analysis**

A cybersecurity project that uses **Microsoft Azure Sentinel (SIEM)** to monitor real-time RDP brute force attacks on a live Windows virtual machine, enrich attack events with geolocation data, and apply machine learning to classify and detect anomalous behavior.

> ⚠️ **Note:** The Azure subscription was shut down after the project to avoid cloud billing costs. All scripts, queries, and analysis code are preserved here.

---

## 🏗 Architecture

```
┌──────────────────────┐
│  Azure Windows VM    │──► RDP Port 3389 (Intentionally Exposed)
└──────────┬───────────┘
           │ Failed Login Events (Event ID 4625)
           ▼
┌──────────────────────┐
│  RDP_GeoLogger.ps1   │──► ipgeolocation.io API
│  (PowerShell Script) │    Enriches IP with lat/lon/country
└──────────┬───────────┘
           │ Writes to: C:\ProgramData\failed_rdp.log
           ▼
┌──────────────────────┐
│  Azure Log Analytics │──► Custom Table: Failed_rdp_geo_CL
│  Workspace (SIEM)    │
└──────────┬───────────┘
           │ KQL Queries
           ▼
┌──────────────────────┐
│  Azure Sentinel      │──► World Map Workbook (live attack map)
│  + ML Analysis       │──► Random Forest / Logistic Regression / SVM
└──────────────────────┘
```

---

## 📁 Project Structure

```
SentinelScope/
├── RDP_GeoLogger.ps1      # PowerShell script — runs on Azure VM
│                          # Monitors Event Viewer & enriches with geolocation
├── KQL_Queries.md         # All KQL queries used in Azure Sentinel
├── Data_Analysis.py       # EDA & visualizations on exported attack data
├── ML_Analysis.py         # ML models for threat classification
├── requirements.txt       # Python dependencies
└── README.md
```

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Cloud | Microsoft Azure (VM + Log Analytics + Sentinel) |
| Log Ingestion | Custom PowerShell Script + ipgeolocation.io API |
| Query Language | KQL (Kusto Query Language) |
| ML Models | Random Forest, Logistic Regression, SVM |
| Visualization | Plotly, Matplotlib, Seaborn |
| Language | Python 3.x, PowerShell |

---

## 🚀 How to Run (Local Analysis)

```bash
# Install dependencies
pip install -r requirements.txt

# Run data analysis & visualizations
python Data_Analysis.py

# Run ML model training & comparison
python ML_Analysis.py
```

> Requires `DTI_Project_new.xlsx` (exported Azure Sentinel data) in the same directory.

---

## 📊 Key Findings

- **1500+ failed RDP login attempts** captured from 15 countries
- **Top attacking countries:** Russia, China, India, Ukraine, United States
- **Most targeted usernames:** `administrator`, `admin`, `root`, `user`, `guest`
- **Peak attack hours:** 2 AM – 6 AM UTC (automated bot activity)
- **200+ anomalous brute force bursts** detected (>5 attempts / 5 min window)
- **Best ML model:** Random Forest — highest classification accuracy

---

## 🔑 Sample KQL Query (Azure Sentinel)

```kql
Failed_rdp_geo_CL
| extend
    username  = extract(@"username:([^,]+)", 1, RawData),
    latitude  = extract(@"latitude:([^,]+)", 1, RawData),
    longitude = extract(@"longitude:([^,]+)", 1, RawData),
    country   = extract(@"country:([^,]+)", 1, RawData)
| where country != ""
| summarize event_count=count() by country, latitude, longitude
| order by event_count desc
```

---

## 📜 Certifications Used
- CEHv12 (Certified Ethical Hacker)
- Secure Networked System with Firewall and IDS

---

## ⚠️ Disclaimer

This project was built for educational purposes in a controlled Azure environment. The VM was intentionally exposed to attract real-world attacks for analysis. No systems other than the owned Azure VM were targeted.
