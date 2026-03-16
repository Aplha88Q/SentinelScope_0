# Azure Sentinel KQL Queries — SentinelScope

These KQL (Kusto Query Language) queries were used in the **Azure Log Analytics Workspace** to parse, filter and visualize RDP brute force attack data ingested from the custom log table `Failed_rdp_geo_CL`.

---

## Query 1: Parse Raw Log & Extract Fields

```kql
Failed_rdp_geo_CL
| extend
    username     = extract(@"username:([^,]+)", 1, RawData),
    timestamp    = extract(@"timestamp:([^,]+)", 1, RawData),
    latitude     = extract(@"latitude:([^,]+)", 1, RawData),
    longitude    = extract(@"longitude:([^,]+)", 1, RawData),
    sourcehost   = extract(@"sourcehost:([^,]+)", 1, RawData),
    state        = extract(@"state:([^,]+)", 1, RawData),
    label        = extract(@"label:([^,]+)", 1, RawData),
    destination  = extract(@"destinationhost:([^,]+)", 1, RawData),
    country      = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count()
    by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude
```

**Purpose:** Parses the raw custom log entries using regex and summarizes unique attack events.

---

## Query 2: Top Attacking Countries

```kql
Failed_rdp_geo_CL
| extend country = extract(@"country:([^,]+)", 1, RawData)
| where country != ""
| summarize attack_count = count() by country
| top 15 by attack_count desc
| render barchart
```

---

## Query 3: Most Attempted Usernames

```kql
Failed_rdp_geo_CL
| extend username = extract(@"username:([^,]+)", 1, RawData)
| where username != "" and username != "N/A"
| summarize count() by username
| order by count_ desc
| take 20
| render barchart
```

---

## Query 4: Attack Volume Over Time

```kql
Failed_rdp_geo_CL
| extend ts = extract(@"timestamp:([^,]+)", 1, RawData)
| extend parsed_time = todatetime(ts)
| where isnotnull(parsed_time)
| summarize attack_count = count() by bin(parsed_time, 1d)
| render timechart
```

---

## Query 5: Brute Force Burst Detection (Anomaly)

```kql
Failed_rdp_geo_CL
| extend
    username = extract(@"username:([^,]+)", 1, RawData),
    ts       = extract(@"timestamp:([^,]+)", 1, RawData)
| extend parsed_time = todatetime(ts)
| where isnotnull(parsed_time)
| summarize attempt_count = count() by username, bin(parsed_time, 5m)
| where attempt_count > 5
| order by attempt_count desc
```

**Purpose:** Detects automated brute force — flags any username attempting more than 5 logins within a 5-minute window.

---

## Query 6: World Map Workbook Query

```kql
Failed_rdp_geo_CL
| extend
    latitude  = extract(@"latitude:([^,]+)", 1, RawData),
    longitude = extract(@"longitude:([^,]+)", 1, RawData),
    country   = extract(@"country:([^,]+)", 1, RawData),
    label     = extract(@"label:([^,]+)", 1, RawData)
| where country != "" and latitude != "" and longitude != ""
| summarize event_count = count() by country, latitude, longitude, label
```

**Purpose:** Powers the Azure Sentinel Workbook world map showing real-time attack origins plotted by geolocation.
