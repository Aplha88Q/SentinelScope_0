# ============================================================
# SentinelScope - RDP Failed Login Geo-Logger
# ============================================================
# This script monitors Windows Event Viewer for failed RDP 
# login attempts (Event ID 4625), enriches each event with 
# geolocation data via ipgeolocation.io API, and logs results
# to a custom log file for ingestion into Azure Log Analytics.
#
# Usage:
#   1. Run on the Azure Windows VM as Administrator
#   2. Log file is created at C:\ProgramData\failed_rdp.log
#   3. Configure Azure Log Analytics to ingest this log file
# ============================================================

# Get API key from here: https://ipgeolocation.io/
$API_KEY      = "YOUR_API_KEY_HERE"
$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

# This filter retrieves failed RDP events (Event ID 4625) from Windows Event Viewer
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

<#
    Creates sample log entries to train the Extract feature 
    in Azure Log Analytics workspace. These are filtered out 
    later by checking destinationhost != "samplehost"
#>
Function write-Sample-Log() {
    "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13" | Out-File $LOGFILE_PATH -Append -Encoding utf8
}

# Create log file if it doesn't exist
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
}

# Infinite loop - continuously monitors Event Viewer for new failed logins
while ($true) {
    Start-Sleep -Seconds 1
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue

    foreach ($event in $events) {
        if ($event.properties[19].Value.Length -ge 5) {

            # Extract event fields
            $timestamp       = $event.TimeCreated
            $year            = $event.TimeCreated.Year
            $month           = $event.TimeCreated.Month.ToString().PadLeft(2, '0')
            $day             = $event.TimeCreated.Day.ToString().PadLeft(2, '0')
            $hour            = $event.TimeCreated.Hour.ToString().PadLeft(2, '0')
            $minute          = $event.TimeCreated.Minute.ToString().PadLeft(2, '0')
            $second          = $event.TimeCreated.Second.ToString().PadLeft(2, '0')
            $timestamp       = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $destinationHost = $event.MachineName
            $username        = $event.properties[5].Value
            $sourceHost      = $event.properties[11].Value
            $sourceIp        = $event.properties[19].Value

            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Only write if this timestamp doesn't already exist in the log
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
                Start-Sleep -Seconds 1

                # Call geolocation API to enrich the IP address with location data
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response     = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT
                $responseData = $response.Content | ConvertFrom-Json

                $latitude   = $responseData.latitude
                $longitude  = $responseData.longitude
                $state_prov = if ($responseData.state_prov -eq "") { "null" } else { $responseData.state_prov }
                $country    = if ($responseData.country_name -eq "") { "null" } else { $responseData.country_name }

                # Write enriched event to log file
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
        }
    }
}
