param([switch]$Console)
# Turn this shit off, geez 
$global:ErrorActionPreference = "SilentlyContinue"
# Threat hunting IP Scanner -- for Reporting integration.

if($Console){
    # Pull API resources to JSON file
    echo "We're gonna do stuff here lol"
    exit
}
function CreateGUI{
    # Global Form Creation
    Add-Type -assembly System.Windows.Forms
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $MainForm = New-Object System.Windows.Forms.Form

    # Form Settings
    $MainForm.Text = "IPv4 Threat Scanner"
    $mainForm.Width = 350
    $MainForm.Height = 225
    $Mainform.MaximizeBox = $false
    $Mainform.MinimizeBox = $True
    $mainform.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
    return $MainForm
}

function IP_ScanBox($MainForm){
    $global:ThreatSearch = New-Object System.Windows.Forms.TextBox
    $ThreatSearch.Text = "IPv4 address to search"
    $ThreatSearch.Location = New-Object System.Drawing.Point(25,25)
    $ThreatSearch.Width = 300
    $ThreatSearch.Height = 10
    $MainForm.Controls.Add($ThreatSearch)
    Write-Host $ThreatSearch.Text
    $Button = New-Object System.Windows.Forms.Button 
    $Button.Text = "Submit"
    $Button.Location = New-Object System.Drawing.Point(125,125)
    $Button.Width = 100
    $Button.Height = 25
    $MainForm.AcceptButton = $Button
    $Mainform.Controls.Add($Button)
    $global:VTAPIKey = New-Object System.Windows.Forms.TextBox
    $VTAPIKey.Text ="VirusTotal API Key"
    $VTAPIKey.Location = New-Object System.Drawing.Point(25,50)
    $VTAPIKey.Width = 300
    $VTAPIKey.Height = 10
    $global:ShodanKey = New-Object System.Windows.Forms.TextBox
    $ShodanKey.Text = "Shodan API Key"
    $ShodanKey.Location = New-Object System.Drawing.Point(25,75)
    $ShodanKey.Width = 300
    $ShodanKey.Height = 10
    $global:NistKey = New-Object System.Windows.Forms.TextBox
    $NistKey.Text = "NIST CVE Key"
    $NistKey.Location = New-Object System.Drawing.Point(25,100)
    $NistKey.Width = 300
    $NistKey.Height = 10
    # Change to some kind of JSON import / Export at some point
    try{
        # Rewrite for JSON object
        $APIKey = [Environment]::GetFolderPath("MyDocuments")
        $APIkey = Get-Content "$APIKey\IPThreatScan\APIKeys.json" -Raw
        $APIKey = ConvertFrom-Json -InputObject $APIKey
        $VTAPIKey.Text = $APIKey.VTAPI
        $ShodanKey.Text = $APIKey.SHAPI
        $NistKey.Text = $APIKey.NAPI
    }catch{}
    $MainForm.Controls.Add($VTAPIKey)
    $MainForm.Controls.Add($ShodanKey)
    $MainForm.Controls.Add($NistKey)
    $Button.Add_Click({
        $Save = [Environment]::GetFolderPath("MyDocuments")
        try{
            New-Item -path "$save" -Name "IPThreatScan" -ItemType "directory" -erroraction Stop
        }catch{}
        try{
            $Credentials = New-Object psobject
            Add-Member -InputObject $Credentials -MemberType NoteProperty -Name VTAPI -Value $VTAPIKey.Text -ErrorAction Inquire
            Add-Member -InputObject $Credentials -MemberType NoteProperty -Name SHAPI -Value $ShodanKey.Text
            Add-Member -InputObject $Credentials -MemberType NoteProperty -Name NAPI -Value $NistKey.Text            
            ConvertTo-Json -InputObject $Credentials | Out-File "$save\IPThreatScan\APIKeys.json"
            # 
            # New-Item -path "$save\IPThreatScan\" -Name "APIKeys.json" -ItemType "file" -value "$CredentialsSave" 
            # New-Item -Path "$save\IPThreatScan\" -Name "SHAPI.txt" -ItemType "file" -Value "$SHAPI"
        }catch{}
        $VTAPI = $VTAPIKey.Text
        $SHAPI = $ShodanKey.Text
        $global:NAPI = $NistKey.Text
        $SearchValue = $ThreatSearch.Text
        write-host $SearchValue
        Write-Host $VTAPI
        $Header = @{}
        $Header.add("x-apikey","$VTAPI")
        $URI = "https://www.virustotal.com/api/v3/ip_addresses/" + $SearchValue
        $VTResults = GetVT $URI $Header
        $TMResults = GetTM $SearchValue
        $VTResults | Out-File -FilePath VTResults.json
        $TMResults | Out-File -FilePath TMResults.json
        $ShodanResults = GetShodanResults $SearchValue $SHAPI
        StartReport $VTResults $TMResults $SearchValue $ShodanResults
        })
}    

function GetVT($URI, $Header){
    # RestMethod didn't work, file saving was scuffed, this was the only thing that produced results
    $Header.Keys 
    $Header.Values
    $URI
    #$VTResults = Invoke-RestMethod -Uri $URI -Method GET -Headers $Header -verbose -erroraction Inquire
    $VTResults = Invoke-WebRequest -URI $URI -Header $Header -Verbose -Outfile VTResults.json
    $VTResults = Get-Content VTResults.json -raw | ConvertFrom-Json
    return $VTResults | Select -ExpandProperty data | Select -ExpandProperty attributes
}

function GetTM($IP){
    $results =@()
    foreach($x in 1..6){
        $URI = "https://api.threatminer.org/v2/host.php?q=$IP" + "&rt=" + "$x"
        $Results += (Invoke-RestMethod -URI $URI -Verbose -outfile "TMResults$x.json")
        }   
    return $results
}

function ConvertUnixTime($UnixTime){
    $time = ([datetime] "1970-01-01Z").ToUniversalTime()
    $time = $time.addSeconds($UnixTime)
    return $Time
}

function GetShodanResults($IP, $SHAPI){
    # Switch to logic statement for non-key use
    $URI = "https://api.shodan.io/shodan/host/" + $IP + "?key=" + $SHAPI
    $Results = Invoke-RestMethod -Uri $URI -Method GET | Select * -Exclude data
    return $Results
}

function GetCVE($vuln){
    try{
        $URI = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+$vuln
        write-host $URI
        $Results = Invoke-RestMethod -Method GET -Uri $URI -Headers @{'apikey'=$NAPI}| Select -ExpandProperty vulnerabilities | Select -ExpandProperty cve
    }catch{
        $Results = "Failed to get request"
    }
    return $Results
    #  Invoke-RestMethod -Method GET -Uri "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218" | Select -ExpandProperty vulnerabilities | Select -ExpandProperty cve | Select -ExpandProperty descriptions | where lang -eq en | Select -ExpandProperty value
}

function StartReport($VTResults, $TMResults, $Address, $ShodanResults){
    # Create Report Variables
    Write-Host "Writing Report"
    $Detections = $VTResults | Select -expandproperty last_analysis_stats  
    $JoinDetections = "harmless:"+$Detections.harmless+" and malicious:"+$Detections.malicious
    $DetectionRating = if($Detections.malicious -gt $Detections.harmless){"malicious"}else{"harmless"}
    Write-Host $VTResults.last_analysis_date
    $DetectionsTime = ConvertUnixTime $VTResults.last_analysis_date
    $DetectionRecent = if((New-TimeSpan -Start $DetectionsTime -End (Get-Date) | Select TotalDays).TotalDays -gt 30){"not recent"}else{"recent"}
    $DetectionVotes = $VTResults.Total_votes
    $DetectionCountry = $VTResults | Select country | Out-String
    $DetectionOwner = $VTResults | Select as_owner | Out-String
    # $DetectionHashes = Invoke-RestMethod -URI TMHashes
    #  $DetectionFiles = TMFIles
    $DetectionDomains = (Get-Content -raw "TMResults3.json" | ConvertFrom-Json | select -ExpandProperty results).uri | Out-String
    $DetectionHashes = Get-Content -raw "TMResults4.json" | ConvertFrom-Json | Select-Object -ExpandProperty results
    $DetectionFiles = (Get-Content -Raw "TMResults6.json" | ConvertFrom-Json | Select-Object -ExpandProperty results).filename | Out-String

    # Title and summary
    $Word = New-Object -ComObject word.application
    $Word.Visible = $False
    $Document = $Word.documents.add()
    $Selection = $Word.Selection
    $Selection.font.size = 11
    $Selection.font.name = "Calibri"
    $Table = $Selection.tables.add($Selection.Range,1,1)
    # For further tables $Table.style ="Grid Table 5 Dark - Accent 3"
    $Table.Cell(1,1).Range.Style = "Heading 1"
    $Table.Cell(1,1).Range.text = "Executive Summary for $Address"
    # Bottom border visible
    # -3 bottom, -2 left, -4 right
    $Table.range.borders.OutsideLineStyle = 0
    $Table.Cell(1,1).Range.Borders.item(-3).LineStyle = 1
    $Word.Selection.Start = $Document.Content.end
    $Summary = @'
The address {0}, appears to operate out of {1} and is owned by {2}. Furthermore, the address is detected as {3} by VirusTotal. As such the address is considered to be {4}. This data is from {5} and is considered {6}. Additionally, there are {7} associated hashes and {8} associated domains with this address.
'@ -f $Address, $VTResults.country, $VTResults.as_owner, $JoinDetections, $DetectionRating, $DetectionsTime, $DetectionRecent, ($DetectionHashes).count, ($DetectionDomains).count   
    $Selection.TypeText("$Summary")
    $Selection.TypeParagraph()

    # Threat Details Table
    $Table = $Selection.tables.add($Selection.Range,6,2)
    $Table.Style = "Grid Table 5 Dark - Accent 3"
    $Table.AllowAutoFit = $True
    $Table.AllowPageBreaks = $True
    $Table.ApplyStyleFirstColumn = $True
    $Table.Cell(1,1).Range.Text = "Threat details for $Address"
    $Table.Cell(2,1).Range.text = "Last Analysis"
    $Table.Cell(2,2).Range.Text = "$DetectionsTime"
    $Table.Cell(3,1).Range.Text = "Total Votes"
    $Table.Cell(3,2).Range.Text = "$DetectionVotes"
    $Table.Cell(4,1).Range.Text = "Domains"
    $Table.Cell(4,2).Range.Text = "$DetectionDomains"
    $Table.Cell(5,1).Range.Text = "Hashes"
    $Table.cell(5,2).Range.Text = "$DetectionHashes"
    $Table.Cell(6,1).Range.Text = "Reports"
    $Table.Cell(6,2).Range.Text = "$DetectionFiles"
    $Word.Selection.Start = $Document.Content.end

    # Shodan Details
    $Table = $Selection.tables.add($Selection.Range,1,1)
    $Table.Cell(1,1).Range.Style = "Heading 1"
    $Table.Cell(1,1).Range.text = "Additional Address Details"
    $Table.range.borders.OutsideLineStyle = 0
    $Table.Cell(1,1).Range.Borders.item(-3).LineStyle = 1
    $Word.Selection.Start = $Document.Content.end
    $Selection.TypeParagraph()

    # Shodan details table
    $Table = $Selection.tables.add($Selection.Range,19,2)
    $Table.Style = "Grid Table 5 Dark - Accent 3"
    $Table.AllowAutoFit = $True
    $Table.AllowPageBreaks = $True
    $Table.ApplyStyleFirstColumn = $True
    $vulns = [string]::Join(', ',$ShodanResults.vulns)
    $Table.Cell(1,1).Range.Text = "Scan details for $Address"
    $Table.Cell(2,1).Range.text = "City"
    $Table.Cell(2,2).Range.Text = "$ShodanCity"
    $Table.Cell(3,1).Range.Text = "Region"
    $Table.Cell(3,2).Range.Text = "{0}" -f $ShodanResults.region_code
    $Table.Cell(4,1).Range.Text = "Operating System"
    $Table.Cell(4,2).Range.Text = "{0}" -f $ShodanResults.os
    $Table.Cell(5,1).Range.Text = "Tags"
    $Table.cell(5,2).Range.Text = "{0}" -f $ShodanResults.tags
    $Table.Cell(6,1).Range.Text = "IP"
    $Table.Cell(6,2).Range.Text = "{0}" -f $ShodanResults.ip_str
    $Table.Cell(7,1).Range.Text = "Internet Service Provider"
    $Table.Cell(7,2).Range.text = "{0}" -f $ShodanResults.isp
    $Table.Cell(8,1).Range.Text = "Area Code"
    $Table.Cell(8,2).Range.Text = "{0}" -f $ShodanResults.area_code
    $Table.Cell(9,1).Range.Text = "Latitude"
    $Table.Cell(9,2).Range.Text = "{0}" -f $ShodanResults.latitude
    $Table.Cell(10,1).Range.Text = "Longitude"
    $Table.Cell(10,2).Range.Text = "{0}" -f $ShodanResults.longitude
    $Table.cell(11,1).Range.Text = "Last Update"
    $Table.Cell(11,2).Range.Text = "{0}" -f $ShodanResults.last_update
    $Table.Cell(12,1).Range.Text = "Ports"
    $Table.Cell(12,2).Range.Text = "{0}" -f ([string]::Join(", ",$ShodanResults.ports))
    $Table.Cell(13,1).Range.text = "Vulnerabilities"
    $Table.Cell(13,2).Range.Text = "{0}" -f $vulns
    $Table.Cell(14,1).Range.Text = "Hostnames"
    $Table.Cell(14,2).Range.Text = "{0}" -f ([string]::Join(", ",$ShodanResults.hostnames))
    $Table.Cell(15,1).Range.Text = "Country Code"
    $Table.Cell(15,2).Range.Text = "{0}" -f $ShodanResults.country_code
    $Table.Cell(16,1).Range.Text = "Country Name"
    $Table.cell(16,2).Range.Text = "{0}" -f $ShodanResults.country_name
    $Table.Cell(17,1).Range.Text = "Domains"
    $Table.Cell(17,2).Range.Text = "{0}" -f ([string]::Join(", ",$ShodanResults.domains))
    $Table.Cell(18,1).Range.Text = "Organization"
    $Table.Cell(18,2).Range.Text = "{0}" -f $ShodanResults.org
    $Table.Cell(19,1).Range.Text = "ASN"
    $Table.Cell(19,2).Range.Text = "{0}" -f $ShodanResults.asn
    $Word.Selection.Start = $Document.Content.end

    # Generate new pages for each vulnerability 
    $vulnlist = $ShodanResults.vulns
    # $CVEDetails = Invoke-RestMethod -Method GET -Uri https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-20012 | Select -ExpandProperty vulnerabilities | Select -ExpandProperty cve
    foreach($x in $vulnlist){
        # write-host $x
        $CVEDetails = GetCVE $x
        if($CVEDetails -match "Failed"){
            Write-Host "Failed $x"
        }
        $CVSS = ($CVEDetails | Select-Object -ExpandProperty metrics | Select-Object -ExpandProperty cvssMetricV31 | Select -ExpandProperty cvssData).baseScore
        $Title = "$x Details"
        $Selection.InsertNewPage()
        $Table = $Selection.tables.add($Selection.Range,1,1)
        $Table.Cell(1,1).Range.Style = "Heading 1"
        Write-Host $Title
        $Table.Cell(1,1).Range.text = "$Title"
        $Table.range.borders.OutsideLineStyle = 0
        $Table.Cell(1,1).Range.Borders.item(-3).LineStyle = 1
        $Word.Selection.Start = $Document.Content.end
        $Selection.TypeParagraph()
        $CVSS = @'
CVSS: {0}
'@ -f $CVSS
        $Selection.TypeText($CVSS)
        $Selection.TypeParagraph()
        $Selection.Style = "Heading 2"
        $Selection.TypeText("Description")
        $Selection.TypeParagraph()
        $Selection.Style = "Body Text"
        $CVEDescription = @'
{0}
'@ -f ($CVEDetails | Select -ExpandProperty descriptions | Where lang -eq en | Select value).value
        $Selection.TypeText($CVEDescription)
        $Selection.TypeParagraph()
        $Selection.Style = "Heading 2"
        $Selection.TypeText("References")
        $Selection.TypeParagraph()
        $Selection.Style = "Body Text"
        $CVERef = @'
{0}
'@ -f ([String]::Join("`n",($CVEDetails | Select -ExpandProperty references | Select url).url))
        $Selection.TypeText($CVERef)
        $Selection.TypeParagraph()
        $Selection.Style = "Heading 2"
        $Selection.TypeText("Vulnerabilities")
        $Selection.TypeParagraph()
        $Selection.Style = "Body Text"       
        $CVEVuln = @'
{0}
'@ -f ([string]::Join("`n",($CVEDetails | Select -ExpandProperty configurations | Select -ExpandProperty nodes | Select -ExpandProperty cpeMatch | Where vulnerable -eq True | Select criteria).criteria))
        $Selection.TypeText($CVEVuln)
        $Selection.TypeParagraph()
        $Table = $Selection.tables.add($Selection.Range,3,2)
        $Table.Style = "Table Grid"
        $Table.Cell(1,1).Range.Text = "Source"
        $Table.Cell(1,2).Range.Text = "{0}" -f ($CVEDetails | Select sourceIdentifier).sourceIdentifier
        $Table.Cell(2,1).Range.Text = "Published"
        $Table.Cell(2,2).Range.Text = "{0}" -f ($CVEDetails | Select published).published
        $Table.Cell(3,1).Range.Text = "Last Modified"
        $Table.Cell(3,2).Range.Text = "{0}" -f ($CVEDetails | Select lastModified).lastModified
        $Word.Selection.Start = $Document.Content.end
        # Manually wait to not overload server - Changed to use NIST api key for 50req/30sec 
        # Enable this if there is no NIST API key 5req/30sec
        # Start-Sleep -Seconds 6
    }

    $Save = [Environment]::GetFolderPath("MyDocuments")
    $savepath = "$save\IPThreatScan\IPThreatScan.docx"
    try{
        $document.SaveAs([ref]$savepath)
        Write-Host "File saved to $savepath"
    }catch{
        Write-Host "Could not save - File is open"
    }
    $document.close()
    $Word.quit()
    start-process $savepath
    }


    # Executive Summary Heading
    # $Selection.Style = ""
    # Selection.TypeText("text")
    # Selection.TypeParagraph()
    # -   WhoIs – TM
    # -   Country – VT
    # -   Last analysis – VT – Link 
    # -   Total_votes – VT
    # -   If(mal) Domains – TM
    # -   If(mal) Hashes – TM
    # -   If(mal) Files – TM

$MainForm = CreateGUI
IP_Scanbox $MainForm
$MainForm.ShowDialog()