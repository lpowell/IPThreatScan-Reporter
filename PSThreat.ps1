# Threat hunting IP Scanner -- for Reporting integration.

function CreateGUI{
    # Global Form Creation
    Add-Type -assembly System.Windows.Forms
    Add-Type -AssemblyName PresentationCore,PresentationFramework
    $MainForm = New-Object System.Windows.Forms.Form

    # Form Settings
    $MainForm.Text = "IPv4 Threat Scanner"
    $mainForm.Width = 350
    $MainForm.Height = 150
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
    $Button.Location = New-Object System.Drawing.Point(125,70)
    $Button.Width = 100
    $Button.Height = 25
    $MainForm.AcceptButton = $Button
    $Mainform.Controls.Add($Button)
    $global:APIKey = New-Object System.Windows.Forms.TextBox
    $APIKey.Text ="VirusTotal API Key"
    $APIKey.Location = New-Object System.Drawing.Point(25,50)
    $APIKey.Width = 300
    $APIKey.Height = 10
    try{
        $VTAPI = [Environment]::GetFolderPath("MyDocuments")
        $VTAPI = Get-Content "$VTAPI\IPThreatScan\VTAPI.txt" -erroraction Stop
        $APIKey.Text = $VTAPI
    }catch{}
    $MainForm.Controls.Add($APIKey)
    $Button.Add_Click({
        try{
            $VTAPI = $APIKey.Text
            $Save = [Environment]::GetFolderPath("MyDocuments")
            New-Item -path "$save" -Name "IPThreatScan" -ItemType "directory" -erroraction Stop
            New-Item -path "$save\IPThreatScan\" -Name "VTAPI.txt" -ItemType "file" -value "$VTAPI" 
        }catch{}
        $VTAPI = $APIKey.Text
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
        StartReport $VTResults $TMResults $SearchValue
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

function StartReport($VTResults, $TMResults, $Address){
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

    # Full Details
    $Table = $Selection.tables.add($Selection.Range,1,1)
    $Table.Cell(1,1).Range.Style = "Heading 1"
    $Table.Cell(1,1).Range.text = "Additional Address Details"
    $Table.range.borders.OutsideLineStyle = 0
    $Table.Cell(1,1).Range.Borders.item(-3).LineStyle = 1
    $Word.Selection.Start = $Document.Content.end
    $Selection.TypeText("")


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