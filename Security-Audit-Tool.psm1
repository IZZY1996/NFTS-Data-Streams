function Get-SATDataStream {
    <#
        .SYNOPSIS
            A script that can be used to find Alternate Data Streams (ADS) that are outside the normal expected types. This can be used for threat hunting or forensics on NTFS volumes.
        .DESCRIPTION
            To view a full view of what's normal or expected in the ADS, or to view more information use -full and view the NOTES section. 
        .NOTES
            ------ Alternate Data Streams (ADS) -------
            Alternate Data Streams (ADS) in NFTS was originally intended to allow for compatibility with Macintosh’s Hierarchical File System (HFS) 
            
            All files on an NTFS volume consist of at least one stream - the main stream – this is the normal, viewable file in which data is stored. The full name of a stream is of the form :: The default data stream has no name. That is, the fully qualified name for the default stream for a file called "sample.txt" is "sample.txt::$DATA" since "sample.txt" is the name of the file and "$DATA" is the stream type.
            
            https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85

            <Note:> A directory can also have an ADS

            A table of all the standard attribute types
            Attribute Name          Description
            ---------------         ------------
            $ATTRIBUTE_LIST         Lists the location of all attribute records that do not fit in the MFT record
            $BITMAP                 Attribute for Bitmaps (Currently Used)
            $DATA                   Contains the default file data (Currently Used)
            $EA	                    Extended the attribute index
            $EA_INFORMATION	        Extended attribute information
            $FILE_NAME	            File name
            $INDEX_ALLOCATION	    The type name for a Directory Stream. A string for the attribute code for index allocation (Currently Used)
            $INDEX_ROOT	            Used to support folders and other indexes
            $LOGGED_UTILITY_STREAM	Use by the encrypting file system
            $OBJECT_ID	            Unique GUID for every MFT record
            $PROPERTY_SET	        Obsolete
            $REPARSE_POINT	        Used for volume mount points
            $SECURITY_DESCRIPTOR	Security descriptor stores ACL and SIDs
            $STANDARD_INFORMATION	Standard information, such as file times and quota data
            $SYMBOLIC_LINK	        Obsolete
            $TXF_DATA	            Transactional NTFS data
            $VOLUME_INFORMATION	    Version and state of the volume
            $VOLUME_NAME	        Name of the volume
            $VOLUME_VERSION	        Obsolete. Volume version

            https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85

            --------------------------------------------
    #>
    [CmdletBinding()]
    param()

    $ror = @()
    $streams = (Get-ChildItem -Recurse | get-item -stream * | Where-Object { $_.stream -ne ':$Data' })
    
    foreach ($stream in $streams) {
        if ($stream.Stream -eq "SmartScreen") {
            # if the stream is a smartscreen
        
            $ww = (get-content $stream.pspath)
            
            if ($ww -eq "Anaheim") {}
            else { $ror += $stream }
        }
        elseif ($stream.Stream -eq "Zone.Identifier") {
            # if the stream is a MOTW
    
            $yy = Get-Content -LiteralPath $stream.pspath.ToString()
    
            if (($yy.Length -eq 4 -or $yy.length -eq 3) -and ($yy[0] -eq "[ZoneTransfer]") -and ($yy[1] -match 'ZoneID=[1234]') -and ($yy[2] -match 'ReferrerUrl=+.' -or $yy[2] -match 'HostUrl=+.')) {}
            elseif (($yy.Length -eq 2) -and ($yy[0] -eq "[ZoneTransfer]") -and ($yy[1] -match 'ZoneID=[1234]')) {}
            elseif (($yy.Length -eq 3) -and ($yy[0] -eq "[ZoneTransfer]") -and ($yy[1] -match 'LastWriterPackageFamilyName=+.') -and ($yy[2] -match 'ZoneID=[1234]')) {}
            elseif (($yy.Length -eq 4) -and ($yy[0] -eq "[ZoneTransfer]") -and ($yy[1] -match 'ZoneID=[1234]') -and ($yy[2] -match 'LastWriterPackageFamilyName=+.') -and ($yy[3] -match 'ZoneID=\d')) {}
            else { $ror += $stream }
        }
        elseif ($stream.Stream -eq "Afp_AfpInfo") {
        
            $ll = Get-Content -LiteralPath $stream.pspath.ToString()
            
            if ($ll -eq 'AFP☺€PDF CARO') {}
            else { $ror += $stream }
        }
        else { $ror += $stream } # if none of the above apply
    }
    
    # write output
    "------------ Suspicious Data Streams ------------"
    ForEach ($s in $ror) {
        $e, $r = $s.PSParentPath -split "::"
        Write-Host "$r\" -ForegroundColor darkGray -NoNewline
        Write-Host $s.PSChildName -ForegroundColor White
    }
}

function Backup-SATM365Log {
    <#
        .SYNOPSIS
            A tool to backup and splice the audit logs together for archiving purposes, to get past the 90 day retention period limitation
    #>
    [CmdletBinding()]
    param(
        $file = "C:\AuditLogSearch\backup.json",
        [DateTime]$start = [DateTime]::UtcNow.Addhours(-10),
        [DateTime]$end = [DateTime]::UtcNow.AddHours(-5)
    )
    process {
        $mergedfile =@()
        if (test-path $file) {
            $ficont = get-content $file | ConvertFrom-Json
            [datetime]$lastcontent = (($ficont[($ficont.count) - 1]).creationtime).Addhours(-1)
            $d = Search-SATM365Log -jsonfile "C:\AuditLogSearch\backupnew.json" -start $lastcontent -end $([DateTime]::UtcNow)
            $t = (Get-Content $file | ConvertFrom-Json | Sort-Object CreationTime)
            $y = (Get-Content "C:\AuditLogSearch\backupnew.json" | ConvertFrom-Json | Sort-Object CreationTime)
            #
            # Holy cow this is awful, I'll clean it up later, but that's the idea 
            #
            $yc = @()
            $tc = @()
            for ($i = 0;$i -lt $y.count; $i++){
                if ($t[$t.count-10].id -eq $y[$i].id) {
                    #Write-host "---- Base ---------------------------- New ----"
                    #write-host " $(($t.count)-10) $($t[($t.count)-10].creationtime)    $i $($y[$i].creationtime)"
                    $tc += $t.count-10
                    $yc += $i
                    for ($i = 0;$i -lt $y.count; $i++){
                        if ($t[$t.count-11].id -eq $y[$i].id) {
                            #write-host " $(($t.count)-11) $($t[($t.count)-11].creationtime)    $i $($y[$i].creationtime)"
                            $tc += $t.count-11
                            $yc += $i
                            for ($i = 0;$i -lt $y.count; $i++){
                                if ($t[$t.count-12].id -eq $y[$i].id) {
                                    #write-host " $(($t.count)-12) $($t[($t.count)-12].creationtime)    $i $($y[$i].creationtime)"
                                    $tc += $t.count-12
                                    $yc += $i
                                    for ($i = 0;$i -lt $y.count; $i++){
                                        if ($t[$t.count-13].id -eq $y[$i].id) {
                                            #write-host " $(($t.count)-13) $($t[($t.count)-13].creationtime)    $i $($y[$i].creationtime)"
                                            $tc += $t.count-13
                                            $yc += $i
                                            for ($i = 0;$i -lt $y.count; $i++){
                                                if ($t[$t.count-14].id -eq $y[$i].id) {
                                                    #write-host " $(($t.count)-14) $($t[($t.count)-14].creationtime)    $i $($y[$i].creationtime)"
                                                    $tc += $t.count-14
                                                    $yc += $i
                                                    for ($i = 0;$i -lt $y.count; $i++){
                                                        if ($t[$t.count-15].id -eq $y[$i].id) {
                                                            #write-host " $(($t.count)-15) $($t[($t.count)-15].creationtime)    $i $($y[$i].creationtime)"
                                                            $tc += $t.count-15
                                                            $yc += $i
                                                            for ($i = 0;$i -lt $y.count; $i++){
                                                                if ($t[$t.count-16].id -eq $y[$i].id) {
                                                                    #write-host " $(($t.count)-16) $($t[($t.count)-16].creationtime)    $i $($y[$i].creationtime)"
                                                                    $tc += $t.count-16
                                                                    $yc += $i
                                                                    for ($i = 0;$i -lt $y.count; $i++){
                                                                        if ($t[$t.count-17].id -eq $y[$i].id) {
                                                                            #write-host " $(($t.count)-17) $($t[($t.count)-17].creationtime)    $i $($y[$i].creationtime)"
                                                                            $tc += $t.count-17
                                                                            $yc += $i
                                                                            for ($i = 0;$i -lt $y.count; $i++){
                                                                                if ($t[$t.count-18].id -eq $y[$i].id) {
                                                                                    #write-host " $(($t.count)-18) $($t[($t.count)-18].creationtime)    $i $($y[$i].creationtime)"
                                                                                    $tc += $t.count-18
                                                                                    $yc += $i
                                                                                    for ($i = 0;$i -lt $y.count; $i++){
                                                                                        if ($t[$t.count-19].id -eq $y[$i].id) {
                                                                                            #write-host " $(($t.count)-19) $($t[($t.count)-19].creationtime)    $i $($y[$i].creationtime)"
                                                                                            $tc += $t.count-19
                                                                                            $yc += $i
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ($yc[1] -eq $yc[0]-1) {
                if ($yc[1] -eq $yc[2]+1) {
                    $answer = 1
                }
            }else {
                if ($yc[2] -eq $yc[1]-1) {
                    if ($yc[2] -eq $yc[3]+1) {
                        $answer = 2
                    }
                }else {
                    if ($yc[3] -eq $yc[2]-1) {
                        if ($yc[3] -eq $yc[4]+1) {
                            $answer = 3
                        }
                    }else {
                        if ($yc[4] -eq $yc[3]-1) {
                            if ($yc[4] -eq $yc[5]+1) {
                                $answer = 4
                            }
                        }else {
                            if ($yc[5] -eq $yc[4]-1) {
                                if ($yc[5] -eq $yc[6]+1) {
                                    $answer = 5
                                }
                            }else {
                                if ($yc[6] -eq $yc[5]-1) {
                                    if ($yc[6] -eq $yc[7]+1) {
                                        $answer = 6
                                    }
                                }else {
                                    if ($yc[7] -eq $yc[6]-1) {
                                        if ($yc[7] -eq $yc[8]+1) {
                                            $answer = 7
                                        }
                                    }else {
                                        if ($yc[8] -eq $yc[7]-1) {
                                            if ($yc[8] -eq $yc[9]+1) {
                                                $answer = 8
                                            }
                                        }else {
                                            if ($yc[9] -eq $yc[8]-1) {
                                                if ($yc[9] -eq $yc[10]+1) {
                                                    $answer = 9
                                                }
                                            }else {
                                                "Can't merge the file try a different Timeframe"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            write-host "Possible merge found at Base[$($tc[$answer])] and New[$($yc[$answer])] at the Creation Time of $(($y[$($yc[$answer])]).creationtime)"
            $mergedfile = $t[0..($tc[$answer+1])]
            $mergedfile += $y[($yc[$answer])..($y.count-1)]
            $mergedfile | ConvertTo-Json | Out-File $file
        }
        else {
            Write-Host "Backup file not found at " -NoNewline; write-host "$file" -ForegroundColor DarkBlue
            $responce = Read-Host "Would you like to create a new one? (Y)es or (N)o"
            if ($responce -eq "Y") {
                $d = Search-SATM365Log -jsonfile $file -start $start -end $end
            }
            else {
                return
            }
        }
    }
}

function StatusBar {
    <#
        .SYNOPSIS
            To Simplify the output and make a cleaner looking progress bar
        .PARAMETER progress
            Takes the current progress in (for Math)
        .PARAMETER text
            Takes in text to output on the statusbar
    #>
    [CmdletBinding()]
    param(
        $progress,
        $text
    )

    process {
        $width = $Host.UI.RawUI.WindowSize.Width
        $h = [math]::round($width * $progress)

        if ($text.length -lt $width) {
            $remaning = $width - ($text.length)
            $text += " " * $remaning
        }

        $delete = "`b" * $width
        write-host $delete -NoNewline

        for ($i = 0; $i -lt $width; $i++) {
            if ($i -le (($width - $h) - 1)) {
                Write-host "$($text[$i])" -BackgroundColor DarkGreen -NoNewline
            }
            else {
                Write-host "$($text[$i])" -NoNewline
            }
        }
    }
}

function Search-SATM365Log {
    <#
        .SYNOPSIS
            A wrapper for Search-UnifiedAuditLog that can be used for searching larger amounts of logs
        .DESCRIPTION
            This is a tooled version of SearchAuditLog.ps1 For use in more interactive situations, original can be found https://docs.microsoft.com/en-us/microsoft-365/compliance/audit-log-search-script

            For more info on the results you get you can find the schema documantation here
            https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
        .EXAMPLE
            Search-SATM365Log -start "04/06/2022 1:00pm" -end "04/8/2022 11:00pm" | where {$_.clientip -match "192.227.123.135"} | ft creationtime, userid, operation, objectid

            Find all the AAD, Exchange, Sharepoint logs what were generated by the IP 192.227.123.135, for the selected days and displays it as a table with the basic info
        .EXAMPLE
            $r = Search-SATM365Log -start "04/07/2022 1:00am" -end "04/7/2022 11:00pm" ; write-output "$(($r | where {$_.operation -match "new-inboxrule"}).userid) created the rule" ($r | where {$_.operation -match "new-inboxrule"}).parameters

            Find all the inbox rules created during the time period specified
        .EXAMPLE
            ((Search-SATM365Log -start "04/07/2022 1:00am" -end "04/7/2022 11:00pm" | ? {$_ -match "targeted"})[0].insightdata).details

            Find a list of users who have been targeted the most by phish campaigns.
        .PARAMETER record
            Specifies the record type of the audit activities (also called operations) to search for. This property indicates the service or feature that an activity was triggered in. For a list of record types that you can use for this variable, https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype
        .PARAMETER start
            Specifies the start date of the range for the audit log search. The script will return records for audit activities that occurred within the specified date range.
        .PARAMETER end
            Specifies the end date of the range for the audit log search. The script will return records for audit activities that occurred within the specified date range.
        .PARAMETER logFile
            Specifies the name and location for the log file that contains information about the progress of the audit log search performed. The script writes UTC timestamps to the log file.
        .PARAMETER jsonFile
            Specifies the name and location of the JSON file that contains the audit records returned.
        .PARAMETER resultSize
            Specifies the number of results returned each time the Search-UnifiedAuditLog cmdlet is called by the script (called a result set). The value of 5,000 is the maximum value supported by the cmdlet. Leave this value as-is.
        .PARAMETER intervalMinutes
            To help overcome the limit of 5000 records returned, this variable takes the data range you specified and slices it up into smaller time intervals. Now each interval, not the entire date range, is subject to the 5000 record output limit of the command.
    #>

    [CmdletBinding()]
    Param (
        [validateset("ExhangeAdmin", "ExchangeItem", "ExchangeItemGroup", "SharePoint", "SharePointFileOperation", "OneDrive", "AzureActiveDirectory", "AzureActiveDirectoryAccountLogon", "DataCenterSecurityCmdlet", "ComplianceDLPSharePoint", "ComplianceDLPExchange", "SharePointSharingOperation", "AzureActiveDirectoryStsLogon", "SkypeForBusinessPSTNUsage", "SkypeForBusinessUsersBlocked", "SecurityComplianceCenterEOPCmdlet", "ExchangeAggregatedOperation", "PowerBIAudit", "CRM", "Yammer", "SkypeForBusinessCmdlets", "Discovery", "MicrosoftTeams", "ThreatIntelligence", "MailSubmission", "MicrosoftFlow", "AeD", "MicrosoftStream", "ComplianceDLPSharePointClassification", "ThreatFinder", "Project", "SharePointListOperation", "DataGovernance", "Kaizala", "SecurityComplianceAlerts", "ThreatIntelligenceUrl", "SecurityComplianceInsights", "MIPLabel", "WorkplaceAnalytics", "PowerAppsApp", "PowerAppsPlan", "ThreatIntelligenceAtpContent", "LabelContentExplorer", "TeamsHealthcare", "ExchangeItemAggregated", "HygieneEvent", "DataInsightsRestApiAudit", "InformationBarrierPolicyApplication", "SharePointListItemOperation", "SharePointContentTypeOperation", "SharePointFieldOperation", "MicrosoftTeamsAdmin", "HRSignal", "MicrosoftTeamsDevice", "MicrosoftTeamsAnalytics", "InformationWorkerProtection", "Campaign", "DLPEndpoint", "AirInvestigation", "Quarantine", "MicrosoftForms", "ApplicationAudit", "ComplianceSupervisionExchange", "CustomerKeyServiceEncryption", "OfficeNative", "MipAutoLabelSharePointItem", "MipAutoLabelSharePointPolicyLocation", "MicrosoftTeamsShifts", "MipAutoLabelExchangeItem", "CortanaBriefing", "WDATPAlerts", "SensitivityLabelPolicyMatch", "SensitivityLabelAction", "SensitivityLabeledFileAction", "AttackSim", "AirManualInvestigation", "SecurityComplianceRBAC", "UserTraining", "AirAdminActionInvestigation", "MSTIC", "PhysicalBadgingSignal", "AipDiscover", "AipSensitivityLabelAction", "AipProtectionAction", "AipFileDeleted", "AipHeartBeat", "MCASAlerts", "OnPremisesFileShareScannerDlp", "OnPremisesSharePointScannerDlp", "ExchangeSearch", "SharePointSearch", "PrivacyInsights", "MyAnalyticsSettings", "SecurityComplianceUserChange", "ComplianceDLPExchangeClassification", "MipExactDataMatch", "MS365DCustomDetection", "CoreReportingSettings")]
        $record = $null,
        [DateTime]$start = [DateTime]::UtcNow.AddDays(-1),
        [DateTime]$end = [DateTime]::UtcNow,
        $logFile = "C:\AuditLogSearch\AuditLogSearchLog.txt",
        $jsonfile = "C:\AuditLogSearch\AuditLogRecords.json",
        [validaterange(1, 5000)]
        $resultSize = 5000,
        $intervalMinutes = 60
    )

    process {

        $totalhours = [math]::Round((($end) - $start).Totalhours)
        $prog = 1
        $jsondata = @()

        ###############################################################
        #  Checks to make sure they are connected to Exchange Online  #  
        ###############################################################
        $hascommand = (get-command -verb search | Where-Object { $_.name -eq "Search-UnifiedAuditLog" })
        if ($hascommand) {}
        else {
            Write-host "You need to Connect to Exchange Online" -ForegroundColor Red
            Write-host "first run " -ForegroundColor Red -NoNewline; Write-Host "Connect-ExchangeOnline"
            Write-Host "to get access to the tools" -ForegroundColor Red
            return 
        }

        [DateTime]$currentStart = $start
        [DateTime]$currentEnd = $start

        Function Write-LogFile ([String]$Message) {
            $final = [DateTime]::Now.ToUniversalTime().ToString("s") + ":" + $Message
            $final | Out-File $logFile -Append
        }

        Write-LogFile "BEGIN: Retrieving audit records between $($start) and $($end), RecordType=$record, PageSize=$resultSize."
        StatusBar -progress $prog -text "Retrieving audit records for the date range between $($start) and $($end), RecordType=$record, ResultsSize=$resultSize"

        $totalCount = 0
        while ($true) {
            $currentEnd = $currentStart.AddMinutes($intervalMinutes)
            if ($currentEnd -gt $end) { $currentEnd = $end }

            if ($currentStart -eq $currentEnd) { break }
            $sessionID = [Guid]::NewGuid().ToString() + "_" + "ExtractLogs" + (Get-Date).ToString("yyyyMMddHHmmssfff")
            $CurrentTeaLeft = [math]::Round((($end) - $currentstart).Totalhours)
            $prog = [math]::round($CurrentTeaLeft / $totalhours, 2)
            Write-LogFile "INFO: Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
            StatusBar -progress $prog -text "Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"
            
            $currentCount = 0

            $sw = [Diagnostics.StopWatch]::StartNew()
            do {
                $results = Search-UnifiedAuditLog -StartDate $currentStart -EndDate $currentEnd -RecordType $record -SessionId $sessionID -SessionCommand ReturnLargeSet -ResultSize $resultSize
                if (($results | Measure-Object).Count -ne 0) {
                    $jsondata += $results.auditdata
                    $currentTotal = $results[0].ResultCount
                    $totalCount += $results.Count
                    $currentCount += $results.Count
                    Write-LogFile "INFO: Retrieved $($currentCount) audit records out of the total $($currentTotal)"

                    if ($currentTotal -eq $results[$results.Count - 1].ResultIndex) {
                        Write-LogFile "INFO: Successfully retrieved $($currentTotal) audit records for the current time range. Moving on!"
                        StatusBar -progress $prog -text "Successfully retrieved $($currentTotal) audit records for the current time range. Moving on to the next interval."
                        break
                    }
                }
            }
            while (($results | Measure-Object).Count -ne 0)

            $currentStart = $currentEnd
        }

        Write-LogFile "END: Retrieving audit records between $($start) and $($end), RecordType=$record, PageSize=$resultSize, total count: $totalCount."
        Write-Host "Script complete! Finished retrieving audit records for the date range between $($start) and $($end). Total count: $totalCount" -foregroundColor Green
        $jsondata |  out-file $jsonfile
        $jsondata | ConvertFrom-Json | Sort-Object CreationTime
    }
}

Export-ModuleMember -Function Search-SATM365Log
#Export-ModuleMember -Function Backup-SATM365Log
Export-ModuleMember -Function Get-SATDataStream
