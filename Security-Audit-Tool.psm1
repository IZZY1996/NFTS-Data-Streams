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
            $DATA	                Contains the default file data (Currently Used)
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
            A tool to backup and splice the audit logs together for archiving purposes, to get past the 90 day retention period
    #>
    [CmdletBinding()]
    param()

    process {}
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

            by: Jacob Petrie
        .EXAMPLE
            Search-AuditLog AzureActiveDirectory -start "03-22-2022" -end "03-24-2022" | ft  CreationDate, UserIds, Operations
            
            This will search for Audit Logs in AAD from March 22nd to the 24th
        .PARAMETER record
            Specifies the record type of the audit activities (also called operations) to search for. This property indicates the service or feature that an activity was triggered in. For a list of record types that you can use for this variable, https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype
        .PARAMETER start
            Specifies the start date of the range for the audit log search. The script will return records for audit activities that occurred within the specified date range.
        .PARAMETER end
            Specifies the end date of the range for the audit log search. The script will return records for audit activities that occurred within the specified date range.
        .PARAMETER logFile
            Specifies the name and location for the log file that contains information about the progress of the audit log search performed. The script writes UTC timestamps to the log file.
        .PARAMETER outputFile
            Specifies the name and location of the CSV file that contains the audit records returned.
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
        $jsondata | out-file $jsonfile
        $jsondata | ConvertFrom-Json | Sort-Object CreationTime
    }
}

Export-ModuleMember -Function Search-SATM365Log
#Export-ModuleMember -Function Backup-SATM365Log
Export-ModuleMember -Function Get-SATDataStream
