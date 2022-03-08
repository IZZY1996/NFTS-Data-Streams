##########################
#   Find Data Streams    #
##########################

$ror = @()
$streams = (Get-ChildItem -Recurse | get-item -stream * | Where-Object {$_.stream -ne ':$Data'})

foreach ($stream in $streams) {
    if ($stream.Stream -eq "SmartScreen"){
        $ww = (get-content $stream.pspath)
        if ($ww -eq "Anaheim"){

        }
        else{
            $ror += $stream
        }
    }
    elseif ($stream.Stream -eq "Zone.Identifier"){
        $yy = Get-Content -LiteralPath $stream.pspath.ToString()
        if (($yy.Length -eq 4 -or $yy.length -eq 3) -and ($yy[0] -eq "[ZoneTransfer]") -and ($yy[1] -match 'ZoneID=[1234]') -and ($yy[2] -match 'ReferrerUrl=+.' -or $yy[2] -match 'HostUrl=+.')){
        }
        elseif (($yy.Length -eq 2 -or $yy.length -eq 3) -and ($yy[0] -eq "[ZoneTransfer]") -and ($yy[1] -match 'ZoneID=[1234]')) {

        }
        else {
            $ror += $stream 
        }
    }
    else {
        $ror += $stream
    }
}

# write output
ForEach ($s in $ror) {
    $e,$r = $s.PSParentPath -split "::"
    Write-Host "$r\" -ForegroundColor darkGray -NoNewline
    Write-Host $s.PSChildName -ForegroundColor White
}
