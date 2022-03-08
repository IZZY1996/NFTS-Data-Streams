##########################
#   Find Data Streams    #
##########################

$ror = @()
$streams = (Get-ChildItem -Recurse | get-item -stream * | Where-Object {$_.stream -ne ':$Data'})

foreach ($stream in $streams) {
    if ($stream.stream -eq "SmartScreen"){
        $ww = (get-content $stream.pspath)
        if ($ww -eq "Anaheim"){

        }
        else{
            $ror += $stream
        }
    }
    elseif ($stream.stream -eq "Zone.Identifier"){
        $ror += $stream
    }
    else {
        $ror += $stream
    }
}

# write output
ForEach ($s in $ror) {
    $r = $s.psparentpath.ToString().split('Microsoft.PowerShell.Core\FileSystem::')
    write-host "$r\" -ForegroundColor darkGray -NoNewline
    write-host $s.PSChildName -ForegroundColor White
}
