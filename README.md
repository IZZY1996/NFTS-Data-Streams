# Security Audit Tool (SAT) PowerShell module
This PowerShell Module can be used to audit various technologies. Currently what it can check is NFTS Alternate Data Streams (ADS) and Microsoft 365 Audit Logs. This can be used for threat hunting or forensics.

Bellow is some infomation on ADS if you need some (I'll hopefully just be able to hide that in the module soon)

# About Alternate Data Streams (ADS)

## Zone.Identifier Stream
Windows uses the stream name Zone.Identifier for storage of <a href="https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537183(v=vs.85)?redirectedfrom=MSDN">URL security zones</a>.<sub><sub><a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8">Microsoft Docs | 5.6.1 Zone.Identifier Stream</a></sub></sub>

This ADS is also known as the *Mark-of-the-Web (MOTW)*
  
The Contents of this ADS have a few variations 
  
A file *[MS-ADA1].pdf* was downloaded from the internet
```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://docs.microsoft.com/
HostUrl=https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-ADA1/%5bMS-ADA1%5d.pdf
```
  
A file *Band_Chart_-_11X17_Color.pdf* Downloaded from the internet (Discord in this case)
```
[ZoneTransfer]
ZoneId=3
HostUrl=https://cdn.discordapp.com/attachments/539252306579816474/620049600782401542/Band_Chart_-_11X17_Color.pdf
```
  
A file *WindowsFirewallHelper.dll* was extracted from a ZIP folder that was downloaded from the internet
```
[ZoneTransfer]
ZoneId=3
ReferrerUrl=C:\Users\XXXX\Downloads\Release_2.1.9.0002.zip
```  
  
A file *1610298430605.mp4* was downloaded from the internet (I think I got this one on discord)
```
[ZoneTransfer]
ZoneId=3
```

A file *doc_2020-06-08_20-11-54.mp4* I downloaded from Telegram (note that it has a blank line) `Not in the Script`
```
[ZoneTransfer]
ZoneId=3

```
  
A video file *2020-10-04 21-16-11_Trim* that was edited using the Windows Photo app (video was first captured using <a href="https://obsproject.com/">OBS</a>)
```
[ZoneTransfer]
LastWriterPackageFamilyName=Microsoft.Windows.Photos_8wekyb3d8bbwe
ZoneId=3
```
> *Note:* I've also seen the app used as *Microsoft.ScreenSketch_8wekyb3d8bbwe* and *Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe* These are AppX packages. If you see something you don't recognise you can use the powershell `Get-AppxPackage | ? {$_.PackageFamilyName -eq "Microsoft.ScreenSketch_8wekyb3d8bbwe"}` or whatever you're looking for.
  
A file *TipsToPublicSpeaking.pdf* probably saved or "print to PDF" from the old edge (this file was from 2017)
```
[ZoneTransfer]
ZoneId=3
LastWriterPackageFamilyName=Microsoft.MicrosoftEdge_8wekyb3d8bbwe
AppZoneId=4
```
  
A table of the ZoneIds
| Value | Zone |
| --- | --- |
| 0 | Local Computer |
| 1 | Local Intranet |
| 2 | Trusted Sites |
| 3 | Internet |
| 4 | Restricted Sites |
## SmartScreen Stream
I've only seen one value for this ADS
```
Anaheim
```
> *Note:* Anaheim was the codename for the Chromium based Microsoft Edge <sub><sub><a href="https://en.wikipedia.org/wiki/Microsoft_Edge#New_Edge_(2019%E2%80%93present)">Wikipedia | Microsoft Edge</a></sub></sub>
  
## Afp_AfpInfo Stream
Existance of Afp_AfpInfo stream on some files is normal, and as such is of no cause for concern. This stream is generated on some file shares for support for Macintosh system (AFP = Apple Filing Protocol).<sub><sub><a href="https://www.f-secure.com/v-descs/afpinfo.shtml"> F-Secure | Afp_AfpInfo </a></sub></sub>
  
A file *INVITE.pdf* (and most PDFs I checked) has this value
```
AFP☺€PDF CARO
```
## AFP_Resource Stream

## com.apple.metadata_kMDItemUserTags Stream
  
## com.apple.lastuseddate#PS Stream
  
## OECustomProperty Stream
Outlook Express uses the stream name OECustomProperty for storage of custom properties related to email files.<sub><sub><a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f1adfb03-a5ca-49e5-9f0e-c01b7c56c2e3"> Microsoft Docs | 5.6.2 Outlook Express Properties Stream Name </a></sub></sub>
