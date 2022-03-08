# NFTS Data Streams
This PowerShell Script can be used to find Alternate Data Streams (ADS) that are outside the normal expected types. This can be used for threat hunting or forensics on NTFS volumes.

Below is an about that will explain the normal behaviors you should expect in an ADS so you know what is normal and what you should look into further. This is all just based on what I've seen on my systems and from documents/blogs I've read.

# About Alternate Data Streams (ADS)
It was originally intended to allow for compatibility with Macintosh’s <a href="https://en.wikipedia.org/wiki/Hierarchical_File_System">Hierarchical File System (HFS)</a>

All files on an NTFS volume consist of at least one stream - the main stream – this is the normal, viewable file in which data is stored. The full name of a stream is of the form <filename>:<stream name>:<stream type> The default data stream has no name. That is, the fully qualified name for the default stream for a file called "sample.txt" is "sample.txt::$DATA" since "sample.txt" is the name of the file and "$DATA" is the stream type. <sub><sub><a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85">Microsoft Docs | 5.1 NTFS Streams</a></sub></sub>
> *Note:* A directory can also have an ADS
  
Here is a table of all the standard attribute types<sub><sub><a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85">Microsoft Docs | 5.2 NTFS Attribute Types</a></sub></sub>
| Attribute Name | Description |
| --- | --- |
| $ATTRIBUTE_LIST | Lists the location of all attribute records that do not fit in the MFT record |
| $BITMAP | Attribute for Bitmaps **(Currently Used)**|
| $DATA | Contains the default file data **(Currently Used)**|
| $EA | Extended the attribute index |
| $EA_INFORMATION | Extended attribute information |
| $FILE_NAME | File name |
| $INDEX_ALLOCATION | The type name for a Directory Stream. A string for the attribute code for index allocation **(Currently Used)**|
| $INDEX_ROOT | Used to support folders and other indexes |
| $LOGGED_UTILITY_STREAM | Use by the encrypting file system |
| $OBJECT_ID | Unique GUID for every MFT record |
| $PROPERTY_SET | Obsolete |
| $REPARSE_POINT | Used for volume mount points |
| $SECURITY_DESCRIPTOR | Security descriptor stores ACL and SIDs |
| $STANDARD_INFORMATION | Standard information, such as file times and quota data |
| $SYMBOLIC_LINK | Obsolete |
| $TXF_DATA | Transactional NTFS data |
| $VOLUME_INFORMATION | Version and state of the volume |
| $VOLUME_NAME | Name of the volume |
| $VOLUME_VERSION | Obsolete. Volume version |

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
  
A file *TipsToPublicSpeaking.pdf* probably saved or "print to PDF" from the old edge (this file was from 2017) `Not in the Script`
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
  
A file *INVITE.pdf* (and all PDFs I checked) has this value `Not in the Script`
```
AFP☺€PDF CARO
```
