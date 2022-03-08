# NFTS Data Streams
This PowerShell Script can be used to find Alternate Data Streams (ADS) that are outside the normal expected types. This can be used for threat hunting or forensics on NTFS systems.

# About Alternate Data Streams (ADS)
All files on an NTFS volume consist of at least one stream - the main stream – this is the normal, viewable file in which data is stored. The full name of a stream is of the form <filename>:<stream name>:<stream type> The default data stream has no name. That is, the fully qualified name for the default stream for a file called "sample.txt" is "sample.txt::$DATA" since "sample.txt" is the name of the file and "$DATA" is the stream type. <sub><sub><a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85">Microsoft Docs | 5.1 NTFS Streams</a></sub></sub>
> *Note:* A directory can also have an ADS
  
Here is a table of all the standard attribute types<sub><sub><a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85">Microsoft Docs | 5.2 NTFS Attribute Types</a>
| Attribute Name | Description |
| --- | --- |
| $ATTRIBUTE_LIST | Lists the location of all attribute records that do not fit in the MFT record |
| $BITMAP | Attribute for Bitmaps |
| $DATA | Contains the default file data |
| $EA | Extended the attribute index |
| $EA_INFORMATION | Extended attribute information |
| $FILE_NAME | File name |
| $INDEX_ALLOCATION | The type name for a Directory Stream. A string for the attribute code for index allocation |
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


