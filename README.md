Using the API provided by PowerForensics this PowerShell script will create CSV files similar to those generated by CDQR for timeline analysis in a forensics investigation. You must have the PowerForensics module installed for this script to work properly.

Example: .\Create-ForensicsTimelines.ps1 -VolumeName E: -StartDate 01/01/2015 -EndData 01/01/2016 -Output Case_001

The above example will get information from the MFT, USN Journal, Registry (NTUSER.dat, SAM, SECURITY, SYSTEM, SOFTWARE), Event Logs, ShellLink Files, and Scheduled Jobs from the E: drive and only keep the information that is timestammped between 01/01/2015 and 01/01/2016
