<# .SYNOPSIS
     Create digital forensic timelines for analysis
.DESCRIPTION
     This script uses the PowerForensics API to create a cmdlet Create-ForensicTimelines which
     generates several forensics timelines in .csv format. These timelines may or 
     may not be useful in an investigation.
.NOTES
     Author: Rodney Thomas - RodneyThomas@protonmail.com
     Thanks to @jaredcatkinson
.LINK
     N/A
#>

Param (
    [Parameter(Mandatory=$true)]
    [ValidatePattern({^\w{1}:$})]
    $VolumeName,
    [Parameter(Mandatory=$true)]
    [ValidatePattern({^\d{2}\/\d{2}\/\d{4}$})]
    $StartDate,
    [Parameter(Mandatory=$false)]
    [ValidatePattern({^\d{2}$})]
    $Hour,
    [Parameter(Mandatory=$false)]
    [ValidatePattern({^\d{2}$})]
    $Min,
    [Parameter(Mandatory=$false)]
    [ValidatePattern({^\d{2}$})]
    $Sec,
    [Parameter(Mandatory=$false)]
    [ValidatePattern({^\d{2}\/\d{2}\/\d{4}$})]
    $EndDate,
    [Parameter(Mandatory=$false)]
    [ValidatePattern({^.+$})]
    $Output,
    [Parameter(Mandatory=$false)]
    [ValidatePattern({^\w+})]
    $VerboseMode
)

#import PowerForensics
Import-Module PowerForensics

#set the start and end timeframe
#TODO: define this better...
if ($Hour -ne $null -and $Min -ne $null -and $Sec -ne $null)
{
    $start = Get-Date -Date $StartDate -Hour $Hour -Minute $Min -Second $Sec
}
else
{
    $start = Get-Date -Date $StartDate
     
}
$end = Get-Date -Date $EndDate

Write-Host "This might take awhile....`n"

#store scheduled jobs records
$sjobs = Get-ForensicScheduledJob -VolumeName $VolumeName
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "scheduled job count is: $($slink.Count)"
}
$sjobsWindow = $sjobs | Where-Object {($_.RunTime -gt $start -and $_.RunTime -lt $end) -or ($_.StartTime -gt $start -and $_.StartTime -lt $end)}
Write-Host "scheduled job count for timeframe: $($sjobsWindow.Count)"

#store the event logs records
$events = Get-ForensicEventLog -VolumeName $VolumeName
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "total event log count is: $($events.Count)"
}

$eventsWindow = $events | Where-Object {($_.WriteTime -gt $start -and  $_.WriteTime -lt $end)}
Write-Host "event log count for timeframe: $($eventsWindow.Count)"

#store the shell link records
$slink = Get-ForensicShellLink -VolumeName $VolumeName
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "total shell link count is: $($slink.Count)"
}

#store shell link records for set timeframe
$slinkWindow = $slink | Where-Object {($_.CreationTime -gt $start -and $_.CreationTime -lt $end) -or ($_.AccessTIme -gt $start -and $_.AccessTIme -lt $end) -or ($_.WriteTime -gt $start -and $_.WriteTime -lt $end)}
Write-Host "shell link count for timeframe: $($slinkWindow.Count)"

#store the master file table records
$mft = Get-ForensicFileRecord -VolumeName $VolumeName
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T")
{
    Write-Host "total mft record count is: $($mft.Count)"
}

#store the master file table records for set timeframe
$mftWindow = $mft | Where-Object {($_.ModifiedTime -gt $start) -and ($_.ModifiedTime -lt $end) -or ($_.AccessedTime -gt $start) -and ($_.AccessedTime -lt $end) -or ($_.ChangedTime -gt $start) -and ($_.ChangedTime -lt $end) -or ($_.BornTime -gt $start) -and ($_.BornTime -lt $end) -or ($_.FNModifiedTime -gt $start) -and ($_.FNModifiedTime -lt $end) -or ($_.FNAccessedTime -gt $start) -and ($_.FNAccessedTime -lt $end) -or ($_.FNChangedTime -gt $start) -and ($_.FNChangedTime -lt $end) -or ($_.FNBornTime -gt $start) -and ($_.FNBornTime -lt $end)}
Write-Host "mft record count for timeframe: $($mftWindow.Count)"

#store the update sequence number journal records
$usn = Get-ForensicUsnJrnl -VolumeName $VolumeName
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "total usn journal count is: $($usn.Count)"
}

#store the update sequence number journal records for set timeframe
$usnWindow = $usn | Where-Object {($_.TimeStamp -gt $start) -and ($_.TimeStamp -lt $end)}
Write-Host "usn journal count for timeframe: $($usnWindow.Count)`n"

#get ntuser data records for all users
$users = Get-ChildItem $VolumeName\Users | Where-Object {$_.PSIsContainer} | Where-Object {$_.Name -ne "Public"} | Foreach-Object {$_.Name}
Write-Host "`nFound the following users on volume $($VolumeName)"
Foreach($user in $users) 
{
    Write-Host "$($user)"
}
Write-Host ""  
$ntusersWindow = @()
Foreach($user in $users)
{
    Write-Host "getting ntuser.dat from $($user)"
    $path = "$($VolumeName)\Users\$($user)\NTUSER.dat"
    $ntusersWindow += Get-ForensicRegistryKey -HivePath $path | where {($_.WriteTime -gt $start) -and ($_.WriteTime -lt $end)}
}
Foreach($user in $users)
{
    $count = 0
    Foreach($ntuserData in $ntusersWindow)
    {
        if ($ntuserData | Where-Object {$_.HivePath -match $user})
        {
            $count++
        }
    }
    Write-Host "$($user) ntuser.dat count for timeframe: $($count)" 
}
Write-Host "`nntuser.dat count for timeframe: $($ntusersWindow.Count)"

#get sam registry records
$sam = Get-ForensicRegistryKey -HivePath E:\Windows\System32\config\SAM -Recurse
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "total sam count is: $($sam.Count)"
}

#get sam registry records for set timeframe
$samWindow = $sam | where {($_.WriteTime -gt $start) -and ($_.WriteTime -lt $end)}
Write-Host "sam count for timeframe: $($samWindow.Count)"

#get security registry records
$security = Get-ForensicRegistryKey -HivePath E:\Windows\System32\config\SECURITY -Recurse
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "total security count is: $($security.Count)"
}

#get security registry records for set timeframe
$securityWindow = $security | where {($_.WriteTime -gt $start) -and ($_.WriteTime -lt $end)}
Write-Host "security count for timeframe: $($securityWindow.Count)"

#get software registry records
$software = Get-ForensicRegistryKey -HivePath E:\Windows\System32\config\SOFTWARE -Recurse
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "total software count is: $($software.Count)"
}

#get software registry records for set timeframe
$softwareWindow = $software | where {($_.WriteTime -gt $start) -and ($_.WriteTime -lt $end)}
Write-Host "software count for timeframe: $($softwareWindow.Count)"

#get system registry records
$system = Get-ForensicRegistryKey -HivePath E:\Windows\System32\config\SYSTEM -Recurse
if ($VerboseMode -eq "t" -or $VerboseMode -eq "T") 
{
    Write-Host "total system count is: $($system.Count)"
}

#get system registry records for set timeframe
$systemWindow = $system | where {($_.WriteTime -gt $start) -and ($_.WriteTime -lt $end)}
Write-Host "system count for timeline: $($systemWindow.Count)`n"

#make timelines
Write-Host "Creating timelines..."
if ($Output -ne $null)
{
    $directoryPath = $Output
}
else
{
    $directoryPath = ".\Results"
}
$path = @()
if (Test-Path $directoryPath) 
{
    Remove-Item $directoryPath -Recurse -Force -ErrorAction Ignore
}
New-Item -Path $directoryPath -ItemType Directory | Out-Null
if ($sjobsWindow.Count -gt 0)
{
    $sjobsWindow | Select-Object -Property StartTime, RunTime, ApplicationName, Author, Status, Flags, Parameters, Uuid, IdleDeadline, IdleWait, RunningInstanceCount, MaximumRuntime, ErrorRetryCount, ErrorRetryInterval, Comment, ExitCode | Export-Csv -Path $directoryPath'\scheduledJobs.csv' -NoTypeInformation
}
if ($eventsWindow.Count -gt 0)
{
    $eventsWindow | Select-Object -Property WriteTime, LogPath, EventRecordId, EventData | Export-Csv -Path $directoryPath'\eventLog.csv' -NoTypeInformation
}
if ($slinkWindow.Count -gt 0)
{
    $slinkWindow | Select-Object -Property CreationTime, AccessTime, WriteTime, Path, LocalBasePath, FileAttributes, WorkingDirectory, RelativePath, LinkFlags | Export-Csv -Path $directoryPath'\shellLink.csv' -NoTypeInformation
}
if ($mftWindow.Count -gt 0)
{
    $mftWindow | Select-Object -Property ModifiedTime, AccessedTime, ChangedTime, BornTime, FNModifiedTime, FNAccessedTime, FNChangedTime, FNBornTime, FullName, Name, Permission, RealSize, AllocatedSize, RecordNumber, LogFileSequenceNumber, SequenceNumber, Hardlinks, Deleted, Directory | Export-Csv -Path $directoryPath'\mft.csv' -NoTypeInformation
}
if ($usnWindow.Count -gt 0)
{
    $usnWindow | Select-Object -Property TimeStamp, FileName, Reason, RecordNumber, FileSequenceNumber, ParentFileRecordNumber, ParentFileSequenceNumber, Usn, FileAttributes | Export-Csv -Path $directoryPath'\usnJournal.csv' -NoTypeInformation
}
Foreach($user in $users)
{
    $userNoSpace = $user -replace "\s","_"
    $path = "$($directoryPath)\ntuser_$($userNoSpace).csv"
    $userTempStorage = @()
    Foreach($ntuserData in $ntusersWindow)
    {
        if ($ntuserData | Where-Object {$_.HivePath -match $user})
        {
            $userTempStorage += $ntuserData
        }
    }
    if ($userTempStorage.Count -gt 0)
    {
        $userTempStorage | Select-Object -Property WriteTime, HivePath, Name, FullName, NumberOfSubKeys, NumberOfVolatileSubKeys, NumberOfValues, Allocated | Export-Csv -Path $path -NoTypeInformation
    }
}
if ($ntusersWindow.Count -gt 0)
{
    $ntusersWindow | Select-Object -Property WriteTime, HivePath, Name, FullName, NumberOfSubKeys, NumberOfVolatileSubKeys, NumberOfValues, Allocated | Export-Csv -Path $directoryPath'\ntuserAll.csv' -NoTypeInformation
}
if ($samWindow.Count -gt 0)
{
    $samWindow | Select-Object -Property WriteTime, HivePath, Name, FullName, NumberOfSubKeys, NumberOfVolatileSubKeys, NumberOfValues, Allocated | Export-Csv -Path $directoryPath'\sam.csv' -NoTypeInformation
}
if ($securityWindow.Count -gt 0)
{
    $securityWindow | Select-Object -Property WriteTime, HivePath, Name, FullName, NumberOfSubKeys, NumberOfVolatileSubKeys, NumberOfValues, Allocated | Export-Csv -Path $directoryPath'\security.csv' -NoTypeInformation
}
if ($softwareWindow.Count -gt 0)
{
    $softwareWindow | Select-Object -Property WriteTime, HivePath, Name, FullName, NumberOfSubKeys, NumberOfVolatileSubKeys, NumberOfValues, Allocated | Export-Csv -Path $directoryPath'\software.csv' -NoTypeInformation
}
if ($systemWindow.Count -gt 0)
{
    $systemWindow | Select-Object -Property WriteTime, HivePath, Name, FullName, NumberOfSubKeys, NumberOfVolatileSubKeys, NumberOfValues, Allocated | Export-Csv -Path $directoryPath'\system.csv' -NoTypeInformation
}
Get-ForensicTimeline -VolumeName $VolumeName | Where-Object {$_.Date -gt $start -and $_.Date -lt $end} | Export-Csv -Path $directoryPath'\timeframeTimeline.csv' -NoTypeInformation
Get-ForensicTimeline -VolumeName $VolumeName | Export-Csv -Path $directoryPath'\fullTimeline.csv' -NoTypeInformation
Write-Host "Timelines created!"
Write-Host "Timelines stored in $($directoryPath) directory"
Write-Host "Opening $($directoryPath)!"
ii $directoryPath